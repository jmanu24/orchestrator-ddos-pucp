#!/usr/bin/env python3
"""
bng_flow_api.py -- local sidecar on `bng` (Broadband domain, VM lab).

Exposes one read-only HTTP JSON endpoint (GET /telemetry) that
telemetry/broadband_adapter.py polls once per collect() cycle, the same
shape as oran_bridge/ue_telemetry_api.py on core5g for the mobile domain.

What it observes is the subscribers' own traffic as the BNG forwards it,
from the kernel's connection-tracking table -- not FreeRADIUS accounting
(volume per session only: no destination, protocol or port) and not the
traffic generator's own idea of what it is sending:

  1. `conntrack -L`: every flow whose ORIGINAL-direction source is in the
     access subnet. bng masquerades subscriber traffic out its backbone NIC,
     but conntrack keeps the pre-NAT subscriber address in the original
     tuple, so the source is the subscriber's own IP. Entries sharing
     (src, dst, protocol, dport) are summed so a source-port-randomizing
     flood (one short-lived entry per packet) still reads as one rate.
  2. `conntrack -E -e NEW -p tcp`: connection attempts per second per
     (src, dst, dport), reported as a TCP_SYN row (one bare SYN each). A SYN
     flood's entries die within a poll, so list deltas alone cannot measure it.
  3. `accel-cmd show sessions`: IP -> subscriber MAC and accel-ppp session id,
     which the adapter needs to block the right subscriber.

Requires net.netfilter.nf_conntrack_acct=1 (set at start-up) and the
`conntrack` tool (roles/bng installs both).
"""

import collections
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque, Dict, Iterator, List, Optional, Tuple

LISTEN_PORT = int(os.environ.get("BNG_FLOW_API_PORT", "8769"))
ACCESS_NET = ipaddress.ip_network(os.environ.get("BNG_ACCESS_CIDR", "10.20.0.0/24"))
# bng's own address on the access subnet: its traffic is not a subscriber's.
BNG_ACCESS_IP = os.environ.get("BNG_ACCESS_IP", "10.20.0.1")
ACCEL_CMD_PORT = os.environ.get("BNG_ACCEL_CMD_PORT", "2000")

CONNTRACK_POLL_INTERVAL_S = 0.5
SESSION_POLL_INTERVAL_S = 2.0
# Connection-attempt rate: sliding window, and the size one bare SYN is
# reported as.
SYN_RATE_WINDOW_S = 2.0
SYN_FRAME_BYTES = 60

_PROTO_NAMES = {"icmp": "ICMP", "tcp": "TCP", "udp": "UDP"}

# One line of `conntrack -E -e NEW -p tcp`; SYN_SENT is the state of an entry
# created by a bare SYN, so each matching line is exactly one attempt.
_CT_NEW_SYN_RE = re.compile(
    r"^\s*\[NEW\]\s+tcp\s+\d+\s+\d+\s+SYN_SENT\s+"
    r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+sport=\d+\s+dport=(?P<dport>\d+)"
)


def _is_subscriber(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr in ACCESS_NET and str(addr) != BNG_ACCESS_IP


def _is_user_destination(ip: str) -> bool:
    """False for traffic addressed to bng itself or broadcast (DHCP, ARP-ish
    control chatter): those are not flows toward a destination."""
    return ip not in (BNG_ACCESS_IP, "255.255.255.255", "0.0.0.0")


def parse_conntrack_flows(text: str) -> Iterator[Tuple[str, str, str, int, int, int]]:
    """Yields (src, dst, protocol, dport, packets, bytes) for the ORIGINAL
    direction of each `conntrack -L` line sourced by a subscriber.
    `conntrack -L` prints the original tuple first and the reply tuple second
    on the same line; only the first match of each field is taken."""
    for line in text.splitlines():
        if "src=" not in line:
            continue
        proto_m = re.match(r"^(\w+)\s", line)
        src_m = re.search(r"\bsrc=([\d.]+)", line)
        dst_m = re.search(r"\bdst=([\d.]+)", line)
        dport_m = re.search(r"\bdport=(\d+)", line)
        pkt_m = re.search(r"\bpackets=(\d+)", line)
        byt_m = re.search(r"\bbytes=(\d+)", line)
        if not (src_m and dst_m and pkt_m and byt_m):
            continue
        src, dst = src_m.group(1), dst_m.group(1)
        if not _is_subscriber(src) or not _is_user_destination(dst):
            continue
        proto = proto_m.group(1) if proto_m else "ip"
        yield (src, dst, _PROTO_NAMES.get(proto, proto.upper()),
               int(dport_m.group(1)) if dport_m else 0,
               int(pkt_m.group(1)), int(byt_m.group(1)))


def parse_new_syn_event(line: str) -> Optional[Tuple[str, str, int]]:
    """(src, dst, dport) of a NEW TCP connection attempt by a subscriber, else
    None (other state or protocol, not a subscriber, or addressed to bng)."""
    m = _CT_NEW_SYN_RE.match(line)
    if not m:
        return None
    if not _is_subscriber(m.group("src")) or not _is_user_destination(m.group("dst")):
        return None
    return m.group("src"), m.group("dst"), int(m.group("dport"))


def parse_sessions(text: str) -> Dict[str, dict]:
    """ip -> {"mac", "session_id"} from `accel-cmd show sessions ip,calling-sid,sid`:
    a header row, a dashed rule, then ` | `-separated rows."""
    sessions: Dict[str, dict] = {}
    header: Optional[List[str]] = None
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        if header is None:
            header = cells
            continue
        row = dict(zip(header, cells))
        ip, mac = row.get("ip", ""), row.get("calling-sid", "")
        if ip and mac:
            sessions[ip] = {"mac": mac.lower(), "session_id": row.get("sid", "")}
    return sessions


class SynRateWindow:
    """Connection attempts per second per (src, dst, dport), averaged over a
    sliding window."""

    def __init__(self, window_s: float = SYN_RATE_WINDOW_S, clock=time.monotonic):
        self.window_s = window_s
        self._clock = clock
        self._events: Dict[Tuple[str, str, int], Deque[float]] = {}

    def record(self, key: Tuple[str, str, int]) -> None:
        self._events.setdefault(key, collections.deque()).append(self._clock())

    def rates(self) -> Dict[Tuple[str, str, int], float]:
        cutoff = self._clock() - self.window_s
        out = {}
        for key in list(self._events):
            q = self._events[key]
            while q and q[0] < cutoff:
                q.popleft()
            if q:
                out[key] = len(q) / self.window_s
            else:
                del self._events[key]
        return out


def aggregate_flows(rows) -> Dict[tuple, Tuple[int, int]]:
    """Sums the counters of every entry sharing (src, dst, protocol, dport)."""
    totals: Dict[tuple, Tuple[int, int]] = {}
    for src, dst, proto, dport, packets, nbytes in rows:
        key = (src, dst, proto, dport)
        p, b = totals.get(key, (0, 0))
        totals[key] = (p + packets, b + nbytes)
    return totals


def compute_rates(totals: Dict[tuple, Tuple[int, int]], previous: Dict[tuple, tuple],
                  now_mono: float, now_wall: float) -> Dict[tuple, dict]:
    """Rates (packets/s and bytes/s, TelemetryEvent's convention) per key from the delta against `previous` ({key: (packets, bytes,
    monotonic_time)}, updated in place; keys no longer present are dropped).
    A negative delta (entries closed between polls, so the sum fell) is "no
    rate this cycle", never a negative one."""
    flows = {}
    for key, (packets, nbytes) in totals.items():
        src, dst, proto, dport = key
        prev = previous.get(key)
        pps = bps = 0.0
        if prev is not None:
            dt = now_mono - prev[2]
            dpkt, dbyt = packets - prev[0], nbytes - prev[1]
            if dt > 0 and dpkt >= 0 and dbyt >= 0:
                pps, bps = dpkt / dt, dbyt / dt
        flows[key] = {"src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": dport,
                      "pps": pps, "bps": bps, "updated_at": now_wall}
        previous[key] = (packets, nbytes, now_mono)
    for key in list(previous):
        if key not in totals:
            del previous[key]
    return flows


def build_rows(flows, syn_rates, sessions, now=None) -> List[dict]:
    """The /telemetry flow rows: the conntrack flows plus one TCP_SYN row per
    (subscriber, destination, port) with connection attempts in the window,
    each joined with its subscriber's MAC and accel-ppp session id."""
    now = time.time() if now is None else now
    all_flows = list(flows)
    for (src, dst, dport), rate in syn_rates.items():
        all_flows.append({
            "src_ip": src, "dst_ip": dst, "protocol": "TCP_SYN", "dst_port": dport,
            "pps": rate, "bps": rate * SYN_FRAME_BYTES, "updated_at": now,
        })
    rows = []
    for f in all_flows:
        sess = sessions.get(f["src_ip"])
        rows.append({**f,
                     "mac": sess["mac"] if sess else None,
                     "session_id": sess["session_id"] if sess else None})
    return rows


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: Dict[str, dict] = {}
        self.flows: Dict[tuple, dict] = {}
        self.syn_window = SynRateWindow()
        self.conntrack_connected = False
        self.syn_events_connected = False
        self.sessions_connected = False


state = _State()


def _sudo(argv: List[str], timeout: float = 10) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, timeout=timeout)


def _conntrack_poll_loop():
    try:
        _sudo(["sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"])
    except (OSError, subprocess.TimeoutExpired):
        pass
    previous: Dict[tuple, tuple] = {}
    while True:
        try:
            result = _sudo(["conntrack", "-L"])
            if result.returncode not in (0, 1):  # 1 = empty table, not an error
                with state.lock:
                    state.conntrack_connected = False
            else:
                flows = compute_rates(aggregate_flows(parse_conntrack_flows(result.stdout)),
                                      previous, time.monotonic(), time.time())
                with state.lock:
                    state.flows = flows
                    state.conntrack_connected = True
        except (subprocess.TimeoutExpired, OSError):
            with state.lock:
                state.conntrack_connected = False
        time.sleep(CONNTRACK_POLL_INTERVAL_S)


def _conntrack_syn_event_loop():
    """Streams `conntrack -E -e NEW -p tcp`; restarted if conntrack exits
    (e.g. its netlink buffer overflowed under a flood)."""
    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["sudo", "-n", "conntrack", "-E", "-e", "NEW", "-p", "tcp"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
            with state.lock:
                state.syn_events_connected = True
            for line in proc.stdout:
                key = parse_new_syn_event(line)
                if key is not None:
                    with state.lock:
                        state.syn_window.record(key)
        except OSError:
            pass
        finally:
            with state.lock:
                state.syn_events_connected = False
            if proc is not None:
                proc.kill()
        time.sleep(1.0)


def _session_poll_loop():
    while True:
        try:
            result = _sudo(["accel-cmd", "-p", ACCEL_CMD_PORT, "show", "sessions", "ip,calling-sid,sid"])
            if result.returncode == 0:
                with state.lock:
                    state.sessions = parse_sessions(result.stdout)
                    state.sessions_connected = True
            else:
                with state.lock:
                    state.sessions_connected = False
        except (subprocess.TimeoutExpired, OSError):
            with state.lock:
                state.sessions_connected = False
        time.sleep(SESSION_POLL_INTERVAL_S)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # polled every ~0.5s by the orchestrator

    def do_GET(self):
        if self.path != "/telemetry":
            self.send_response(404)
            self.end_headers()
            return
        with state.lock:
            sessions = dict(state.sessions)
            flows = list(state.flows.values())
            syn_rates = state.syn_window.rates()
            payload_flags = {
                "conntrack_connected": state.conntrack_connected,
                "syn_events_connected": state.syn_events_connected,
                "sessions_connected": state.sessions_connected,
            }
        body = json.dumps({
            "flows": build_rows(flows, syn_rates, sessions),
            "sessions": [{"ip": ip, **s} for ip, s in sessions.items()],
            **payload_flags,
            "session_count": len(sessions),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    threading.Thread(target=_conntrack_poll_loop, daemon=True).start()
    threading.Thread(target=_conntrack_syn_event_loop, daemon=True).start()
    threading.Thread(target=_session_poll_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
