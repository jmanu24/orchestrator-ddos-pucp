#!/usr/bin/env python3
"""
ue_telemetry_api.py -- local sidecar on core5g (10.10.0.5).

Exposes a single real HTTP JSON API (GET /telemetry) that orchestrator's
mobile_adapter.py polls once per COLLECT_INTERVAL -- orchestrator itself
never tails a log or SSHes into core5g for data, it only does a plain
GET, mirroring simulation/bng_subscriber_agent.py's existing
/active_scenario endpoint (see telemetry/broadband_adapter.py's
_read_active_scenario()).

Two things Open5GS itself has no live query API for are joined here,
locally, where the raw state actually lives:

  1. amf_ue_ngap_id -> imsi -> ip, from Open5GS's own AMF/SMF docker
     logs (open5gs_5gc container). Confirmed real log lines (see
     ngap-handler.c:562 and npcf-handler.c:539 in Open5GS's source):
       [amf] RAN_UE_NGAP_ID[0] AMF_UE_NGAP_ID[17] TAC[7] CellID[...]
       [smf] UE SUPI[imsi-001010123456780] DNN[srsapn] IPv4[10.45.1.2]
     No shared key exists between these two lines in the text itself --
     correlated here by arrival order (a FIFO of pending amf_ue_ngap_ids,
     matched against SMF IPv4 lines as they arrive), which is safe at
     this testbed's scale (a handful of concurrent UEs, Open5GS's AMF
     processes each registration burst largely sequentially).

  2. Per-(UE IP, destination) volumetric flow stats, from conntrack --
     all UE uplink traffic is decapsulated onto core5g's own ogstun
     interface, so the kernel's own connection-tracking table (queried
     locally via `conntrack -L`, netlink-based, NOT a log) is a real,
     complete, OpenFlow-independent view of exactly which destinations
     each UE is talking to, with real packet/byte counters (requires
     net.netfilter.nf_conntrack_acct=1, enabled once by this script).

  3. Per-UE UL KPM (RRU.PrbUsedUl, DRB.UEThpUl, ...) from the oran-sc-ric
     KPM bridge xApp (KPM_API_URL, default http://10.10.0.4:8767/kpm). The
     bridge registers each DU as its own E2 node and keys each sample by
     imsi (via its gnb_du_id->imsi map), so the UL metrics are already
     per-UE. We join them to the flow/session rows by imsi -- the same
     imsi resolved from the SMF log in (1) -- not by amf_ue_ngap_id.

This process owns all pollers and joins them in memory; /telemetry
returns pre-joined, ready-to-use rows so mobile_adapter.py's own job is
just "GET a URL and build TelemetryEvents", nothing more.
"""

import collections
import ipaddress
import json
import os
import re
import subprocess
from typing import Deque, Dict, Optional, Tuple
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = 8766
CONTAINER_NAME = "open5gs_5gc"
UE_POOL = ipaddress.ip_network("10.45.0.0/16")
KPM_API_URL = os.environ.get("KPM_API_URL", "http://10.10.0.4:8767/kpm")
KPM_API_TIMEOUT_S = 2.0
KPM_POLL_INTERVAL_S = 1.0
KPM_SAMPLE_TTL_S = 10.0
# The lab config uses a 22-bit gNB id. An NR Cell Identity has 36 bits,
# leaving 14 low bits for the cell-local id (DU sector in this topology).
GNB_ID_BIT_LENGTH = 22
NCI_BIT_LENGTH = 36

CONNTRACK_POLL_INTERVAL_S = 1.0
# New-TCP-connection rate (see _conntrack_syn_event_loop): sliding window the
# per-second rate is averaged over, and the size one bare SYN is reported as.
SYN_RATE_WINDOW_S = 2.0
SYN_FRAME_BYTES = 60
LOG_POLL_INTERVAL_S = 0.5
# How long a pending amf_ue_ngap_id (seen via the RAN_UE_NGAP_ID/
# AMF_UE_NGAP_ID line) stays eligible to be matched against the next
# SMF "UE SUPI[...] IPv4[...]" line -- guards against a stalled/failed
# registration leaving a stale entry at the front of the FIFO forever.
PENDING_NGAP_ID_TTL_S = 15.0
# A session entry (amf_ue_ngap_id/imsi/ip) is dropped from the live map
# if not refreshed within this long. The SMF only logs the "UE SUPI...IPv4..."
# line once at PDU establishment and nothing refreshes updated_at, so this must
# outlast how long a UE stays attached. Kept at 24h to match the RAN idle/
# inactivity timers (srsRAN CU inactivity_timer=86400, AMF t3512=86400); a
# shorter TTL purges live sessions mid-connection and starves KPM attribution.
SESSION_TTL_S = 86400.0

_AMF_NGAP_ID_RE = re.compile(
    r"RAN_UE_NGAP_ID\[(\d+)\]\s+AMF_UE_NGAP_ID\[(\d+)\]"
    r".*?CellID\[0x([0-9a-fA-F]+)\]"
)
_SMF_IPV4_RE = re.compile(r"UE SUPI\[imsi-(\d{15,16})\].*?IPv4\[(\d+\.\d+\.\d+\.\d+)\]")
_SESSION_REMOVED_RE = re.compile(
    r"Removed Session: UE IMSI:\[imsi-(\d{15,16})\].*?IPv4:\[(\d+\.\d+\.\d+\.\d+)\]"
)

_PROTO_NAMES = {"icmp": "ICMP", "tcp": "TCP", "udp": "UDP"}

# One line of `conntrack -E -e NEW -p tcp`, e.g.
#   [NEW] tcp      6 120 SYN_SENT src=10.45.1.4 dst=10.55.0.100 sport=42190 dport=443 [UNREPLIED] src=...
# SYN_SENT is the state of an entry created by a bare SYN (with
# nf_conntrack_tcp_loose=1 a mid-stream packet can also create one, but not
# in SYN_SENT), so each matching line is exactly one connection attempt.
_CT_NEW_SYN_RE = re.compile(
    r"^\s*\[NEW\]\s+tcp\s+\d+\s+\d+\s+SYN_SENT\s+"
    r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+sport=\d+\s+dport=(?P<dport>\d+)"
)


def parse_new_syn_event(line: str) -> Optional[Tuple[str, str, int]]:
    """(src, dst, dport) for a NEW TCP connection attempt whose source is in
    the UE pool, else None (other state, other protocol, or not a UE)."""
    m = _CT_NEW_SYN_RE.match(line)
    if not m:
        return None
    try:
        if ipaddress.ip_address(m.group("src")) not in UE_POOL:
            return None
    except ValueError:
        return None
    return m.group("src"), m.group("dst"), int(m.group("dport"))


class SynRateWindow:
    """Connection attempts per second per (src, dst, dport), averaged over a
    sliding window. Counting NEW events instead of reading `conntrack -L`
    is what makes a SYN flood measurable at all: its entries live for a few
    hundred milliseconds (the victim answers RST / the UPF reaps them), so
    they rarely survive two polls and the list-based packet deltas read as
    0, a burst, 0, a burst... (measured: 0/173/0/307/0/1158 pps for a flood
    of ~900 attempts/s)."""

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


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        # ip -> {"imsi": str, "amf_ue_ngap_id": int, "updated_at": float}
        self.sessions = {}
        # (src_ip,dst_ip,proto,dport) -> {"packets","bytes","pps","bps","updated_at"}
        self.flows = {}
        # imsi -> latest per-UE KPM sample from the oran-sc-ric bridge.
        # (The bridge registers each DU as its own E2 node and keys samples
        # by imsi via the gnb_du_id->imsi map, so the UL metrics are already
        # per-UE; we join them to flows by imsi, not amf_ue_ngap_id.)
        self.kpm_by_imsi = {}
        self.log_connected = False
        self.conntrack_connected = False
        self.syn_events_connected = False
        self.kpm_connected = False
        # New-TCP-connection rate per (src, dst, dport) -- guarded by `lock`.
        self.syn_window = SynRateWindow()


state = _State()


# ---------------------------------------------------------------------
# 1. Open5GS docker-log tailer (local -- this file lives ON core5g)
# ---------------------------------------------------------------------

def _container_log_path() -> str:
    out = subprocess.run(
        ["sudo", "docker", "inspect", "--format={{.LogPath}}", CONTAINER_NAME],
        capture_output=True, text=True, timeout=10,
    )
    return out.stdout.strip()


def _log_tail_loop():
    import collections

    offset = 0
    pending = collections.deque()  # (amf_ue_ngap_id, nr_cell_id, seen_at)
    log_path = None

    while True:
        try:
            if log_path is None:
                log_path = _container_log_path()
                offset = 0

            result = subprocess.run(
                ["sudo", "tail", "-c", f"+{offset + 1}", log_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                with state.lock:
                    state.log_connected = False
                log_path = None
                time.sleep(LOG_POLL_INTERVAL_S)
                continue

            new_bytes = result.stdout
            offset += len(new_bytes.encode("utf-8", errors="ignore"))

            with state.lock:
                state.log_connected = True

            now = time.time()
            # Drop stale pending entries from the front.
            while pending and (now - pending[0][2]) > PENDING_NGAP_ID_TTL_S:
                pending.popleft()

            for line in new_bytes.splitlines():
                # Docker's json-file driver wraps each line as
                # {"log": "...\n", "stream": "stdout", "time": "..."}.
                try:
                    rec = json.loads(line)
                    text = rec.get("log", "")
                except (json.JSONDecodeError, AttributeError):
                    text = line

                removed = _SESSION_REMOVED_RE.search(text)
                if removed:
                    removed_imsi, removed_ip = removed.group(1), removed.group(2)
                    with state.lock:
                        session = state.sessions.get(removed_ip)
                        if session and session["imsi"] == removed_imsi:
                            del state.sessions[removed_ip]
                    continue

                m = _AMF_NGAP_ID_RE.search(text)
                if m:
                    amf_ngap_id = int(m.group(2))
                    nr_cell_id = int(m.group(3), 16)
                    pending.append((amf_ngap_id, nr_cell_id, now))
                    continue

                m = _SMF_IPV4_RE.search(text)
                if m and pending:
                    imsi, ip = m.group(1), m.group(2)
                    amf_ngap_id, nr_cell_id, _ = pending.popleft()
                    cell_bits = NCI_BIT_LENGTH - GNB_ID_BIT_LENGTH
                    with state.lock:
                        state.sessions[ip] = {
                            "imsi": imsi,
                            "amf_ue_ngap_id": amf_ngap_id,
                            "nr_cell_id": nr_cell_id,
                            "gnb_id": nr_cell_id >> cell_bits,
                            "cell_local_id": nr_cell_id & ((1 << cell_bits) - 1),
                            "updated_at": now,
                        }

            # Prune sessions nobody's refreshed in a long time.
            with state.lock:
                cutoff = now - SESSION_TTL_S
                for ip in [ip for ip, v in state.sessions.items() if v["updated_at"] < cutoff]:
                    del state.sessions[ip]

        except (subprocess.TimeoutExpired, OSError):
            with state.lock:
                state.log_connected = False
            log_path = None

        time.sleep(LOG_POLL_INTERVAL_S)


# ---------------------------------------------------------------------
# 2. Identity-bound KPM poller (RIC-local exporter, plain HTTP)
# ---------------------------------------------------------------------

def _kpm_poll_loop():
    while True:
        try:
            with urllib.request.urlopen(KPM_API_URL, timeout=KPM_API_TIMEOUT_S) as response:
                payload = json.loads(response.read())
            now = time.time()
            samples = {}
            for sample in payload.get("samples", []):
                imsi = sample.get("imsi")
                updated_at = float(sample.get("updated_at", 0))
                if not imsi or now - updated_at > KPM_SAMPLE_TTL_S:
                    continue
                samples[str(imsi)] = sample
            with state.lock:
                state.kpm_by_imsi = samples
                state.kpm_connected = bool(payload.get("connected"))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
            with state.lock:
                state.kpm_by_imsi = {}
                state.kpm_connected = False
        time.sleep(KPM_POLL_INTERVAL_S)


# ---------------------------------------------------------------------
# 3. conntrack poller (local -- netlink query, not a log)
# ---------------------------------------------------------------------

_CT_LINE_RE = re.compile(
    r"^(?P<proto>\w+)\s+\d+\s+\d+\s+"
    r".*?src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+"
    r"(?:sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)|.*?)\s+"
    r"packets=(?P<packets>\d+)\s+bytes=(?P<bytes>\d+)"
)


def _ensure_conntrack_acct():
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"],
        capture_output=True, text=True, timeout=10,
    )


def _parse_conntrack_output(text: str):
    """Yields (src, dst, proto, dport, packets, bytes) for the ORIGINAL
    direction of each line whose src is in our UE pool. `conntrack -L`
    prints original-direction tuple first, reply-direction second, both
    on the same line -- only the first packets=/bytes= pair (original
    direction) is captured by taking the first match per line."""
    for line in text.splitlines():
        if "src=" not in line:
            continue
        # Take only the first src=/dst=/packets=/bytes= occurrence (the
        # original-direction tuple) -- a reply-direction second match
        # later on the same line is a different (dst,src) pair we don't
        # want double-counted here.
        proto_m = re.match(r"^(\w+)\s", line)
        proto = proto_m.group(1) if proto_m else "ip"
        src_m = re.search(r"\bsrc=([\d.]+)", line)
        dst_m = re.search(r"\bdst=([\d.]+)", line)
        dport_m = re.search(r"\bdport=(\d+)", line)
        pkt_m = re.search(r"\bpackets=(\d+)", line)
        byt_m = re.search(r"\bbytes=(\d+)", line)
        if not (src_m and dst_m and pkt_m and byt_m):
            continue
        src = src_m.group(1)
        try:
            if ipaddress.ip_address(src) not in UE_POOL:
                continue
        except ValueError:
            continue
        dst = dst_m.group(1)
        dport = int(dport_m.group(1)) if dport_m else 0
        packets = int(pkt_m.group(1))
        nbytes = int(byt_m.group(1))
        yield src, dst, _PROTO_NAMES.get(proto, proto.upper()), dport, packets, nbytes


def _conntrack_poll_loop():
    _ensure_conntrack_acct()
    # key -> (packets, bytes, monotonic_time) at the previous poll.
    previous = {}

    while True:
        try:
            result = subprocess.run(
                ["sudo", "conntrack", "-L"], capture_output=True, text=True, timeout=10,
            )
            now_mono = time.monotonic()
            now_wall = time.time()
            if result.returncode not in (0, 1):  # 1 = empty table, not an error
                with state.lock:
                    state.conntrack_connected = False
                time.sleep(CONNTRACK_POLL_INTERVAL_S)
                continue

            with state.lock:
                state.conntrack_connected = True

            # Aggregate ALL currently-open conntrack entries sharing the
            # same (src,dst,proto,dport) into one running total -- a
            # source-port-randomizing flood (hping3's default, no -k)
            # opens a fresh short-lived conntrack entry PER PACKET, each
            # with its own tiny packets=/bytes= count; grouping only by
            # dst_port (not src_port) and summing is what turns that
            # into the real aggregate volumetric rate for the pair,
            # instead of just whichever single entry happened to be
            # listed last (confirmed on a real run: that bug made a
            # genuine flood read back as pps=0 every cycle).
            aggregated: Dict[tuple, tuple] = {}
            for src, dst, proto, dport, packets, nbytes in _parse_conntrack_output(result.stdout):
                key = (src, dst, proto, dport)
                p, b = aggregated.get(key, (0, 0))
                aggregated[key] = (p + packets, b + nbytes)

            seen_keys = set(aggregated.keys())
            new_flows = {}
            for key, (packets, nbytes) in aggregated.items():
                src, dst, proto, dport = key
                prev = previous.get(key)
                pps = bps = 0.0
                if prev is not None:
                    dt = now_mono - prev[2]
                    if dt > 0:
                        dpkt = packets - prev[0]
                        dbyt = nbytes - prev[1]
                        # A negative delta means enough of this key's
                        # underlying entries closed between polls that
                        # the aggregate sum dropped -- treat as "no rate
                        # this cycle" rather than negative, same as a
                        # single entry being replaced.
                        if dpkt >= 0 and dbyt >= 0:
                            pps = dpkt / dt
                            bps = dbyt / dt
                new_flows[key] = {
                    "src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": dport,
                    "pps": pps, "bps": bps, "updated_at": now_wall,
                }
                previous[key] = (packets, nbytes, now_mono)

            # Drop counters for flows that disappeared (connection closed).
            for key in list(previous.keys()):
                if key not in seen_keys:
                    del previous[key]

            with state.lock:
                state.flows = new_flows

        except (subprocess.TimeoutExpired, OSError):
            with state.lock:
                state.conntrack_connected = False

        time.sleep(CONNTRACK_POLL_INTERVAL_S)


# ---------------------------------------------------------------------
# 3b. New-TCP-connection rate (conntrack event stream)
# ---------------------------------------------------------------------

def _conntrack_syn_event_loop():
    """Streams `conntrack -E -e NEW -p tcp` and counts connection attempts
    per (UE, destination, port). The stream is restarted if conntrack exits
    (e.g. its netlink buffer overflowed under a flood)."""
    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["sudo", "conntrack", "-E", "-e", "NEW", "-p", "tcp"],
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


# ---------------------------------------------------------------------
# 4. HTTP API
# ---------------------------------------------------------------------

def build_flow_rows(flows, syn_rates, sessions, kpm_by_imsi, now=None):
    """The /telemetry flow rows: the `conntrack -L` flows plus one TCP_SYN row
    per (UE, destination, port) with connection attempts in the window, every
    row joined with its UE's identity and KPM. The TCP_SYN pps is the attempt
    rate (one bare SYN each), not a delta of entry counters."""
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
        kpm = kpm_by_imsi.get(sess["imsi"]) if sess else None
        rows.append({
            **f,
            "imsi": sess["imsi"] if sess else None,
            "amf_ue_ngap_id": sess["amf_ue_ngap_id"] if sess else None,
            "nr_cell_id": sess["nr_cell_id"] if sess else None,
            "gnb_id": sess["gnb_id"] if sess else None,
            "cell_local_id": sess["cell_local_id"] if sess else None,
            "kpm": kpm["metrics"] if kpm else {},
            "kpm_updated_at": kpm["updated_at"] if kpm else None,
        })
    return rows


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep stdout/log quiet -- polled every ~0.5s by orchestrator

    def do_GET(self):
        if self.path != "/telemetry":
            self.send_response(404)
            self.end_headers()
            return

        with state.lock:
            sessions = dict(state.sessions)
            flows = list(state.flows.values())
            syn_rates = state.syn_window.rates()
            kpm_by_imsi = dict(state.kpm_by_imsi)
            log_connected = state.log_connected
            conntrack_connected = state.conntrack_connected
            syn_events_connected = state.syn_events_connected
            kpm_connected = state.kpm_connected

        rows = build_flow_rows(flows, syn_rates, sessions, kpm_by_imsi)

        session_rows = []
        for ip, sess in sessions.items():
            kpm = kpm_by_imsi.get(sess["imsi"])
            session_rows.append({
                "ip": ip,
                "imsi": sess["imsi"],
                "amf_ue_ngap_id": sess["amf_ue_ngap_id"],
                "nr_cell_id": sess["nr_cell_id"],
                "gnb_id": sess["gnb_id"],
                "cell_local_id": sess["cell_local_id"],
                "kpm": kpm["metrics"] if kpm else {},
                "kpm_updated_at": kpm["updated_at"] if kpm else None,
            })

        body = json.dumps({
            "flows": rows,
            "sessions": session_rows,
            "log_connected": log_connected,
            "conntrack_connected": conntrack_connected,
            "syn_events_connected": syn_events_connected,
            "kpm_connected": kpm_connected,
            "session_count": len(sessions),
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    threading.Thread(target=_log_tail_loop, daemon=True).start()
    threading.Thread(target=_conntrack_poll_loop, daemon=True).start()
    threading.Thread(target=_conntrack_syn_event_loop, daemon=True).start()
    threading.Thread(target=_kpm_poll_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
