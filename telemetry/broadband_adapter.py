import dataclasses
import json
import logging
import subprocess
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

import config.settings as settings
from core.log_format import log_line
from core.models import TelemetryEvent, MitigationAction
from core.ssh_utils import run_ssh as _ssh
from mitigation.broadband_mitigator import BngMitigator
from telemetry.base import DomainAdapter

_REPO_SCRIPT_DIR = "/opt/Tesis_Controller/simulation"


class BroadbandAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Fixed Broadband Domain (BNG).

    Runs against deploy/vm-lab: `bng` runs accel-ppp
    (a real open-source BRAS/BNG) fronted by FreeRADIUS. Telemetry is what
    the BNG actually forwards for its subscribers:

      - collect(): one HTTP GET per cycle to simulation/bng_flow_api.py, a
        sidecar on `bng` that reads the kernel's conntrack table. Each
        subscriber flow arrives with its real source, destination, protocol
        and port (the original-direction tuple keeps the subscriber's
        address from before the masquerade toward the backbone) and a
        packet/byte rate from counter deltas; connection attempts are
        reported as TCP_SYN rows. The sidecar also resolves IP -> MAC and
        accel-ppp session id, which apply_mitigation() needs to hand a
        resolved MAC down to the mitigation backend. Neither FreeRADIUS
        accounting (volume per session only, no L4) nor the traffic
        generator's own state is used as a telemetry source.
      - apply_mitigation(): this adapter is the only place a src_ip can be
        resolved back to the subscriber's MAC (Calling-Station-Id) --
        MitigationAction only ever carries the IP DDoSDetectionEngine
        classified. It resolves that identity, hands a copy of the action
        with action.mac filled in (empty if unresolved) to
        mitigation/broadband_mitigator.py's BngMitigator, and reports that
        delegation's own result. See BngMitigator's own module docstring
        for what it actually does on the wire (accel-cmd terminate +
        FreeRADIUS reject marker + suscriptor kick on unblock).

    Confirmed against a real run (2026-09-17): 8 real IPoE sessions,
    real DHCP leases, real per-subscriber source-based routing (see
    simulation/bng_subscriber_agent.py's own module docstring for why
    that routing override is needed at all), and real attack traffic
    correctly moving a session's own ipoeN RX counters, plus a full
    real detect -> block (accel-cmd terminate + FreeRADIUS reject) ->
    unblock -> kick cycle.

    Use self._logger, NOT print(), anywhere in this class -- confirmed
    on a real run: ryu-manager's systemd unit redirects stdout to a
    file (StandardOutput=append:/var/log/ryu-manager.log), and Python
    fully-buffers stdout when it isn't a TTY. A plain print() call can
    sit in that buffer indefinitely and never actually reach the file,
    while `self._logger.warning(...)` (a real logging.StreamHandler)
    flushes per record. This made several real bugs in this class look
    unfixable for a long stretch of debugging: the fix code was
    correct and running, but its own confirming print() output was
    silently never appearing in the log at all.
    """

    domain_name = "broadband"

    def __init__(
        self,
        mitigator: Optional[BngMitigator] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.target_ip = settings.BNG_DIST_TARGET_IP
        self.mitigator = mitigator or BngMitigator(logger=logger)

        # Passed down from the Ryu app (its own self.logger), same
        # convention telemetry/mobile_adapter.py already uses -- defaults
        # to a plain logging.Logger so this stays usable standalone.
        self._logger = logger or logging.getLogger(__name__)
        # Tracks the last-logged connection state so collect() logs a
        # "telemetry source connected/lost" event only on the transition,
        # same as MobileNetworkAdapter.collect()'s own SOURCE_CONNECTED/
        # SOURCE_LOST handling.
        self._was_connected = False
        # (src_ip, dst_ip, protocol, dst_port) -> updated_at of the last row
        # turned into an event: the sidecar re-serves a flow's last rate
        # until its next conntrack poll, and the same sample must not count
        # twice toward the activation hysteresis.
        self._flow_seen: Dict[tuple, float] = {}
        # src_ip -> accel-ppp session id / subscriber MAC (Calling-Station-Id),
        # learned from the sidecar's session list -- the only place this
        # adapter sees that mapping (MitigationAction only carries the IP
        # DDoSDetectionEngine classified). Never forgotten once learned: a
        # blocked subscriber's session is gone from the list by the time it
        # has to be unblocked.
        self._session_by_ip: Dict[str, str] = {}
        self._mac_by_ip: Dict[str, str] = {}

        # Offered load of blocked subscribers (see offered_pps): the last
        # nft counter reading per (mac, kind) and the rate derived from it.
        self._clock = time.time
        self._offered_polled_at = 0.0
        self._offered_prev: Dict[tuple, tuple] = {}
        self._offered_rate: Dict[tuple, tuple] = {}

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def is_connected(self) -> bool:
        result = self._ssh_bng(["systemctl", "is-active", "--quiet", "accel-pppd", "freeradius"])
        return result.returncode == 0

    def _ssh_bng(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_BNG_SSH_USER, settings.BNG_DIST_BNG_SSH_HOST, args, input_text=input_text)

    # ------------------------------------------------------------------
    # Telemetry (conntrack sidecar on `bng`)
    # ------------------------------------------------------------------

    def _read_flow_api(self) -> Optional[dict]:
        """The sidecar's /telemetry payload, or None when it cannot be read.

        Plain HTTP GET, not SSH: ryu-manager's eventlet monkey-patching
        already makes plain socket I/O cooperative (the tpool workaround
        used for the SSH calls above exists because subprocess is not)."""
        try:
            with urllib.request.urlopen(settings.BNG_DIST_FLOW_API_URL,
                                        timeout=settings.BNG_DIST_FLOW_API_TIMEOUT_S) as resp:
                payload = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return None
        return payload if isinstance(payload, dict) else None

    def _collect_distributed(self) -> List[TelemetryEvent]:
        payload = self._read_flow_api()
        connected = bool(payload and payload.get("conntrack_connected"))

        if connected and not self._was_connected:
            self._logger.info(log_line("broadband", "TELEMETRY", "SOURCE_CONNECTED",
                                        f"url={settings.BNG_DIST_FLOW_API_URL}"))
        elif not connected and self._was_connected:
            self._logger.warning(log_line("broadband", "TELEMETRY", "SOURCE_LOST",
                                           f"url={settings.BNG_DIST_FLOW_API_URL}"))
        self._was_connected = connected
        if not connected:
            return []

        for sess in payload.get("sessions") or []:
            ip, mac = sess.get("ip"), sess.get("mac")
            if ip and mac:
                self._mac_by_ip[ip] = mac
                if sess.get("session_id"):
                    self._session_by_ip[ip] = sess["session_id"]

        events: List[TelemetryEvent] = []
        live = set()
        for row in payload.get("flows") or []:
            try:
                src_ip, dst_ip = row["src_ip"], row["dst_ip"]
                protocol, dst_port = row["protocol"], int(row.get("dst_port") or 0)
                pps, bps = float(row["pps"]), float(row["bps"])
                updated_at = float(row.get("updated_at") or time.time())
            except (KeyError, TypeError, ValueError):
                continue
            if row.get("mac"):
                self._mac_by_ip[src_ip] = row["mac"]
            key = (src_ip, dst_ip, protocol, dst_port)
            live.add(key)
            if self._flow_seen.get(key) == updated_at:
                continue  # same sample as last cycle
            self._flow_seen[key] = updated_at
            if pps <= 0.0 and bps <= 0.0:
                continue
            events.append(TelemetryEvent(
                domain=self.domain_name, device_id="bng", src_ip=src_ip, dst_ip=dst_ip,
                dst_port=dst_port, protocol=protocol, pps=pps, bps=bps, timestamp=updated_at,
            ))
        for key in list(self._flow_seen):
            if key not in live:
                del self._flow_seen[key]
        return events

    def collect(self) -> List[TelemetryEvent]:
        return self._collect_distributed()

    # ------------------------------------------------------------------
    # Offered load while blocked
    # ------------------------------------------------------------------
    # A blocked subscriber's accel-ppp session is terminated, so its
    # flows stop appearing and collect() says nothing about whether
    # the attacker is still flooding. roles/bng installs a netdev-ingress
    # nft table on the access NIC with one counter per subscriber MAC and
    # protocol; those keep counting the frames the MAC still sends even with
    # no session. Comment format: "<mac> <kind>".
    _OFFERED_KIND_BY_PROTOCOL = {"TCP": "tcp_syn", "UDP": "udp", "ICMP": "icmp"}

    @staticmethod
    def _parse_offered_counters(text: str) -> Optional[Dict[tuple, int]]:
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            return None
        counters: Dict[tuple, int] = {}
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            parts = (rule.get("comment") or "").split()
            if len(parts) != 2:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    counters[(parts[0].lower(), parts[1])] = int(expr["counter"].get("packets", 0))
        return counters or None

    def _read_offered_counters(self) -> Optional[Dict[tuple, int]]:
        try:
            result = self._ssh_bng([
                "sudo", "-n", "nft", "-j", "list", "chain", "netdev",
                settings.BNG_DIST_OFFERED_NFT_TABLE, settings.BNG_DIST_OFFERED_NFT_CHAIN,
            ])
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] cannot read offered-load counters: {exc}")
            return None
        if result.returncode != 0:
            self._logger.warning(f"[BROADBAND] cannot read offered-load counters: {result.stderr.strip()}")
            return None
        return self._parse_offered_counters(result.stdout)

    def _refresh_offered(self, now: float) -> None:
        if now - self._offered_polled_at < settings.BROADBAND_OFFERED_POLL_S:
            return
        self._offered_polled_at = now
        counters = self._read_offered_counters()
        if counters is None:
            return
        for key, packets in counters.items():
            prev = self._offered_prev.get(key)
            self._offered_prev[key] = (packets, now)
            if prev is None:
                continue
            prev_packets, prev_time = prev
            dt = now - prev_time
            # A smaller counter means the table was recreated: no rate
            # this round rather than a bogus negative one.
            if dt <= 0 or packets < prev_packets:
                continue
            self._offered_rate[key] = ((packets - prev_packets) / dt, now)

    def offered_pps(self, src_ip: str, protocol: str) -> Optional[float]:
        """Packets/s of `protocol` (TCP means bare SYNs) that this
        subscriber's MAC is still sending into bng, or None when there is no
        fresh measurement (unknown MAC/protocol, counters unreadable): the
        caller must then not read "None" as "quiet"."""
        mac = (self._mac_by_ip.get(src_ip) or "").lower()
        kind = self._OFFERED_KIND_BY_PROTOCOL.get(protocol)
        if not mac or kind is None:
            return None
        now = self._clock()
        self._refresh_offered(now)
        sample = self._offered_rate.get((mac, kind))
        if sample is None or now - sample[1] > settings.BROADBAND_OFFERED_MAX_AGE_S:
            return None
        return sample[0]

    # ------------------------------------------------------------------
    # Mitigation (delegates to mitigation/broadband_mitigator.py)
    # ------------------------------------------------------------------

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # The attacking subscriber is action.src_ip (the real source
        # this domain reported it under in collect() above). This is
        # the only place that lookup can happen -- BngMitigator is never
        # handed a raw action; mac is "" (not None) when unresolved, so
        # BngMitigator still terminates the session by IP but skips the
        # persistent AAA reject marker (see its own apply() docstring).
        mac = self._mac_by_ip.get(action.src_ip, "")
        return self.mitigator.apply(dataclasses.replace(action, mac=mac))
