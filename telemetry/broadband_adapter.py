import json
import logging
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from eventlet import tpool

import config.settings as settings
from core.log_format import log_line
from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter

_REPO_SCRIPT_DIR = "/opt/Tesis_Controller/simulation"
_SSH_TIMEOUT_S = 10



def _ssh(user: str, host: str, args: list, timeout: int = _SSH_TIMEOUT_S,
          input_text: str = None) -> subprocess.CompletedProcess:
    """Same BatchMode/accept-new convention as the former lab tooling
    _ssh_br -- see that function's docstring.

    shlex.join(args), NOT *args -- confirmed on a real run: the ssh
    CLIENT itself concatenates every argument after user@host with a
    single plain space to build the command line it sends to the
    remote shell, with NO extra quoting of its own. Passing
    ["sudo", "-n", "sh", "-c", script] as separate argv elements (as
    this used to) works fine for a plain multi-word command, but the
    moment `script` itself contains shell metacharacters (quotes, `|`,
    `;`, `$(...)`  -- any inline `sh -c` script), the remote shell parses ONLY script's first word as -c's
    actual argument and treats the rest as separate, unrelated words on
    the OUTER login shell's own command line -- broken syntax, or at
    best silently wrong behavior, with no error surfaced anywhere (this
    adapter's own collect()/apply_mitigation() degrade a failed SSH
    call to a quiet return, so this was invisible until traced by hand
    against a live run). shlex.join() re-quotes the whole args list
    into ONE shell-safe string first, so ssh's own space-joining (a
    no-op on a single already-complete argv element) can't split it
    apart again.

    tpool.execute(), NOT a direct call -- confirmed on a real run:
    ryu-manager's whole process is one eventlet-cooperative reactor
    (its own startup warning, "1 RLock(s) were not greened", is the
    tell), and subprocess.run() is a genuinely blocking OS-level call
    (fork/exec/waitpid) that eventlet's monkey-patching does not make
    cooperative the way it does plain sockets. A single slow/stuck SSH
    call (observed: minutes, once even ~6.5 hours behind a large nfdump
    backlog on a different domain) freezes the ENTIRE controller --
    every domain's collect()/detect()/mitigate(), not just this one's --
    since nothing yields back to the reactor until it returns.
    tpool.execute() runs the call in a real OS thread from eventlet's
    own thread pool instead, so the reactor keeps servicing every other
    greenthread while this blocks.

    ControlMaster/ControlPersist -- confirmed on a real run: a bare SSH
    call here costs ~0.5s just for the fresh TCP+key-exchange+auth
    handshake, every single time, since this runs on EVERY collect()
    cycle (COLLECT_INTERVAL, nominally 0.5s). That's the dominant cost
    behind this domain's real-world cycle time being ~6x its nominal
    interval, which directly inflates UNBLOCK_CONFIRM_CYCLES's wall-clock
    duration (orchestration/controller.py) -- measured ~5min for a
    recovery that should only need ~50s at the nominal interval. Reusing
    one multiplexed connection (opened once, kept warm for
    ControlPersist seconds) turns every subsequent call here into a
    single round-trip over an already-authenticated session -- tens of
    ms instead of ~0.5s. /run is root-writable and cleared on reboot,
    matching this socket's own lifetime (this process runs as root via
    systemd). %C is ssh's own hash of user/host/port -- keeps the path
    short and collision-free without hand-rolling one per call site."""
    return tpool.execute(
        subprocess.run,
        ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(timeout, 5)}",
         "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ControlMaster=auto", "-o", "ControlPersist=600",
         "-o", "ControlPath=/run/ssh-mux-%C",
         f"{user}@{host}", shlex.join(args)],
        input=input_text, capture_output=True, text=True, timeout=timeout,
    )

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
        accel-ppp session id, which apply_mitigation() needs. Neither
        FreeRADIUS accounting (volume per session only, no L4) nor the
        traffic generator's own state is used as a telemetry source.
      - apply_mitigation(): two real BNG-native actions per block:
          1. `accel-cmd terminate ip <src_ip>` on `bng` -- drops the
             session immediately, accel-ppp's own real management
             interface (the same tool a real BRAS operator uses).
             NOT "terminate username <mac>" -- confirmed on a real run:
             under IPoE every subscriber shares the same username
             (accel-ppp's own ifname fallback), so that could never
             match a specific one; `ip` needs no MAC lookup either.
          2. A per-MAC marker file in settings.BNG_DIST_FREERADIUS_
             BLOCKED_DIR, which FreeRADIUS's authorize{} turns into an
             Access-Reject (roles/bng's mac_blocked exec module) --
             needed for the SAME reason a DHCP blacklist would be:
             accel-ppp retries auth on its own the next time the client
             re-DHCPs, so a terminate-only block would get silently
             undone the moment that happens. Blocking at the AAA layer
             means it can retry as many times as it wants -- it never
             gets re-admitted until the marker is removed on unblock.
             The match is by MAC (Calling-Station-Id), not User-Name
             (which every IPoE subscriber shares), and takes effect
             immediately: no FreeRADIUS reload or restart is involved.
          On unblock specifically, a third step: tells suscriptor's own
          bng_subscriber_agent.py (over the same FIFO the former lab tooling
          drives) to "kick" that subscriber into a fresh session
          immediately, rather than leaving it to notice on its own
          (potentially a long time later) that its old, terminate()'d
          session is a ghost -- see _kick_subscriber()'s own docstring
          and Subscriber.force_refresh() on the suscriptor side.

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
        accel_cmd_port: int = None,
        freeradius_blocked_dir: str = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.accel_cmd_port = accel_cmd_port or settings.BNG_DIST_ACCEL_CMD_PORT
        self.freeradius_blocked_dir = freeradius_blocked_dir or settings.BNG_DIST_FREERADIUS_BLOCKED_DIR
        self.target_ip = settings.BNG_DIST_TARGET_IP

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

        # Every new controller process starts with a clean mitigation
        # slate: a reject marker left over from a previous process's
        # block is by definition orphaned.
        self._clear_radius_rejects()

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def is_connected(self) -> bool:
        result = self._ssh_bng(["systemctl", "is-active", "--quiet", "accel-pppd", "freeradius"])
        return result.returncode == 0

    def _ssh_suscriptor(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_SUSCRIPTOR_SSH_USER, settings.BNG_DIST_SUSCRIPTOR_SSH_HOST, args,
                    input_text=input_text)

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
    # Mitigation (accel-cmd + FreeRADIUS reject markers)
    # ------------------------------------------------------------------

    def _accel_cmd(self, args: list) -> subprocess.CompletedProcess:
        return self._ssh_bng(["accel-cmd", "-p", str(self.accel_cmd_port), *args])

    # A MAC is blocked at the AAA layer by the existence of a file named
    # after it in freeradius_blocked_dir. FreeRADIUS's authorize{} asks
    # for it on every Access-Request (roles/bng's mac_blocked exec
    # module), so blocking/unblocking takes effect immediately with no
    # reload or restart. Neither is an option: HUP (and radmin `hup
    # files`) does not re-read the `users` data file (a Reject added
    # there is silently ignored -- verified on 3.0.26), and a restart per
    # block/unblock trips systemd's StartLimit (5 per 10s) when an attack
    # involves several sessions.
    _MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

    def _blocked_path(self, mac: str) -> Optional[str]:
        """Path of the marker file for this MAC, or None if it isn't a
        well-formed MAC. The strict check is load-bearing: the value ends
        up in a remote command line."""
        normalized = (mac or "").strip().lower()
        if not self._MAC_RE.match(normalized):
            self._logger.warning(f"[BROADBAND] refusing to use malformed MAC {mac!r} for a reject marker")
            return None
        return f"{self.freeradius_blocked_dir.rstrip('/')}/{normalized}"

    def _set_mac_rejected(self, mac: str, rejected: bool) -> bool:
        """Creates/removes the marker file that makes FreeRADIUS answer
        Access-Reject to this MAC. Best-effort, same convention as every
        other mitigation failure in this adapter: a failure degrades to a
        logged no-op."""
        path = self._blocked_path(mac)
        if path is None:
            return False
        argv = ["sudo", "-n", "touch", path] if rejected else ["sudo", "-n", "rm", "-f", path]
        try:
            result = self._ssh_bng(argv)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] cannot update reject marker {path}: {exc}")
            return False
        if result.returncode != 0:
            self._logger.warning(f"[BROADBAND] cannot update reject marker {path}: {result.stderr.strip()}")
            return False
        return True

    def _clear_radius_rejects(self) -> None:
        """Every new controller process starts with a clean mitigation
        slate -- a marker left over from a PREVIOUS process's block (e.g.
        the controller restarted before that block's wall-clock duration
        elapsed) is orphaned."""
        try:
            result = self._ssh_bng([
                "sudo", "-n", "find", self.freeradius_blocked_dir, "-maxdepth", "1",
                "-type", "f", "-name", "??:??:??:??:??:??", "-delete",
            ])
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] cannot clear reject markers in {self.freeradius_blocked_dir}: {exc}")
            return
        if result.returncode != 0:
            self._logger.warning(
                f"[BROADBAND] cannot clear reject markers in {self.freeradius_blocked_dir}: {result.stderr.strip()}"
            )

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

    def _apply_mitigation_distributed(self, action: MitigationAction) -> bool:
        is_block = action.action in ("block", "rate_limit")
        ok = True

        # NOT "terminate username <mac>" -- confirmed on a real run:
        # under IPoE every subscriber shares the SAME username (accel-
        # ppp's own ifname fallback, see accel-ppp.conf.j2's [ipoe]
        # comment), so a username-keyed terminate can never match a
        # specific subscriber. "terminate ip <address>" (accel-cmd's own
        # documented match key, confirmed via `accel-cmd help`) needs no
        # MAC lookup at all -- src_ip is already on the MitigationAction.
        if is_block:
            try:
                result = self._accel_cmd(["terminate", "ip", action.src_ip])
                if result.returncode != 0:
                    self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {result.stderr.strip()}")
                    ok = False
            except (OSError, subprocess.TimeoutExpired) as exc:
                self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {exc}")
                ok = False

        # The persistent FreeRADIUS reject marker (below) still needs the real
        # MAC -- terminate alone doesn't stop accel-ppp's own automatic
        # re-DHCP retry, and IP is not a stable identity across a fresh
        # lease the way Calling-Station-Id is.
        mac = self._mac_by_ip.get(action.src_ip)
        if mac is None:
            self._logger.warning(f"[BROADBAND] cannot resolve src_ip {action.src_ip!r} to a subscriber MAC, "
                  f"session terminated but no persistent reject entry added")
            return False

        if not self._set_mac_rejected(mac, rejected=is_block):
            ok = False

        if not is_block:
            self._kick_subscriber(action.src_ip)

        self._logger.warning(f"[BROADBAND] {'block' if is_block else 'unblock'} mac={mac} "
              f"(src_ip={action.src_ip}, attack_type={action.attack_type})")
        return ok

    def _kick_subscriber(self, src_ip: str) -> None:
        """Tells suscriptor's bng_subscriber_agent.py to fully
        re-establish the session at this IP -- see that module's own
        Subscriber.force_refresh() docstring for why this is needed at
        all: the accel-cmd terminate above (issued back when this
        subscriber was blocked) leaves that daemon's own cached self.ip
        pointing at a session `bng` no longer tracks, and nothing there
        would otherwise notice until its own next DHCP lease renewal --
        which could be a long time away. Best-effort: a failed kick
        just means that subscriber stays a silent ghost a bit longer,
        not a broken unblock (the FreeRADIUS reject is already gone by
        this point either way)."""
        self._logger.warning(f"[BROADBAND] kicking suscriptor for src_ip={src_ip}")
        try:
            result = self._ssh_suscriptor(["sh", "-c", f"echo 'kick {src_ip}' > {settings.BNG_DIST_FIFO_PATH}"])
            self._logger.warning(f"[BROADBAND] kick ssh rc={result.returncode} stderr={result.stderr.strip()!r}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] cannot kick suscriptor for src_ip={src_ip}: {exc}")

    def apply_mitigation(self, action: MitigationAction) -> bool:
        return self._apply_mitigation_distributed(action)
