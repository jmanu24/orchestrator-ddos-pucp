"""
mitigation/broadband_mitigator.py — BNG-native actuation backend for the
Fixed Broadband domain (accel-ppp + FreeRADIUS on `bng`, see deploy/vm-lab).

Pure actuation: action.mac must already be resolved by the caller --
telemetry/broadband_adapter.py's BroadbandAdapter.apply_mitigation() is
the only caller, and the only place this domain's src_ip -> MAC mapping
is learned (from the conntrack sidecar's session list -- see that
module's own docstring). An empty action.mac means the adapter couldn't
resolve one; this class still terminates the session by src_ip in that
case (accel-cmd needs no MAC), it just can't add the persistent AAA
reject marker below.

Two real BNG-native actions per block:
  1. `accel-cmd terminate ip <src_ip>` on `bng` -- drops the session
     immediately, accel-ppp's own real management interface (the same
     tool a real BRAS operator uses). NOT "terminate username <mac>" --
     confirmed on a real run: under IPoE every subscriber shares the
     same username (accel-ppp's own ifname fallback, see
     accel-ppp.conf.j2's [ipoe] comment), so a username-keyed terminate
     can never match a specific subscriber; `ip` needs no MAC lookup
     either.
  2. A per-MAC marker file in settings.BNG_DIST_FREERADIUS_BLOCKED_DIR,
     which FreeRADIUS's authorize{} turns into an Access-Reject (roles/
     bng's mac_blocked exec module) -- needed for the SAME reason a DHCP
     blacklist would be: accel-ppp retries auth on its own the next time
     the client re-DHCPs, so a terminate-only block would get silently
     undone the moment that happens. Blocking at the AAA layer means it
     can retry as many times as it wants -- it never gets re-admitted
     until the marker is removed on unblock. The match is by MAC
     (Calling-Station-Id), not User-Name (which every IPoE subscriber
     shares), and takes effect immediately: no FreeRADIUS reload or
     restart is involved.
On unblock specifically, a third step: tells suscriptor's own
bng_subscriber_agent.py (over the same FIFO the former lab tooling
drives) to "kick" that subscriber into a fresh session immediately,
rather than leaving it to notice on its own (potentially a long time
later) that its old, terminate()'d session is a ghost -- see
_kick_subscriber()'s own docstring and Subscriber.force_refresh() on the
suscriptor side.

Use self._logger, NOT print(), anywhere in this class -- confirmed on a
real run: ryu-manager's systemd unit redirects stdout to a file
(StandardOutput=append:/var/log/ryu-manager.log), and Python fully-
buffers stdout when it isn't a TTY. A plain print() call can sit in that
buffer indefinitely and never actually reach the file, while
`self._logger.warning(...)` (a real logging.StreamHandler) flushes per
record.
"""
import logging
import re
import subprocess
from typing import Optional

import config.settings as settings
from core.log_format import log_line
from core.models import MitigationAction
from core.ssh_utils import run_ssh as _ssh
from mitigation.base import MitigationAdapter


class BngMitigator(MitigationAdapter):
    """accel-cmd + FreeRADIUS reject-marker actuation -- see module docstring."""

    domain_name = "broadband"

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

    def __init__(
        self,
        accel_cmd_port: int = None,
        freeradius_blocked_dir: str = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.accel_cmd_port = accel_cmd_port or settings.BNG_DIST_ACCEL_CMD_PORT
        self.freeradius_blocked_dir = freeradius_blocked_dir or settings.BNG_DIST_FREERADIUS_BLOCKED_DIR

        # Same convention as telemetry/broadband_adapter.py's own
        # logger -- passed down so every log line across domains shares
        # the same name/format.
        self._logger = logger or logging.getLogger(__name__)

        # Every new controller process starts with a clean mitigation
        # slate: a reject marker left over from a previous process's
        # block is by definition orphaned.
        self._clear_radius_rejects()

    # ------------------------------------------------------------------
    # SSH helpers
    # ------------------------------------------------------------------

    def _ssh_suscriptor(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_SUSCRIPTOR_SSH_USER, settings.BNG_DIST_SUSCRIPTOR_SSH_HOST, args,
                    input_text=input_text)

    def _ssh_bng(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_BNG_SSH_USER, settings.BNG_DIST_BNG_SSH_HOST, args, input_text=input_text)

    def _accel_cmd(self, args: list) -> subprocess.CompletedProcess:
        return self._ssh_bng(["accel-cmd", "-p", str(self.accel_cmd_port), *args])

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        is_block = action.action in ("block", "rate_limit")
        ok = True

        # NOT "terminate username <mac>" -- see module docstring.
        # "terminate ip <address>" (accel-cmd's own documented match
        # key, confirmed via `accel-cmd help`) needs no MAC lookup at
        # all -- src_ip is already on the MitigationAction.
        if is_block:
            try:
                result = self._accel_cmd(["terminate", "ip", action.src_ip])
                if result.returncode != 0:
                    self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {result.stderr.strip()}")
                    ok = False
            except (OSError, subprocess.TimeoutExpired) as exc:
                self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {exc}")
                ok = False

        # The persistent FreeRADIUS reject marker (below) still needs the
        # real MAC -- terminate alone doesn't stop accel-ppp's own
        # automatic re-DHCP retry, and IP is not a stable identity across
        # a fresh lease the way Calling-Station-Id is. action.mac is
        # empty when telemetry/broadband_adapter.py couldn't resolve one
        # (see MitigationAction's own docstring in core/models.py).
        if not action.mac:
            self._logger.warning(f"[BROADBAND] no subscriber MAC resolved for src_ip {action.src_ip!r}, "
                  f"session terminated but no persistent reject entry added")
            return False

        if not self._set_mac_rejected(action.mac, rejected=is_block):
            ok = False

        if not is_block:
            self._kick_subscriber(action.src_ip)

        self._logger.warning(f"[BROADBAND] {'block' if is_block else 'unblock'} mac={action.mac} "
              f"(src_ip={action.src_ip}, attack_type={action.attack_type})")
        return ok

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
        other mitigation failure in this class: a failure degrades to a
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
