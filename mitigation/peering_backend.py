"""
mitigation/peering_backend.py — BGP FlowSpec speaker for the Peering domain.

Talks to a locally running `exabgp` process, which holds the actual BGP
session to r1's `flow` instance (https://github.com/hack3ric/flow) --
NOT FRR. FRR's own FlowSpec-to-dataplane bridge builds the rule object
in memory but never actually installs it in the kernel; this is a
confirmed, long-standing gap in FRR mainline, not a configuration
mistake (see docs/peering-plan.md §2.1, FRRouting/frr#3160). `flow`
receives the same BGP FlowSpec NLRI and translates it into a real
nftables rule via rtnetlink -- confirmed with a live nftables rule (see
docs/peering-plan.md §2.2).

exabgp does NOT create or manage this FIFO itself -- deploy/
spike_flowspec_flow.sh (and, eventually, the real deployment config)
must `mkfifo` it and point exabgp's own config at it via a `process`
block that runs `cat <fifo path>`, whose stdout exabgp reads as
commands. This module only ever writes to that FIFO; it does not
implement BGP itself, nor does it manage the exabgp or flow processes.

CAPABILITY STATUS: both directions are CONFIRMED against a live `flow`
instance (see docs/peering-plan.md §2.2) -- announcing a FlowSpec
discard route produces a real nftables rule, and withdrawing it removes
that same rule (`nft list ruleset` verified empty afterward). Still
unverified: TTL-driven withdrawal specifically (the spike withdrew
manually via the FIFO, not through MitigationAction.duration expiring),
and the measured *effect* on real traffic once wired into the VM lab's
`br` (see docs/peering-plan.md §6). Per implementation-design.md §5's state machine,
apply()/announce()/withdraw() returning True here means DISPATCHED/
ACCEPTED -- do not report it to the UI/logs as APPLIED or VERIFIED
without the readback/effect measurement implementation-design.md §5
requires for those states.
"""
import logging
import os
import shlex
import subprocess
import time
from typing import Dict, Optional, Tuple

from eventlet import tpool

import config.settings as settings
from core.experiment_audit import emit as audit_emit
from core.log_format import log_line
from core.models import MitigationAction
from mitigation.base import MitigationAdapter

_PROTO_NAMES = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}

# nftables table/chain flow.service.j2 (deploy/vm-lab/ansible/roles/br)
# actually installs discard rules into -- see flowspec-hooks.sh.j2 and
# docs/peering-plan.md §2.2's captured `nft list ruleset` output for the
# exact rule shape this is matched against.
_NFT_TABLE = "inet flowspecs"
_NFT_CHAIN = "flowspecs"


class PeeringBackend(MitigationAdapter):
    """
    Announces/withdraws BGP FlowSpec discard routes via exabgp's FIFO API.

    Tracks active routes by (dst_ip, dst_port, protocol) for idempotency
    and to support unblock the same way OpenFlowMitigator does for the
    Enterprise domain.
    """

    def __init__(
        self,
        fifo_path: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        clock=time.time,
    ):
        self.fifo_path = fifo_path or settings.PEERING_EXABGP_FIFO
        self.logger = logger or logging.getLogger(__name__)
        self.clock = clock
        self._active: Dict[Tuple[str, int, str], float] = {}

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        if action.action == "bgp_flowspec_discard":
            return self.announce(action.dst_ip, action.dst_port, action.protocol)
        if action.action == "unblock":
            return self.withdraw(action.dst_ip, action.dst_port, action.protocol)
        return False

    # ------------------------------------------------------------------
    # Public mitigation methods
    # ------------------------------------------------------------------

    def announce(self, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """Idempotent -- announcing an already-active route is a no-op success."""
        key = (dst_ip, dst_port, protocol)
        if key in self._active:
            return True

        if not self._send(self._flow_command("announce", dst_ip, dst_port, protocol)):
            return False

        self._active[key] = self.clock()
        self.logger.info(log_line(
            "bgp", "MITIGATION", "FLOWSPEC_ANNOUNCED",
            f"destination={dst_ip}:{dst_port}/{protocol}",
        ))
        self._spawn_install_verification(dst_ip, dst_port, protocol)
        return True

    def withdraw(self, dst_ip: str, dst_port: int, protocol: str) -> bool:
        key = (dst_ip, dst_port, protocol)
        if key not in self._active:
            return False

        ok = self._send(self._flow_command("withdraw", dst_ip, dst_port, protocol))
        self._active.pop(key, None)
        if ok:
            self.logger.info(log_line(
                "bgp", "MITIGATION", "FLOWSPEC_WITHDRAWN",
                f"destination={dst_ip}:{dst_port}/{protocol}",
            ))
        return ok

    def is_connected(self) -> bool:
        """
        True only if the FIFO exists -- i.e. exabgp was configured with
        the expected `api` process section and created it. This does NOT
        confirm the BGP session to r1 is established.
        """
        return bool(self.fifo_path) and os.path.exists(self.fifo_path)

    # ------------------------------------------------------------------
    # Real dataplane-installation confirmation (tI, HE3 / tesis Tabla 3.6)
    # ------------------------------------------------------------------
    #
    # announce()/_send() only ever confirm the FIFO write succeeded -- per
    # this module's own docstring, that is DISPATCHED/ACCEPTED, not
    # APPLIED/VERIFIED. docs/peering-plan.md §2.2 already proved `flow`
    # does install a real nftables rule (captured there with a plain `nft
    # list ruleset` against a standalone spike), and bgp_adapter.py's own
    # docstring names that exact gap: "confirmed... but only against a
    # standalone spike, not yet against `br` in the VM lab". This is that
    # first real integration.
    #
    # Deliberately NOT inline in announce()/apply_mitigation(): this
    # domain's own telemetry collector (collectors/peering_flow_
    # collector.py) documents, from a real prior incident, that an SSH
    # round trip to `br` on every pipeline cycle was the dominant cost of
    # this domain's cycle time and was removed from the hot path for
    # exactly that reason. Re-adding one unconditionally here would
    # reintroduce that regression -- for every attack, not just this
    # domain's. So this runs in its own greenthread, spawned ONCE per
    # newly-announced block (announce() is already idempotent on repeat
    # calls for the same key), bounded to a handful of retries, and never
    # blocks apply_mitigation()'s return -- a slow or unreachable `br`
    # can delay only this domain's own tI measurement, never detection or
    # mitigation dispatch for any domain.

    def _spawn_install_verification(self, dst_ip: str, dst_port: int, protocol: str) -> None:
        try:
            from ryu.lib import hub
        except ImportError:
            # Standalone/test context (no Ryu reactor) -- nothing to
            # spawn into. tI simply stays unconfirmed, same as before
            # this method existed.
            return
        hub.spawn(self._verify_installed_background, dst_ip, dst_port, protocol)

    def _verify_installed_background(
        self, dst_ip: str, dst_port: int, protocol: str,
        attempts: int = 6, interval_s: float = 0.5, ssh_timeout_s: float = 2.0,
    ) -> None:
        from ryu.lib import hub
        key = (dst_ip, dst_port, protocol)
        for _ in range(attempts):
            if key not in self._active:
                return  # withdrawn (or never truly active) before confirmation
            if self._check_nft_rule(dst_ip, dst_port, protocol, ssh_timeout_s):
                audit_emit(
                    self.logger, 'mitigation_installed', domain='bgp',
                    action=dict(dst_ip=dst_ip, dst_port=dst_port, protocol=protocol),
                )
                return
            hub.sleep(interval_s)
        self.logger.warning(log_line(
            "bgp", "MITIGATION", "INSTALL_UNCONFIRMED",
            f"destination={dst_ip}:{dst_port}/{protocol} -- nftables rule on br "
            f"never observed within {attempts * interval_s:.1f}s",
        ))

    def _check_nft_rule(self, dst_ip: str, dst_port: int, protocol: str, timeout_s: float) -> bool:
        """One SSH round trip reading br's real `flowspecs` nftables chain,
        off the hot path (see class-level note above). ControlMaster/
        ControlPersist (same convention as telemetry/broadband_adapter.py's
        own _ssh()) keeps repeat calls -- across different announce()s --
        cheap; only the very first ever pays full handshake cost."""
        user = getattr(settings, 'PEERING_DIST_BR_SSH_USER', None)
        host = getattr(settings, 'PEERING_DIST_BR_SSH_HOST', None)
        if not user or not host:
            return False
        args = ["nft", "list", "chain"] + shlex.split(_NFT_TABLE) + [_NFT_CHAIN]
        try:
            result = tpool.execute(
                subprocess.run,
                ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(timeout_s, 5):.0f}",
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "ControlMaster=auto", "-o", "ControlPersist=600",
                 "-o", "ControlPath=/run/ssh-mux-peering-%C",
                 f"{user}@{host}", shlex.join(args)],
                capture_output=True, text=True, timeout=timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.logger.warning(log_line(
                "bgp", "MITIGATION", "INSTALL_CHECK_FAILED",
                f"destination={dst_ip}:{dst_port}/{protocol} err={exc}",
            ))
            return False
        if result.returncode != 0:
            return False
        proto_name = _PROTO_NAMES.get(protocol)
        needle_ip = f"ip daddr {dst_ip} "
        for line in result.stdout.splitlines():
            if needle_ip not in line:
                continue
            if proto_name and proto_name not in line:
                continue
            if dst_port and f"{{ {dst_port} }}" not in line and f"dport {dst_port}" not in line:
                continue
            return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_command(verb: str, dst_ip: str, dst_port: int, protocol: str) -> str:
        """
        Build one ExaBGP flow-route command line. dst_ip is announced as
        a /32 host route -- this backend only ever discards traffic
        toward a single destination IP (the attack target), never a
        broader prefix; RTBH-style whole-prefix blackholing is out of
        scope for this action (see docs/peering-plan.md §1).
        """
        match = [f"destination {dst_ip}/32;"]
        proto = _PROTO_NAMES.get(protocol)
        if proto:
            match.append(f"protocol {proto};")
        if dst_port:
            match.append(f"destination-port ={dst_port};")

        match_body = " ".join(match)
        return f"{verb} flow route {{ match {{ {match_body} }} then {{ discard; }} }}"

    def _send(self, command: str) -> bool:
        if not self.fifo_path:
            self.logger.warning("PEERING_EXABGP_FIFO not configured -- cannot send: %s", command)
            return False
        try:
            # O_NONBLOCK so this never hangs the calling thread if exabgp
            # isn't reading the FIFO (e.g. the process is down) -- a plain
            # open() on a FIFO with no reader blocks forever otherwise.
            fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            try:
                os.write(fd, (command + "\n").encode())
            finally:
                os.close(fd)
            return True
        except OSError as exc:
            self.logger.warning("Failed writing to exabgp FIFO %s: %s", self.fifo_path, exc)
            return False
