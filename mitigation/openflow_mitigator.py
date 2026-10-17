import logging
from typing import Callable, Dict, List, Optional, Set, Tuple

import config.settings as settings
from core.log_format import log_line
from forwarding.syn_twin import syn_twin_match
from core.models import MitigationAction
from mitigation.base import MitigationAdapter


PROTO_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}


class OpenFlowMitigator(MitigationAdapter):
    """
    Mitigation backend for the OpenFlow / SDN domain.

    Installs high-priority drop rules to block traffic matching an
    attack's exact L4 flow — src_ip, dst_ip, protocol and dst_port —
    rather than blanket-blocking the source IP. Forwarding rules stay
    L3-only; only mitigation needs L4 precision.

    Scope:
    - Single-attacker block (src_ip != "*") with a known (dpid, in_port):
      installed on that ONE switch only, matching in_port too — the
      block sits on the switch+port closest to the attacker instead of
      the whole network.
    - Distributed attack (src_ip == "*") or unknown ingress point: falls
      back to every registered switch, matching the L4 5-tuple only —
      there's no single entry point to scope to.

    The controller registers/deregisters datapaths as switches connect
    and disconnect.
    """

    # OpenFlow flow rule priority for drop rules (higher than forwarding
    # rules). Shared with FlowCollector (config/settings.py) so it can
    # exclude these from polled flow stats.
    DROP_PRIORITY = settings.MITIGATION_DROP_PRIORITY

    # Priority LearningSwitch uses for its L3 (ipv4_src/ipv4_dst) forwarding
    # rules — needed to delete exactly those entries, not the drop rules.
    FORWARDING_PRIORITY = settings.FORWARDING_PRIORITY

    # Priority of each L3 rule's SYN twin -- deleted together with it.
    SYN_TWIN_PRIORITY = settings.SYN_TWIN_PRIORITY

    # How many send_msg calls clear_forwarding_rules() makes between
    # cooperative yields. A distributed attack's source list can run into
    # the thousands; without yielding periodically, that loop runs as one
    # uninterrupted burst on Ryu's single eventlet thread, starving every
    # other greenthread — including each datapath's own echo-reply loop —
    # for as long as it takes. Observed taking 36s for ~6000 send_msg
    # calls under real attack load, during which a switch missed its
    # keepalives and reconnected. Yielding every N calls lets the hub
    # service those in between instead.
    YIELD_EVERY = 200

    def __init__(
        self,
        yield_fn: Optional[Callable[[], None]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        # (src_ip, dst_ip, dst_port, protocol, dpid) tuples currently
        # blocked. dpid is part of the key (None for an unscoped/network-
        # wide block) so that two DIFFERENT physical ingress locations for
        # the same destination — e.g. a distributed attack entering
        # through two different real attacker switches at once — are
        # tracked as two distinct entries instead of the second one being
        # silently skipped as "already blocked" once the first is in.
        self._blocked: Set[Tuple[str, str, int, str, Optional[int]]] = set()
        self._datapaths: Dict[int, object] = {}   # dpid -> Ryu datapath
        # Cooperative-yield hook (e.g. ryu.lib.hub.sleep(0)) — optional so
        # this stays testable without a Ryu/eventlet runtime.
        self._yield_fn = yield_fn or (lambda: None)
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Datapath lifecycle — called from the Ryu controller
    # ------------------------------------------------------------------

    def register(self, datapath) -> None:
        """Register a new switch datapath."""
        self._datapaths[datapath.id] = datapath

    def deregister(self, dpid: int) -> None:
        """Remove a disconnected switch datapath."""
        self._datapaths.pop(dpid, None)

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        if action.action == "block":
            dpid = int(action.device_id) if action.device_id.isdigit() else None
            self.block(
                action.src_ip, action.dst_ip, action.dst_port, action.protocol,
                dpid=dpid, in_port=action.in_port or None,
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Public mitigation methods
    # ------------------------------------------------------------------

    def block(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        dpid: Optional[int] = None,
        in_port: Optional[int] = None,
    ) -> None:
        """
        Install an L4 drop rule (src_ip, dst_ip, protocol, dst_port).
        Idempotent — calling block() again for the same (src_ip, dst_ip,
        dst_port, protocol, dpid) is a no-op.

        When dpid is known, the rule is installed on that ONE switch
        only — the one closest to the attacker, or, for a distributed
        attack's per-location block (src_ip="*" but dpid/in_port known
        from where its packets were actually observed entering), the
        one closest to that physical entry point — and matches in_port
        too when known, instead of dropping the traffic network-wide.
        """
        key = (src_ip, dst_ip, dst_port, protocol, dpid)

        if key in self._blocked:
            return

        self._blocked.add(key)

        targets = self._scoped_targets(dpid)

        for datapath in targets:
            self._install_drop_rule(
                datapath, src_ip, dst_ip, dst_port, protocol,
                in_port=in_port if datapath.id == dpid else None,
            )

        scope = (
            f"switch {dpid}" + (f" port {in_port}" if in_port else "")
            if len(targets) == 1 and dpid is not None
            else f"{len(targets)} switch(es) (network-wide)"
        )
        # Supplementary detail the standard MITIGATION line (ryu_controller_2.
        # py's _run_pipeline) doesn't carry -- which switch/port the drop
        # rule actually landed on.
        self._logger.info(log_line(
            "enterprise", "MITIGATION", "DROP_RULE_INSTALLED",
            f"source={src_ip} destination={dst_ip}:{dst_port}/{protocol} scope={scope}",
        ))

    def unblock(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> None:
        """
        Remove the drop rule for this L4 flow from every switch it could
        have been installed on (scoped or network-wide — unblock doesn't
        need to know which, it just deletes wherever it matches), and
        forgets every _blocked entry for it regardless of which dpid
        each one was scoped to (the caller doesn't track per-location
        dpids on its side either — unblocking means this flow is no
        longer under attack anywhere).
        """
        matching = [k for k in self._blocked if k[:4] == (src_ip, dst_ip, dst_port, protocol)]

        if not matching:
            return

        for key in matching:
            self._blocked.discard(key)

        for datapath in self._datapaths.values():
            self._delete_drop_rule(datapath, src_ip, dst_ip, dst_port, protocol)

        # No log here -- OrchestrationController.check_unblocks() reports
        # this through the same MITIGATION dashboard/logger line every
        # other domain's actions go through.

    def _scoped_targets(self, dpid: Optional[int]) -> List[object]:
        """
        The datapath(s) a block should be installed on: just the known
        ingress switch when one is known and still connected, otherwise
        every switch.
        """
        if dpid is not None and dpid in self._datapaths:
            return [self._datapaths[dpid]]
        return list(self._datapaths.values())

    def clear_forwarding_rules(self, dst_ip: str, sources: List[str]) -> None:
        """
        Delete the per-source L3 forwarding rules (installed by
        LearningSwitch, priority=10) that were letting these specific
        sources reach dst_ip. Used right after installing a destination-wide
        block ("*" src) for a distributed attack: that block already wins
        on priority regardless, but leaving thousands of one-shot spoofed-
        source forwarding entries around just wastes flow table space.

        Deletes with an exact (priority, match) using OFPFC_DELETE_STRICT,
        scoped per known source, so the drop rule for this same dst_ip
        (priority=100, a different match/priority) is never touched.
        """
        calls = 0

        for datapath in self._datapaths.values():
            for src_ip in sources:
                self._delete_forwarding_rule(datapath, src_ip, dst_ip)
                self._delete_syn_twin_rule(datapath, src_ip, dst_ip)
                calls += 2
                if calls % self.YIELD_EVERY == 0:
                    self._yield_fn()

        # DEBUG, not INFO -- this fires on every flow_stats_reply cycle
        # for as long as a wildcard/distributed block stays active (see
        # OrchestrationController.sweep_blocked_forwarding), which is
        # routine housekeeping, not something worth surfacing in the
        # normal MITIGATION log stream the way an actual BLOCK/UNBLOCK is.
        self._logger.debug(log_line(
            "enterprise", "MITIGATION", "FORWARDING_CLEARED",
            f"count={len(sources)} destination={dst_ip} switches={len(self._datapaths)}",
        ))

    # ------------------------------------------------------------------
    # Internal OpenFlow helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _l4_match_fields(src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> dict:
        fields = {"eth_type": 0x0800, "ipv4_dst": dst_ip}

        # "*" marks a distributed/spoofed-source attack — there's no single
        # attacker IP to match on, so the rule drops by destination alone.
        if src_ip and src_ip != "*":
            fields["ipv4_src"] = src_ip

        proto_num = PROTO_NUMBERS.get(protocol)
        if proto_num is None:
            return fields

        fields["ip_proto"] = proto_num

        if protocol == "TCP" and dst_port:
            fields["tcp_dst"] = dst_port
        elif protocol == "UDP" and dst_port:
            fields["udp_dst"] = dst_port

        return fields

    def _install_drop_rule(self, datapath, src_ip, dst_ip, dst_port, protocol, in_port=None) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        fields = self._l4_match_fields(src_ip, dst_ip, dst_port, protocol)
        if in_port:
            fields["in_port"] = in_port

        match = parser.OFPMatch(**fields)
        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=self.DROP_PRIORITY,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def _delete_drop_rule(self, datapath, src_ip, dst_ip, dst_port, protocol) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**self._l4_match_fields(src_ip, dst_ip, dst_port, protocol))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            priority=self.DROP_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

    def _delete_forwarding_rule(self, datapath, src_ip: str, dst_ip: str) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            priority=self.FORWARDING_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

    def _delete_syn_twin_rule(self, datapath, src_ip: str, dst_ip: str) -> None:
        """Strict-deletes the SYN twin of this pair's L3 rule (see
        forwarding/syn_twin.py). Deleting a rule that doesn't exist is a
        silent no-op in OpenFlow, so this is safe for pairs that never got
        one (provisional rules)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            priority=self.SYN_TWIN_PRIORITY,
            match=syn_twin_match(parser, src_ip, dst_ip),
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)
