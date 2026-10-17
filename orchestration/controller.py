from dataclasses import asdict
from core.experiment_audit import emit as audit_emit
import json
import logging
import os
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import config.settings as settings
from core.log_format import log_line
from core.models import CorrelatedEvent, DetectionResult, MitigationAction
from decision.engine import DecisionEngine, Decision
from telemetry.base import DomainAdapter
from mitigation.openflow_mitigator import OpenFlowMitigator, PROTO_NUMBERS


_THRESHOLD_BY_PROTOCOL = {
    "TCP": settings.SYN_THRESHOLD,
    "UDP": settings.UDP_THRESHOLD,
    "ICMP": settings.ICMP_THRESHOLD,
}


class OrchestrationController:
    """
    Orchestration and Control layer.

    Sits at the bottom of the centralized controller pipeline:
      DetectionResults → DecisionEngine → MitigationActions → Domain adapters

    Responsibilities:
    1. Run DetectionResults through the DecisionEngine to produce a Decision.
    2. Map the Decision to domain-specific MitigationActions.
    3. Dispatch each action to the correct adapter or the OpenFlowMitigator.

    The OpenFlowMitigator is kept separate from the DomainAdapter list because
    it requires live Ryu datapath references (registered/deregistered by the
    Ryu controller as switches connect and disconnect).

    Unblocking is traffic-driven rather than time-driven: a blocked flow's
    drop rule keeps counting matched (dropped) packets, so check_unblocks()
    can tell whether the attacker is still flooding and release the block
    once that flow's volume falls back under a fraction of the threshold
    that triggered it.
    """

    # Release a block once the flow's pps falls below this fraction of the
    # detection threshold that originally triggered it.
    UNBLOCK_RATIO = 0.5

    # Require this many consecutive below-threshold cycles before actually
    # unblocking, so a brief lull in a bursty attack doesn't lift the block
    # only for the next burst to need re-detection from scratch. Shared by
    # both check_unblocks() (openflow) and check_mobile_unblocks() (mobile).
    # Expressed in pipeline CYCLES, not real time -- this implicitly meant
    # 50s of confirmation back when config.settings.COLLECT_INTERVAL was
    # 5s. Once COLLECT_INTERVAL got lowered to 0.5s (for mobile-domain
    # sub-second latency), the same 10-cycle count silently became only 5s
    # of real confirmation -- confirmed on a real run: openflow would
    # BLOCK a still-running hping3 SYN flood and then UNBLOCK it ~5s later
    # because a couple of noisy below-threshold samples off the DROP
    # rule's own counters (record_block_traffic) were enough to satisfy
    # 10 cycles, triggering a fast BLOCK/UNBLOCK/re-detect oscillation.
    # Raised 10x to restore the original 50s of real confirmation time.
    UNBLOCK_CONFIRM_CYCLES = 100

    def __init__(
        self, adapters: List[DomainAdapter], locate_host=None,
        locate_source_ingress=None, yield_fn=None, logger=None,
    ):
        # Index adapters by domain name for O(1) dispatch
        self._adapters: Dict[str, DomainAdapter] = {
            a.domain_name: a for a in adapters
        }
        self._decision_engine = DecisionEngine()
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)
        # yield_fn (e.g. ryu.lib.hub.sleep(0)) is threaded through to
        # OpenFlowMitigator so its forwarding-rule cleanup loop — which can
        # run into thousands of iterations under a distributed attack —
        # cooperatively yields instead of starving every other greenthread
        # (including each switch's own echo-reply loop) for the duration.
        self.of_mitigator = OpenFlowMitigator(yield_fn=yield_fn, logger=self._logger)

        # Optional Callable[[ip], Optional[Tuple[int,int]]] — (dpid, port)
        # an IP's mac was last confirmed attached to via a genuine edge
        # port (LearningSwitch.get_host_location). This is the actual
        # source of truth for scoping a block to the switch closest to an
        # attacker — unlike a detection's own device_id/in_port, which
        # just reflects whichever switch's packet-in happened to be
        # processed, not necessarily the one nearest the source.
        self._locate_host = locate_host

        # Optional Callable[[src_ip, dst_ip], Tuple[Optional[int],
        # Optional[int]]] — (dpid, in_port) a (src_ip, dst_ip) pair was
        # last observed entering on via packet-in (OpenFlowAdapter.
        # get_source_ingress). Unlike _locate_host above, this works for
        # a spoofed/fabricated src_ip too — it reflects where the packet
        # physically arrived, not an ARP-learned identity a fake IP could
        # never produce. Used to scope each individual source's block in
        # a distributed attack to its own real ingress switch+port.
        self._locate_source_ingress = locate_source_ingress

        # (src_ip, dst_ip, dst_port, protocol) -> MitigationAction currently
        # enforced for the mobile domain (separate from _active_blocks
        # below because its unblock signal is telemetry-pps-based, not
        # openflow drop-rule-counter-based -- see check_mobile_unblocks).
        self._active_mobile_blocks: Dict[Tuple[str, str, int, str], MitigationAction] = {}
        self._mobile_below_threshold_streak: Dict[Tuple[str, str, int, str], int] = {}
        # (src_ip, dst_ip, dst_port, protocol) -> time.time() the block was
        # first dispatched -- only consulted for domains in
        # settings.PRESENCE_BLIND_DOMAINS (see check_mobile_unblocks's
        # docstring on why those can't use the presence-streak signal at
        # all: a real session-stop suppresses every TelemetryEvent for
        # that source, which is indistinguishable from "the attacker
        # stopped" if presence is the only signal available).
        self._mobile_block_started_at: Dict[Tuple[str, str, int, str], float] = {}
        # key -> time.time() of the last cycle whose bgp telemetry still
        # showed offered load at/above the release threshold for that
        # block (see _bgp_offered_load_present). Starts at the block time.
        self._bgp_offered_last_seen: Dict[Tuple[str, str, int, str], float] = {}
        # Same idea for broadband: last cycle in which the blocked
        # subscriber's MAC was still sending at/above the release threshold
        # (see _broadband_release_wait).
        self._bb_offered_last_seen: Dict[Tuple[str, str, int, str], float] = {}

        # (src_ip, dst_ip, dst_port, protocol) -> MitigationAction currently
        # enforced, only for the openflow domain (the only one with a real
        # drop-rule backend so far).
        self._active_blocks: Dict[Tuple[str, str, int, str], MitigationAction] = {}

        # Same keys -> count of consecutive cycles seen below the unblock
        # threshold. Reset to 0 whenever traffic rises back above it.
        self._below_threshold_streak: Dict[Tuple[str, str, int, str], int] = {}

        # (src_ip, dst_ip) flows that have completed at least one full
        # detection cycle without that specific source being flagged as
        # part of an attack toward that destination. LearningSwitch refuses
        # to cache *any* rule — permit or block — for a flow until it's in
        # this set, so brand-new traffic always goes through the detection
        # pipeline before the switch commits to anything.
        #
        # Scoped per-FLOW, not per-destination: a shared, frequently
        # -targeted destination (e.g. this topology's central server, which
        # is both a legitimate attack target and the one destination every
        # domain's benign baseline also reaches) would otherwise force
        # EVERY source's traffic toward it through LearningSwitch's short
        # -lived provisional flow (PROVISIONAL_TIMEOUT=2s) any time even
        # ONE unrelated source is under active attack against it. Confirmed
        # on a real run: once the central server became a real, frequently
        # -attacked-and-unblocked target, innocent hosts' own steady ICMP
        # baseline toward it started re-triggering packet-in every ~2s
        # instead of every VALIDATED_FLOW_HARD_TIMEOUT=30s, and
        # DDoSCollector's per-(dst_ip, dst_port, protocol) aggregation
        # (deliberately source-blind — see its docstring — to catch
        # spoofed/distributed floods) summed all of those innocent hosts'
        # packet-ins into one shared counter, occasionally spiking past
        # ICMP_THRESHOLD and producing a false ICMP_FLOOD against a host
        # that was never actually flooding. Per-flow scoping keeps a truly
        # new (src, dst) pair protected exactly as before, without
        # punishing every OTHER source that happens to share a popular
        # destination with an actual attacker.
        self._validated_flows: Set[Tuple[str, str]] = set()

        # (key, dpid) -> last sample of the matching drop rule's counters.
        # Once blocked, an attacker's packets are dropped in the fast path
        # and never reach packet_in again, and FlowCollector deliberately
        # excludes drop-rule entries from telemetry (so the mitigation's
        # own counters don't get re-detected as a fresh attack) — so this
        # is tracked independently, purely to answer "is this still being
        # hit" for check_unblocks.
        self._block_traffic_samples: Dict[Tuple[Tuple[str, str, int, str], int], dict] = {}

        # key -> most recently computed pps for its drop rule, summed
        # across all switches that reported a fresh-enough sample.
        self._block_pps: Dict[Tuple[str, str, int, str], float] = {}

        # (dpid, port_no) pairs known to be switch-switch links, from
        # topology discovery. A packet with no matching flow rule triggers
        # packet-in on every switch it passes through, not just the one
        # nearest the source, so an ingress (dpid, in_port) that's actually
        # one of these can't be trusted to scope a block to.
        self._interswitch_ports: set = set()

    # ------------------------------------------------------------------
    # Datapath lifecycle (called from the Ryu controller)
    # ------------------------------------------------------------------

    def register_datapath(self, datapath) -> None:
        self.of_mitigator.register(datapath)

    def update_interswitch_ports(self, ports: set) -> None:
        """Called by the Ryu controller whenever topology is (re)discovered."""
        self._interswitch_ports = ports

    def is_interswitch_port(self, dpid: int, port_no: int) -> bool:
        """Queried by LearningSwitch before trusting a mac sighting as a
        genuine host attachment point."""
        return (dpid, port_no) in self._interswitch_ports

    def deregister_datapath(self, dpid: int) -> None:
        self.of_mitigator.deregister(dpid)

    # ------------------------------------------------------------------
    # Main pipeline entry point
    # ------------------------------------------------------------------

    def process(self, detections: List[DetectionResult]) -> List[MitigationAction]:
        """
        Evaluate detections, decide on a response, and dispatch mitigation.
        Returns the list of MitigationActions that were issued (empty if no
        attack scored above the decision threshold).

        Detections are grouped by attacker identity (src_ip, dst_ip,
        dst_port, protocol) first, and each group gets its own independent
        decision/threshold check — DecisionEngine.evaluate() only ever
        returns the single best-scoring entry it's given, so without this
        grouping, two simultaneous distinct attacks (e.g. a bidirectional
        ICMP flood, or two unrelated attackers) would compete for one
        "winner" slot each cycle and only ever get mitigated one at a
        time, alternating cycle to cycle as their relative scores shift.
        """
        if not detections:
            return []

        groups: Dict[Tuple[str, str, int, str], List[DetectionResult]] = defaultdict(list)
        for d in detections:
            groups[(d.src_ip, d.dst_ip, d.dst_port, d.protocol)].append(d)

        all_actions: List[MitigationAction] = []

        for group in groups.values():
            det_dicts = [
                {
                    "type": d.attack_type,
                    "src_ip": d.src_ip,
                    "score": d.score * d.confidence,
                }
                for d in group
            ]

            decision: Decision = self._decision_engine.evaluate(det_dicts)

            audit_emit(self._logger,'decision',accepted=decision is not None,
                threshold=self._decision_engine.global_threshold,
                weights=self._decision_engine.weights,
                candidates=[dict(detection=asdict(d),effective_score=d.score*d.confidence*self._decision_engine.weights.get(d.attack_type,1.0)) for d in group])
            if decision is None:
                continue

            actions = self._build_actions(decision, group)

            newly_enforced: List[MitigationAction] = []

            for action in actions:
                audit_emit(self._logger,'mitigation_attempt',action=asdict(action))
                if self._dispatch(action):
                    audit_emit(self._logger,'mitigation_issued',action=asdict(action),confirmation='backend_dispatch_returned_true')
                    # Only newly-enforced actions are reported back — an
                    # already-active block re-dispatching every cycle
                    # (because the attack is still ongoing) is a no-op at
                    # the mitigator level, so it shouldn't re-log either.
                    newly_enforced.append(action)
                    all_actions.append(action)

            if (
                newly_enforced
                and decision.attack_type in ("DDOS_DISTRIBUTED", "MULTIDOMAIN_DISTRIBUTED_ATTACK")
                and any(a.domain == "enterprise" for a in newly_enforced)
            ):
                # One cleanup pass per group, after every location's block
                # in it is already live — not per action, since
                # _build_actions can split one distributed detection into
                # several actions (one per distinct ingress location, or
                # for MULTIDOMAIN_DISTRIBUTED_ATTACK also one per
                # contributing domain), each carrying only the sources
                # seen at ITS location; the union covers every source in
                # the whole detection. Restricted to enterprise-domain
                # actions -- of_mitigator.clear_forwarding_rules only
                # means anything for OpenFlow's own forwarding-rule
                # table; a mobile/broadband source in the same
                # MULTIDOMAIN_DISTRIBUTED_ATTACK never had an L3
                # forwarding rule there to begin with.
                enterprise_actions = [a for a in newly_enforced if a.domain == "enterprise"]
                all_sources = {s for action in enterprise_actions for s in action.sources}
                if all_sources:
                    self.of_mitigator.clear_forwarding_rules(
                        enterprise_actions[0].dst_ip, list(all_sources)
                    )

        return all_actions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_actions(
        self,
        decision: Decision,
        detections: List[DetectionResult],
    ) -> List[MitigationAction]:
        """
        Build one MitigationAction per affected domain.
        Chooses the mitigation action type based on attack type and domain.

        DDOS_DISTRIBUTED and MULTIDOMAIN_DISTRIBUTED_ATTACK are the
        exception to "one action per detection":
        each carries a real per-source list (`DetectionResult.sources`),
        which is first partitioned by each source's OWN real domain
        (`DetectionResult.source_domains`) rather than assumed to all
        share `d.domain` (just the representative contributing event's
        domain — correlation/correlator.py already aggregates telemetry
        across domains toward one dst_ip, so one detection's sources can
        genuinely span more than one domain, which is exactly what
        MULTIDOMAIN_DISTRIBUTED_ATTACK means). Each per-domain partition
        is then dispatched through that domain's own real mitigation
        shape:
        - enterprise sources: every source IP is first resolved to the
          physical HOST port its packets were actually confirmed
          entering on (see _scoped_ingress_for_source — packet-in-derived
          and host-port-filtered, works even for a spoofed src_ip, since
          it reflects where the packet arrived, not an ARP-learned
          identity a fake IP could never produce), then grouped by that
          location. One action per *distinct location* — not per source —
          matching only (in_port, dst_ip, dst_port, protocol), no src_ip:
          a real spoofed flood is virtually always many fake IPs funneled
          through ONE real attacker port, so this normally collapses to a
          single precise block instead of one rule per fake IP. Sources
          with no confirmed host-port location yet are skipped entirely —
          NEVER blocked network-wide; they'll get caught once a host-port
          sighting for them arrives in a later cycle.
        - PER_SOURCE_MITIGATION_DOMAINS sources that are ALSO per-source
          mitigation levers (mobile UEs, BNG subscriber sessions):
          no destination-wide network lever the way an OpenFlow drop rule
          is, so a "*" src_ip can't be dispatched as a single action as
          OpenFlow can — one action per contributing source instead, each
          quarantined individually through the existing per-source
          block/unblock machinery.
        - bgp sources: despite also being a PER_SOURCE_MITIGATION_DOMAINS
          member (for its single-source dispatch path and its offered-load
          release hysteresis), a FlowSpec discard route IS a destination-
          wide lever like OpenFlow's — one aggregate action, src_ip="*",
          never one per source. Confirmed necessary, not just tidier: one
          action per (spoofed, virtually-unique-per-packet) source under
          real DDoS testing produced thousands of redundant dispatches
          for what should have been a single route.

        A detection whose OWN live sources are all one domain still gets
        relabeled MULTIDOMAIN_DISTRIBUTED_ATTACK if another domain
        already has an active mitigation against this SAME destination
        (see _active_domains_for) -- correlation/detection only ever see
        ONE cycle's live telemetry, and a domain that's already blocked
        produces none at all (that's the point of blocking it), so two
        domains attacking the same target minutes apart, one still under
        an active block when the other starts, would otherwise never
        share a correlation window and never combine. Matched on dst_ip
        alone, not the full 4-tuple -- a coordinated attack can use a
        different protocol per domain (enterprise SYN, mobile ICMP,
        etc.), which a narrower match would miss entirely.
        """
        actions: List[MitigationAction] = []
        seen_domains = set()

        for d in detections:

            if d.domain in seen_domains:
                continue

            seen_domains.add(d.domain)

            contributing_domains = set(d.source_domains.values()) if d.source_domains else {d.domain}
            already_active_domains = self._active_domains_for(d.dst_ip) - contributing_domains
            effective_attack_type = (
                "MULTIDOMAIN_DISTRIBUTED_ATTACK" if already_active_domains else decision.attack_type
            )

            # When this detection escalates to MULTIDOMAIN, back-fill the
            # attack_type on any earlier blocks for the same dst_ip that were
            # originally labeled with a single-domain type (DDOS_DISTRIBUTED,
            # SYN_FLOOD, etc.) -- those blocks were the first-mover detections
            # that now belong to the same multidomain event. Without this,
            # the UNTHROTTLE logs keep showing the original
            # single-domain label for those blocks even after the escalation.
            if effective_attack_type == "MULTIDOMAIN_DISTRIBUTED_ATTACK":
                for action in self._active_blocks.values():
                    if action.dst_ip == d.dst_ip:
                        action.attack_type = "MULTIDOMAIN_DISTRIBUTED_ATTACK"
                for action in self._active_mobile_blocks.values():
                    if action.dst_ip == d.dst_ip:
                        action.attack_type = "MULTIDOMAIN_DISTRIBUTED_ATTACK"
                self._publish_active_blocks()

            action_type = self._action_for(effective_attack_type, d.domain)

            if (
                effective_attack_type in ("DDOS_DISTRIBUTED", "MULTIDOMAIN_DISTRIBUTED_ATTACK")
                and d.sources
            ):
                # Partition this detection's contributing sources by their
                # OWN real domain (DetectionResult.source_domains) instead
                # of assuming every source shares d.domain -- which is
                # just the representative contributing event's domain,
                # picked by whichever source had the most pps (see
                # detection/engine.py's _build_result/_classify_
                # distributed). correlation/correlator.py already
                # aggregates telemetry across domains toward one dst_ip,
                # so one detection's sources can genuinely span more than
                # one domain (that's exactly what
                # MULTIDOMAIN_DISTRIBUTED_ATTACK means). Routing ALL
                # of them through one domain's mitigation either silently
                # drops the others (enterprise's OpenFlow location lookup
                # never resolves spoofed mobile/BNG sources) or misroutes
                # real enterprise IPs to an adapter that can never resolve
                # them (mobile/broadband's apply_mitigation looks them up
                # in its own IMSI/session table and no-ops).
                sources_by_domain: Dict[str, List[str]] = defaultdict(list)
                for source in d.sources:
                    sources_by_domain[d.source_domains.get(source, d.domain)].append(source)

                for src_domain, sources_subset in sources_by_domain.items():
                    per_domain_action_type = self._action_for(effective_attack_type, src_domain)

                    if src_domain == "enterprise":
                        # Every source IP is first resolved to the
                        # physical HOST port its packets were actually
                        # confirmed entering on (see
                        # _scoped_ingress_for_source -- packet-in-derived
                        # and host-port-filtered, works even for a
                        # spoofed src_ip, since it reflects where the
                        # packet arrived, not an ARP-learned identity a
                        # fake IP could never produce), then grouped by
                        # that location. One action per *distinct
                        # location* -- not per source -- matching only
                        # (in_port, dst_ip, dst_port, protocol), no
                        # src_ip: a real spoofed flood is virtually always
                        # many fake IPs funneled through ONE real attacker
                        # port, so this normally collapses to a single
                        # precise block instead of one rule per fake IP.
                        # Sources with no confirmed host-port location yet
                        # are skipped entirely -- NEVER blocked
                        # network-wide; they'll get caught once a
                        # host-port sighting for them arrives in a later
                        # cycle.
                        by_location: Dict[Tuple[str, int], List[str]] = defaultdict(list)
                        for source in sources_subset:
                            device_id, in_port = self._scoped_ingress_for_source(source, d.dst_ip)
                            if not device_id:
                                continue
                            by_location[(device_id, in_port)].append(source)

                        for (device_id, in_port), sources_at_location in by_location.items():
                            actions.append(MitigationAction(
                                domain=src_domain,
                                device_id=device_id,
                                src_ip="*",
                                dst_ip=d.dst_ip,
                                dst_port=d.dst_port,
                                protocol=d.protocol,
                                action=per_domain_action_type,
                                sources=sources_at_location,
                                attack_type=effective_attack_type,
                                in_port=in_port,
                                pps=d.pps,
                                bps=d.bps,
                            ))

                    elif src_domain == "bgp":
                        # Unlike mobile/broadband (below), a BGP FlowSpec
                        # discard route IS a single (dst_ip, dst_port,
                        # protocol)-scoped network lever, same shape as
                        # OpenFlow's own block -- there's no per-source
                        # concept to quarantine individually (a FlowSpec
                        # route can't discard "just one IP" among spoofed
                        # traffic anyway). Dispatching one action per
                        # contributing source (the old behavior, falling
                        # through to the generic PER_SOURCE_MITIGATION_
                        # DOMAINS branch below) actively broke on the VM
                        # under a real spoofed (--rand-source) DDoS test:
                        # _dispatch()'s own per-source dedup key (src_ip,
                        # dst_ip, dst_port, protocol) never recognized two
                        # cycles' sources as "the same" attacker, since a
                        # virtually-unique src_ip per packet means almost
                        # every source is "new" every single cycle --
                        # confirmed over 7,000 redundant FLOWSPEC_ANNOUNCED
                        # dispatches (up to ~1,500 in one second) for what
                        # should have been ONE route. One aggregate action
                        # instead, src_ip="*" (mirrors OpenFlow's own
                        # DDOS_DISTRIBUTED shape exactly) -- _dispatch()'s
                        # dedup key becomes ("*", dst_ip, dst_port,
                        # protocol), stable across cycles regardless of how
                        # many (or how ephemeral) the contributing sources
                        # are. check_mobile_unblocks() releases it on
                        # offered-load hysteresis (_bgp_offered_load_present),
                        # which also handles src_ip="*".
                        actions.append(MitigationAction(
                            domain=src_domain,
                            device_id=d.device_id,
                            src_ip="*",
                            dst_ip=d.dst_ip,
                            dst_port=d.dst_port,
                            protocol=d.protocol,
                            action=per_domain_action_type,
                            sources=sources_subset,
                            attack_type=effective_attack_type,
                            pps=d.pps,
                            bps=d.bps,
                        ))

                    elif src_domain in settings.PER_SOURCE_MITIGATION_DOMAINS:
                        # domains in PER_SOURCE_MITIGATION_DOMAINS (mobile
                        # UEs, BNG subscriber sessions) have
                        # inherently per-source mitigation -- there's no
                        # destination-wide network lever the way an
                        # OpenFlow drop rule is -- so a "*" src_ip can't
                        # be dispatched as a single action the way it can
                        # for OpenFlow. One action per contributing
                        # source, each quarantined individually through
                        # the existing per-source block/unblock machinery,
                        # which already works correctly per real source
                        # IP (see check_mobile_unblocks). bgp is also a
                        # PER_SOURCE_MITIGATION_DOMAINS member (for the
                        # single-source dispatch path and its
                        # offered-load release, both below/elsewhere) but never reaches this branch -- the
                        # bgp-specific one above always intercepts it
                        # first.
                        for source in sources_subset:
                            actions.append(MitigationAction(
                                domain=src_domain,
                                # This source's OWN gNB/BNG id
                                # (DetectionResult.source_device_ids), not
                                # d.device_id (just one representative
                                # contributing event's) -- contributing
                                # sources can each be attached to a
                                # different gNB,
                                # so using d.device_id for all of them
                                # mislabeled every one except the
                                # representative's with the wrong gNB.
                                device_id=d.source_device_ids.get(source, d.device_id),
                                src_ip=source,
                                dst_ip=d.dst_ip,
                                dst_port=d.dst_port,
                                protocol=d.protocol,
                                action=per_domain_action_type,
                                attack_type=effective_attack_type,
                                pps=d.pps,
                                bps=d.bps,
                            ))

                    else:
                        # No recognized mitigation lever for this domain
                        # (shouldn't happen given how source_domains is
                        # populated today -- every TelemetryEvent.domain
                        # is one of enterprise/mobile/broadband) -- log
                        # and skip, never force it through the wrong
                        # adapter.
                        self._logger.warning(log_line(
                            src_domain, "MITIGATION", "NO_MITIGATION_LEVER",
                            f"sources={sources_subset} destination={d.dst_ip} "
                            f"(unrecognized domain, skipped)",
                        ))
                continue

            if d.domain in settings.PER_SOURCE_MITIGATION_DOMAINS:
                # _scoped_ingress below resolves an OpenFlow switch+port
                # via LearningSwitch's host-location tracking -- not
                # applicable here (neither a mobile UE nor a BNG
                # subscriber session has an OpenFlow ingress port concept).
                # d.device_id is already the real gNB/BNG id for this
                # source (see the per-UE/per-session branch above), which
                # IS what the RIC/BNG control plane would need to locate it.
                device_id, in_port = d.device_id, 0
            else:
                device_id, in_port = self._scoped_ingress(d)

            actions.append(MitigationAction(
                domain=d.domain,
                device_id=device_id,
                src_ip=decision.src_ip,
                dst_ip=d.dst_ip,
                dst_port=d.dst_port,
                protocol=d.protocol,
                action=action_type,
                sources=d.sources,
                attack_type=effective_attack_type,
                in_port=in_port,
                pps=d.pps,
                bps=d.bps,
            ))

        return actions

    def _active_domains_for(self, dst_ip: str) -> Set[str]:
        """
        Every domain currently holding an active mitigation (OpenFlow
        block or per-source throttle/block) against this destination,
        regardless of dst_port/protocol -- a coordinated multidomain
        attack can use a different protocol per domain (enterprise SYN,
        mobile ICMP, ...), and correlation/correlator.py's own grouping
        is per-protocol within one cycle, so a narrower match would miss
        exactly the case this exists to catch. Scans both _active_blocks
        (enterprise) and _active_mobile_blocks (mobile/broadband) --
        every stored MitigationAction already carries its own accurate
        `.domain` and `.dst_ip` (see _dispatch), so this is a plain
        lookup, no new state to maintain.
        """
        domains = {a.domain for a in self._active_blocks.values() if a.dst_ip == dst_ip}
        domains |= {a.domain for a in self._active_mobile_blocks.values() if a.dst_ip == dst_ip}
        return domains

    def _scoped_ingress(self, d: DetectionResult) -> Tuple[str, int]:
        """
        Find the switch+port actually closest to this detection's src_ip,
        via LearningSwitch's confirmed host-location tracking (mac
        sightings filtered to genuine edge ports, never an inter-switch
        hop's view of the same mac) — NOT the detection's own
        device_id/in_port, which just reflects whichever switch's
        packet-in happened to get processed for that traffic. A packet
        with no matching flow rule triggers packet-in on every switch it
        passes through, not just the one nearest the actual source, so
        that telemetry-derived info isn't reliable enough to scope a
        block to a single switch+port — only an authoritative location
        lookup is. No location known yet -> fall back to network-wide.
        """
        if self._locate_host is None:
            return "", 0

        location = self._locate_host(d.src_ip)

        if location is None:
            return "", 0

        dpid, port_no = location
        return str(dpid), port_no

    def _scoped_ingress_for_source(self, src_ip: str, dst_ip: str) -> Tuple[str, int]:
        """
        Like _scoped_ingress, but for one source IP inside a distributed
        attack — uses the packet-in-observed ingress (OpenFlowAdapter.
        get_source_ingress), not ARP-based host location, since a
        spoofed src_ip never ARPs and would never resolve there. Falls
        back to network-wide for that one source if its ingress was
        never captured (e.g. only ever seen via flow-stats aggregation,
        never its own packet-in).
        """
        if self._locate_source_ingress is None:
            return "", 0

        dpid, port_no = self._locate_source_ingress(src_ip, dst_ip)

        if dpid is None:
            return "", 0

        return str(dpid), port_no or 0

    @staticmethod
    def _action_for(attack_type: str, domain: str) -> str:
        """Map attack type + domain to a concrete mitigation action string."""
        if domain == "bgp":
            return "bgp_flowspec_discard"
        if attack_type in (
            "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "DDOS_DISTRIBUTED",
            "MULTIDOMAIN_DISTRIBUTED_ATTACK",
        ):
            return "block"
        return "rate_limit"

    def _dispatch(self, action: MitigationAction) -> bool:
        """
        Send action to the correct backend. Returns True if this is a
        newly-enforced action worth reporting (logging) — False if it's
        just process() re-evaluating an attack that's already blocked,
        which would otherwise re-log every cycle for as long as the
        attack stays active.
        """
        if action.domain == "enterprise":
            is_new = True

            if action.action == "block":
                key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
                is_new = key not in self._active_blocks

                if is_new:
                    # Only set on first block, not every re-evaluation --
                    # the same flow can flip between classifications cycle
                    # to cycle right at the edge of a threshold/entropy
                    # boundary (e.g. SYN_FLOOD one cycle, DDOS_DISTRIBUTED
                    # the next, for the literal same attack). Overwriting _active_blocks[key]
                    # on every re-evaluation made the eventual UNBLOCK
                    # line report whichever attack_type happened to be
                    # classified LAST, not the one that was actually
                    # logged as the block -- confusing when they differ.
                    self._active_blocks[key] = action
                    self._publish_active_blocks()
                    self._below_threshold_streak[key] = 0

            # Install the actual protective rule — cleanup of any stray
            # forwarding/permit rules for this group happens once, after
            # every action in the group is live (see process()), not
            # here: a distributed attack explodes into one action per
            # source, all sharing the same dst_ip/sources list, so
            # cleaning up per-action would redundantly re-scan the flow
            # table once per source instead of once per attack.
            self.of_mitigator.apply(action)

            return is_new

        if action.domain in settings.PER_SOURCE_MITIGATION_DOMAINS and action.action in ("block", "bgp_flowspec_discard"):
            # Mirrors the openflow branch above: dedupe so an attack
            # that's still ongoing doesn't re-queue a fresh mitigation
            # command (and re-log "MITIGATION") every single pipeline
            # cycle — check_mobile_unblocks() is what eventually clears
            # this once the source's reported throughput actually drops
            # (or, for bgp, once its offered load has stayed quiet for
            # PEERING_RELEASE_QUIET_S; for broadband, once its fixed
            # wall-clock window elapses). Shared by every
            # PER_SOURCE_MITIGATION_DOMAINS member (mobile UEs, BNG
            # sessions, bgp FlowSpec routes) -- the dict key carries no
            # domain field, just (src_ip, dst_ip, dst_port, protocol),
            # which is already unambiguous since a given src_ip belongs to
            # exactly one domain in practice. "bgp_flowspec_discard" is
            # bgp's own action string (see _action_for) -- it's still a
            # per-source block in every sense this branch cares about,
            # just not literally named "block".
            key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
            is_new = key not in self._active_mobile_blocks

            if not is_new:
                return False

            # Only set on first throttle, not every re-evaluation -- see
            # the matching comment in the openflow branch above for why
            # (a flow can flip classification cycle to cycle right at a
            # threshold/entropy boundary; overwriting here would make the
            # eventual UNTHROTTLE line report the wrong attack_type).
            self._active_mobile_blocks[key] = action
            self._publish_active_blocks()
            self._mobile_below_threshold_streak[key] = 0
            self._mobile_block_started_at[key] = time.time()
            self._bgp_offered_last_seen[key] = self._mobile_block_started_at[key]
            self._bb_offered_last_seen[key] = self._mobile_block_started_at[key]

            adapter = self._adapters.get(action.domain)
            if adapter:
                adapter.apply_mitigation(action)
            return True

        adapter = self._adapters.get(action.domain)

        if adapter:
            adapter.apply_mitigation(action)
        else:
            self._logger.error(log_line(action.domain, "ORCHESTRATION", "ADAPTER_MISSING"))

        return True

    def _publish_active_blocks(self) -> None:
        """Atomically write the current active blocks (both dicts) to
        settings.ACTIVE_BLOCKS_STATE_PATH as a JSON list, so out-of-process
        readers (analysis/run_vm_lab_trials.py's mitigation_withdrawn probe)
        can tell whether a specific block is still enforced. Best effort:
        a write failure is logged at debug level and never affects
        mitigation."""
        path = settings.ACTIVE_BLOCKS_STATE_PATH
        if not path:
            return
        blocks = [
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "attack_type": action.attack_type,
                "domain": action.domain,
            }
            for store in (self._active_blocks, self._active_mobile_blocks)
            for (src_ip, dst_ip, dst_port, protocol), action in store.items()
        ]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.tmp"
            with open(tmp, "w") as f:
                json.dump(blocks, f)
            os.replace(tmp, path)
        except OSError as exc:
            self._logger.debug(log_line("controller", "ORCHESTRATION", "ACTIVE_BLOCKS_WRITE_FAILED", str(exc)))

    def active_block_counts_by_domain(self) -> Dict[str, int]:
        """Active blocks per domain (both _active_blocks and
        _active_mobile_blocks store MitigationActions that carry their own
        .domain). Only includes domains with at least one block active
        RIGHT NOW. Reported in the experiment audit's per-cycle record."""
        counts: Dict[str, int] = defaultdict(int)
        for action in self._active_blocks.values():
            counts[action.domain] += 1
        for action in self._active_mobile_blocks.values():
            counts[action.domain] += 1
        return dict(counts)

    # ------------------------------------------------------------------
    # Queried by the forwarding layer before caching a new flow
    # ------------------------------------------------------------------

    def is_blocked(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        True if this exact (src_ip, dst_ip, dst_port, protocol) is
        blocked, or a "*" (destination/location-wide) block covers
        (dst_ip, dst_port, protocol) — DDOS_DISTRIBUTED blocks are
        always keyed by src_ip="*" (scoped by physical ingress
        switch+port instead, not by which fake IP a packet claims to be
        from), so it relies on this fallback. LearningSwitch checks this before
        installing a new per-source forwarding rule, so a flow already
        covered by an active block doesn't get a pointless one-shot
        permit entry — the drop rule would win on priority anyway, but
        there's no reason to let the flow table fill up with entries
        that can never deliver traffic.
        """
        if (src_ip, dst_ip, dst_port, protocol) in self._active_blocks:
            return True
        return ("*", dst_ip, dst_port, protocol) in self._active_blocks

    def is_active_block(
        self, src_ip: str, dst_ip: str, dst_port: int, protocol: str,
        sources: "list[str] | None" = None,
    ) -> bool:
        """
        True if this exact (src_ip, dst_ip, dst_port, protocol) already
        has an active block. Used to skip re-logging "ATTACK DETECTED"
        every cycle for an attack that's already known and being
        handled — DDOS_DISTRIBUTED on the openflow domain always carries
        src_ip="*", which directly matches the literal key stored for it
        (one entry per distinct physical ingress location; see
        _build_actions). Also true for an active mobile-domain block
        (_active_mobile_blocks) — same dedup purpose, separate dict
        because its unblock signal is telemetry-presence-based rather
        than openflow drop-rule-counter-based.

        sources: the detection's own per-source UE list, when it has one
        (DetectionResult.sources, populated for mobile-domain
        DDOS_DISTRIBUTED). Those are dispatched as one action per real
        UE IP, not one action keyed by the literal "*" (see _build_
        actions's mobile branch) -- src_ip="*" alone would never match
        any of those per-UE keys, so every still-active multi-source
        mobile attack would otherwise re-log "ATTACK DETECTED" every
        single cycle even while already correctly blocked. Checking any
        one contributing UE's key is enough: they're all dispatched
        together and torn down together.
        """
        key = (src_ip, dst_ip, dst_port, protocol)
        if key in self._active_blocks or key in self._active_mobile_blocks:
            return True
        if sources:
            return any(
                (source, dst_ip, dst_port, protocol) in self._active_mobile_blocks
                for source in sources
            )
        return False

    def is_validated_flow(self, src_ip: str, dst_ip: str) -> bool:
        """
        True once this exact (src_ip, dst_ip) flow has completed at least
        one full detection cycle without src_ip being flagged as part of
        an attack toward dst_ip. LearningSwitch checks this before
        installing *any* flow rule — permit or block — so brand-new
        traffic is always forwarded packet-by-packet (no caching either
        way) until the pipeline has actually evaluated it at least once.

        Scoped per-flow rather than per-destination on purpose — see
        _validated_flows' declaration comment for why a shared destination
        (e.g. this topology's central server) must not drag every OTHER
        source's already-clean traffic back into the unvalidated state
        just because one specific source is under attack.
        """
        return (src_ip, dst_ip) in self._validated_flows

    def validate(self, correlated: List[CorrelatedEvent], detections: List[DetectionResult]) -> None:
        """
        Called once per pipeline cycle, after detection. Any (src_ip,
        dst_ip) flow observed this cycle whose src_ip was NOT part of a
        detection against that dst_ip has now been evaluated and found
        clean — mark it validated so LearningSwitch can start caching
        forwarding rules for it. A flow whose src_ip WAS flagged is left
        unvalidated; it gets blocked instead, and stays unvalidated until
        it's reassessed clean in some future cycle. Every OTHER source
        sharing that same destination is unaffected either way.
        """
        attacking_sources_by_dst: Dict[str, Set[str]] = defaultdict(set)
        for d in detections:
            if d.src_ip and d.src_ip != "*":
                attacking_sources_by_dst[d.dst_ip].add(d.src_ip)
            attacking_sources_by_dst[d.dst_ip].update(d.sources)

        for c in correlated:
            attackers = attacking_sources_by_dst.get(c.dst_ip, ())
            for event in c.events:
                if event.src_ip not in attackers:
                    self._validated_flows.add((event.src_ip, c.dst_ip))

    # ------------------------------------------------------------------
    # Continuous sweep — catches forwarding rules clear_forwarding_rules()
    # missed at block time
    # ------------------------------------------------------------------

    def sweep_blocked_forwarding(self, body) -> None:
        """
        Delete any L3 forwarding rule (priority=FORWARDING_PRIORITY, or its
        SYN twin) whose
        (src_ip, dst_ip) is currently under an active block — either that
        exact source individually or a "*" block carrying the specific
        sources detection flagged (DDOS_DISTRIBUTED's per-location blocks).

        clear_forwarding_rules() at block time only knows the sources the
        detection had already seen by then. Sources that slip in during the
        race window between the attack starting and the block actually
        taking effect — especially one-shot spoofed sources that never get
        a second flow-stats sample — never make it into that list and
        would otherwise sit in the flow table forever (harmless, since the
        drop rule outranks them, but exactly the clutter we want gone).

        Called every flow_stats_reply cycle with the raw OFPFlowStatsReply
        body for one switch, so it sees the table as OVS actually has it,
        not just what detection inferred.
        """
        if not self._active_blocks:
            return

        # For a wildcard ("*") block, scope the sweep to the SPECIFIC
        # sources that detection actually flagged as part of THAT attack
        # (MitigationAction.sources, stored on the block itself) -- not
        # "any src_ip currently talking to a wildcard-blocked dst_ip".
        # Confirmed on a real run: once a destination that's ALSO a
        # legitimate target of ongoing benign traffic (e.g. the star
        # topology's central server, which every benign host's baseline
        # targets) gets a wildcard block, the broader match repeatedly
        # evicted those unrelated benign hosts' own forwarding rules too
        # -- every cycle, since LearningSwitch reinstalls them for
        # traffic that's still genuinely flowing, immediately swept away
        # again next cycle. Beyond the log noise, forcing benign traffic
        # through table-miss/packet-in instead of a fast-path rule can
        # itself inflate that traffic's measured pps enough to look like
        # a fresh attack.
        wildcard_known_sources: Dict[str, Set[str]] = defaultdict(set)
        blocked_pairs = set()
        for (src_ip, dst_ip, _, _), action in self._active_blocks.items():
            if src_ip != "*":
                blocked_pairs.add((src_ip, dst_ip))
            else:
                wildcard_known_sources[dst_ip].update(action.sources)

        if not wildcard_known_sources and not blocked_pairs:
            return

        stale_sources_by_dst: Dict[str, List[str]] = defaultdict(list)

        for stat in body:
            if stat.priority not in (self.of_mitigator.FORWARDING_PRIORITY, self.of_mitigator.SYN_TWIN_PRIORITY):
                continue

            match = stat.match

            if match.get("eth_type") != 0x0800:
                continue

            dst_ip = match.get("ipv4_dst")
            src_ip = match.get("ipv4_src")

            if not src_ip:
                continue

            if (
                src_ip in wildcard_known_sources.get(dst_ip, ())
                or (src_ip, dst_ip) in blocked_pairs
            ):
                stale_sources_by_dst[dst_ip].append(src_ip)

        for dst_ip, sources in stale_sources_by_dst.items():
            self.of_mitigator.clear_forwarding_rules(dst_ip, sources)

    # ------------------------------------------------------------------
    # Continuous measurement of each block's own drop-rule traffic
    # ------------------------------------------------------------------

    def record_block_traffic(self, dpid: int, body) -> None:
        """
        Sample the packet/byte counters of each active block's drop rule
        on this switch and turn the delta since the last sample into a
        pps figure check_unblocks() can use. Called every flow_stats_reply
        cycle, same as sweep_blocked_forwarding().
        """
        if not self._active_blocks:
            return

        now = time.time()

        for stat in body:
            if stat.priority != self.of_mitigator.DROP_PRIORITY:
                continue

            match = stat.match

            for key in self._active_blocks:
                if not self._stat_matches_block(match, key):
                    continue

                sample_key = (key, dpid)
                prev = self._block_traffic_samples.get(sample_key)

                self._block_traffic_samples[sample_key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now,
                }

                if prev is None:
                    break

                dt = now - prev["time"]

                if dt < settings.MIN_FLOW_RATE_DT:
                    break

                packet_delta = stat.packet_count - prev["packets"]

                if packet_delta < 0:
                    break

                self._block_pps[key] = packet_delta / dt
                break

    @staticmethod
    def _stat_matches_block(match, key) -> bool:
        src_ip, dst_ip, dst_port, protocol = key

        if match.get("eth_type") != 0x0800:
            return False
        if match.get("ipv4_dst") != dst_ip:
            return False

        match_src = match.get("ipv4_src")
        if src_ip == "*":
            if match_src:
                return False  # this is some other, source-specific rule
        elif match_src != src_ip:
            return False

        if match.get("ip_proto") != PROTO_NUMBERS.get(protocol):
            return False

        if protocol == "TCP" and match.get("tcp_dst", 0) != dst_port:
            return False
        if protocol == "UDP" and match.get("udp_dst", 0) != dst_port:
            return False

        return True

    def _forget_block_traffic(self, key) -> None:
        self._block_pps.pop(key, None)
        for sample_key in [k for k in self._block_traffic_samples if k[0] == key]:
            del self._block_traffic_samples[sample_key]

    # ------------------------------------------------------------------
    # Unblocking — driven by the current volume of each blocked flow
    # ------------------------------------------------------------------

    def check_unblocks(self) -> List[MitigationAction]:
        """
        Re-evaluate every active openflow block. A block is released once
        its drop rule's own pps (see record_block_traffic — telemetry from
        the regular pipeline goes silent for a blocked flow, since its
        packets never reach packet_in again and FlowCollector excludes
        drop-rule entries) has stayed below UNBLOCK_RATIO of the
        triggering threshold for UNBLOCK_CONFIRM_CYCLES consecutive
        cycles — i.e. once the controller no longer "feels" the attack,
        confirmed rather than on a single quiet sample.

        Returns the unblock MitigationActions issued this cycle (empty if
        none) instead of logging them itself — the caller (ryu_controller_2.
        py's _run_pipeline) folds them into the same MITIGATION
        logger line every other domain's actions go through, the same
        pattern check_mobile_unblocks() uses.
        """
        if not self._active_blocks:
            return []

        unblock_actions: List[MitigationAction] = []

        for key in list(self._active_blocks):
            src_ip, dst_ip, dst_port, protocol = key

            pps = self._block_pps.get(key, 0.0)

            if src_ip == "*":
                threshold = settings.DIST_PPS_THRESHOLD
            else:
                threshold = _THRESHOLD_BY_PROTOCOL.get(protocol, settings.UDP_THRESHOLD)

            if pps >= threshold * self.UNBLOCK_RATIO:
                self._below_threshold_streak[key] = 0
                continue

            self._below_threshold_streak[key] += 1

            if self._below_threshold_streak[key] >= self.UNBLOCK_CONFIRM_CYCLES:
                original = self._active_blocks[key]
                attack_type = original.attack_type

                self.of_mitigator.unblock(src_ip, dst_ip, dst_port, protocol)
                unblock_actions.append(MitigationAction(
                    domain="enterprise",
                    device_id="",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    action="unblock",
                    attack_type=attack_type,
                ))

                del self._active_blocks[key]
                self._publish_active_blocks()
                del self._below_threshold_streak[key]
                self._forget_block_traffic(key)
                # Force re-validation: a flow that was just under attack
                # shouldn't get its forwarding rules trusted again without
                # going through at least one more clean cycle. Scoped to
                # exactly the source(s) that were actually blocked -- a
                # wildcard ("*") block has no single real src_ip, so fall
                # back to the concrete attacker list it was built from
                # (MitigationAction.sources) instead. Every OTHER source
                # that shares dst_ip stays validated -- see
                # _validated_flows' declaration comment.
                if src_ip == "*":
                    for attacker in original.sources:
                        self._validated_flows.discard((attacker, dst_ip))
                else:
                    self._validated_flows.discard((src_ip, dst_ip))

        return unblock_actions

    def force_unblock(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        Manually release an active block without waiting for the normal
        traffic-driven unblock cycle. Handles both OpenFlow blocks
        (_active_blocks) and mobile/broadband blocks (_active_mobile_blocks).
        Returns True if a block was found and removed, False otherwise.

        Used by config/baseline.py to clear mitigations. Logged as
        MANUAL_UNBLOCK so it's distinguishable from the automatic path.
        """
        key = (src_ip, dst_ip, dst_port, protocol)

        if key in self._active_blocks:
            original = self._active_blocks[key]
            self.of_mitigator.unblock(src_ip, dst_ip, dst_port, protocol)
            del self._active_blocks[key]
            self._publish_active_blocks()
            self._below_threshold_streak.pop(key, None)
            self._forget_block_traffic(key)
            self._logger.info(log_line(
                original.domain, "MITIGATION", "MANUAL_UNBLOCK",
                f"source={src_ip} destination={dst_ip}:{dst_port}/{protocol} "
                f"attack_type={original.attack_type}",
            ))
            return True

        if key in self._active_mobile_blocks:
            original = self._active_mobile_blocks[key]
            domain = original.domain
            unblock_action = MitigationAction(
                domain=domain,
                device_id=original.device_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                action="unblock",
                attack_type=original.attack_type,
            )
            adapter = self._adapters.get(domain)
            if adapter:
                adapter.apply_mitigation(unblock_action)
            del self._active_mobile_blocks[key]
            self._publish_active_blocks()
            self._mobile_below_threshold_streak.pop(key, None)
            self._mobile_block_started_at.pop(key, None)
            self._bgp_offered_last_seen.pop(key, None)
            self._bb_offered_last_seen.pop(key, None)
            if src_ip == "*":
                for attacker in getattr(original, "sources", []):
                    self._validated_flows.discard((attacker, dst_ip))
            else:
                self._validated_flows.discard((src_ip, dst_ip))
            self._logger.info(log_line(
                domain, "MITIGATION", "MANUAL_UNBLOCK",
                f"source={src_ip} destination={dst_ip}:{dst_port}/{protocol} "
                f"attack_type={original.attack_type}",
            ))
            return True

        return False

    def _bgp_offered_load_present(self, key, bgp_events) -> bool:
        """True if this cycle's bgp telemetry shows the offered load a
        FlowSpec block was installed against still at/above its release
        threshold (UNBLOCK_RATIO x the threshold that triggered it, same
        rule as check_unblocks()). Matches the block's destination,
        protocol (TCP_SYN counts as TCP) and port (0 = any), and -- for a
        per-source block -- its source; a "*" block sums every source
        toward the destination. Not every cycle carries bgp events (see
        settings.PEERING_RELEASE_QUIET_S), so "no events" is simply
        "not present" here; the caller applies the quiet window."""
        src_ip, _dst_ip, dst_port, protocol = key
        pps = 0.0
        for e in bgp_events:
            ev_proto = "TCP" if e.protocol == "TCP_SYN" else e.protocol
            if ev_proto != protocol:
                continue
            if dst_port and e.dst_port != dst_port:
                continue
            if src_ip != "*" and e.src_ip != src_ip:
                continue
            pps += e.pps
        if src_ip == "*":
            threshold = settings.DIST_PPS_THRESHOLD
        else:
            threshold = _THRESHOLD_BY_PROTOCOL.get(protocol, settings.UDP_THRESHOLD)
        return pps >= threshold * self.UNBLOCK_RATIO

    def _broadband_release_wait(self, key, original) -> bool:
        """True while a broadband block must be held. Offered-load
        hysteresis: the subscriber's session is terminated, so accounting
        says nothing; BroadbandAdapter.offered_pps() reports what its MAC
        still sends into bng. The block is released only after that rate has
        stayed below UNBLOCK_RATIO x the triggering threshold for
        BROADBAND_RELEASE_QUIET_S. With no fresh measurement it falls back
        to the block's fixed wall-clock duration -- never to "quiet"."""
        src_ip, _dst_ip, _dst_port, protocol = key
        now = time.time()
        started_at = self._mobile_block_started_at.get(key, now)
        adapter = self._adapters.get("broadband")
        pps = None
        if adapter is not None and src_ip != "*" and hasattr(adapter, "offered_pps"):
            pps = adapter.offered_pps(src_ip, protocol)
        if pps is None:
            return now - started_at < original.duration
        threshold = _THRESHOLD_BY_PROTOCOL.get(protocol, settings.UDP_THRESHOLD)
        if pps >= threshold * self.UNBLOCK_RATIO:
            self._bb_offered_last_seen[key] = now
        last_seen = self._bb_offered_last_seen.setdefault(key, started_at)
        return now - last_seen < settings.BROADBAND_RELEASE_QUIET_S

    def check_mobile_unblocks(self, correlated: List[CorrelatedEvent]) -> List[MitigationAction]:
        """
        Re-evaluate every active per-source block (any
        config.settings.PER_SOURCE_MITIGATION_DOMAINS member -- kept this
        method's original "_mobile" name, see is_mobile_blocked's
        docstring). Unlike openflow's
        check_unblocks(), a successfully-quarantined UE's reported pps
        drops near zero *as soon as the throttle takes effect* — that's
        the mitigation working, not proof the attacker stopped. Using a
        pps-vs-threshold comparison here (the way check_unblocks() does
        for openflow, where a blocked flow's packets genuinely vanish
        from telemetry) would unblock almost immediately every time,
        let 1-2 cycles of full-rate traffic back through while the
        attacker is still active, get re-detected, and re-block — an
        observed block/unblock/reattack oscillation.

        The signal used instead is presence, not rate: a UE still inside
        its attack window keeps reporting telemetry toward the same
        dst_ip even while throttled to near-zero (dst_ip only reverts to
        the UE's normal destination once the attack genuinely stops). So a block
        is only released once this exact (src_ip, dst_ip, protocol) has
        produced *zero* matching telemetry events for UNBLOCK_CONFIRM_
        CYCLES consecutive cycles -- i.e. the UE stopped reporting
        toward that destination entirely, not just reporting less.

        Returns the unblock MitigationActions issued this cycle (empty if
        none) instead of logging them itself — the caller (ryu_controller_2.
        py's _run_pipeline) folds them into the same MITIGATION
        logger line every other domain's actions go through, so mobile
        unblocks read exactly like an openflow one instead of a separate,
        differently-formatted message.
        """
        if not self._active_mobile_blocks:
            return []

        # Keyed by (domain, dst_ip), NOT just dst_ip (item 3 fix,
        # config/settings.py's DETECTION_CROSS_DOMAIN_CORRELATION=False /
        # "isolated detection"): correlator.py's own isolated-mode bucket
        # key is (domain, dst_ip), so correlate() can return SEVERAL
        # CorrelatedEvents sharing the same dst_ip -- one per domain that
        # happens to be under attack toward the same destination. A dict
        # keyed on dst_ip alone collapses those into whichever one
        # iteration happened to visit last, so a block's `c = by_dst.get
        # (dst_ip)` lookup below could silently fetch a DIFFERENT
        # domain's CorrelatedEvent (one with no events for this block's
        # own domain/src_ip at all), making `still_present` see nothing
        # and release the block prematurely while the real attacker is
        # still flooding. Each CorrelatedEvent is registered once per
        # domain in its own `domains` list -- in multidomain mode that
        # list has every contributing domain and every one of them maps
        # back to the SAME CorrelatedEvent, so this is a no-op there.
        by_domain_dst = {
            (domain, c.dst_ip): c for c in correlated for domain in c.domains
        }
        unblock_actions: List[MitigationAction] = []

        for key in list(self._active_mobile_blocks):
            src_ip, dst_ip, dst_port, protocol = key
            original = self._active_mobile_blocks[key]
            domain = original.domain

            # broadband (PRESENCE_BLIND_DOMAINS) can't use the presence
            # signal below at all -- their block (BroadbandAdapter's
            # session-stop) doesn't throttle the source, it cuts it off
            # entirely, so collect() produces literally zero
            # TelemetryEvents for it while blocked. That's
            # indistinguishable from "the attacker stopped" under the
            # presence check, and confirmed on a real run to cause
            # exactly the oscillation that check was originally written
            # to prevent: BLOCK at t, telemetry vanishes (because it's
            # blocked, not because the attack ended), UNBLOCK fires after
            # UNBLOCK_CONFIRM_CYCLES, the still-active attacker
            # immediately gets re-detected and re-blocked. Held for a
            # fixed wall-clock window instead (the block's own `duration`
            # field, no streak/confirm-cycles gate -- elapsed time is
            # already a deliberate, complete signal) -- if the attacker
            # is still flooding once that window ends and gets
            # re-detected, fine, that's a fresh block with its own fresh
            # window, not an instant bounce.
            if domain == "bgp":
                # Offered-load hysteresis -- see settings.PEERING_RELEASE_
                # QUIET_S. The telemetry here is captured BEFORE the
                # FlowSpec drop, so it keeps showing the attack for as long
                # as it lasts even while the block works; the block is
                # released only after the offered load has stayed below
                # the release threshold for the whole quiet window.
                now = time.time()
                c = by_domain_dst.get((domain, dst_ip))
                bgp_events = [e for e in c.events if e.domain == "bgp"] if c is not None else []
                adapter = self._adapters.get(domain)
                if self._bgp_offered_load_present(key, bgp_events):
                    self._bgp_offered_last_seen[key] = now
                elif adapter is not None and not adapter.is_connected():
                    # Telemetry source down: absence of events is not
                    # evidence the attack ended -- keep holding.
                    self._bgp_offered_last_seen[key] = now
                last_seen = self._bgp_offered_last_seen.setdefault(
                    key, self._mobile_block_started_at.get(key, now)
                )
                if now - last_seen < settings.PEERING_RELEASE_QUIET_S:
                    continue
            elif domain == "broadband":
                if self._broadband_release_wait(key, original):
                    continue
            elif domain in settings.PRESENCE_BLIND_DOMAINS:
                started_at = self._mobile_block_started_at.get(key, time.time())
                if time.time() - started_at < original.duration:
                    continue
            else:
                c = by_domain_dst.get((domain, dst_ip))
                # Matches on src_ip alone, not protocol -- neither
                # MobileNetworkAdapter nor BroadbandAdapter's collect()
                # can produce more than one TelemetryEvent per source per
                # cycle (one IMSI/session's single current row), so a
                # src_ip can't be ambiguous between protocols the way an
                # OpenFlow 5-tuple could be. Matching on protocol too
                # caused real false unblocks: the stored key's protocol
                # comes from DetectionResult, which carries either the
                # *normalized* tag (DDoSDetectionEngine._normalize_
                # protocol turns "TCP_SYN" into "TCP" for OpenFlow's
                # benefit), which doesn't equal the real TelemetryEvent.
                # protocol ("TCP_SYN" or whatever the source actually
                # sends), so the comparison always failed and every
                # SYN_FLOOD/DDOS_DISTRIBUTED block unblocked
                # itself after exactly UNBLOCK_CONFIRM_CYCLES regardless
                # of whether the attack was still running.
                still_present = c is not None and any(
                    e.domain == domain and e.src_ip == src_ip for e in c.events
                )

                # Recovery hysteresis (mobile): the recovery signal is the
                # UE's UL throughput, and it must be FLOW-INDEPENDENT. A real
                # E2SM-RC throttle drives the attacker's UL to ~0, which also
                # kills its conntrack flow, so the UE vanishes from c.events
                # entirely -- presence alone would then just wait out
                # UNBLOCK_CONFIRM_CYCLES of absence (and never see the KPM
                # that proves the throttle worked). The bridge keeps
                # reporting this UE's radio KPM every period regardless, and
                # ue_telemetry_api joins it onto the persistent session, so
                # the mobile adapter can hand us the latest UL throughput by
                # src_ip even with no flow. Use that as the authority when
                # available: UL below the recovery threshold == recovered
                # (throttle working / attack stopped), UL at/above it ==
                # still attacking -- both independent of flow presence. Only
                # if no KPM is available at all do we fall back to the pure
                # presence signal (and broadband/bgp, carrying no per-source
                # KPM, always use presence). See
                # settings.MOBILE_KPM_THPUL_RECOVERY_KBPS.
                if domain == "mobile":
                    ue_thp_ul = None
                    adapter = self._adapters.get("mobile")
                    if adapter is not None and hasattr(adapter, "latest_ul_thp_ul"):
                        ue_thp_ul = adapter.latest_ul_thp_ul(src_ip)
                    if ue_thp_ul is None and c is not None:
                        flow_thps = [
                            ev.kpm.get("DRB.UEThpUl")
                            for ev in c.events
                            if ev.domain == "mobile" and ev.src_ip == src_ip
                            and ev.kpm and ev.kpm.get("DRB.UEThpUl") is not None
                        ]
                        if flow_thps:
                            ue_thp_ul = max(flow_thps)
                    if ue_thp_ul is not None:
                        still_present = (
                            ue_thp_ul >= settings.MOBILE_KPM_THPUL_RECOVERY_KBPS
                        )

                if still_present:
                    self._mobile_below_threshold_streak[key] = 0
                    continue

                self._mobile_below_threshold_streak[key] = (
                    self._mobile_below_threshold_streak.get(key, 0) + 1
                )

                if self._mobile_below_threshold_streak[key] < self.UNBLOCK_CONFIRM_CYCLES:
                    continue

            # Reaching here means either the presence-streak gate above
            # already confirmed UNBLOCK_CONFIRM_CYCLES of absence, or
            # (broadband) the fixed wall-clock window / (bgp) the offered-
            # load quiet window already elapsed -- either way, release it now.
            #
            # Carries the original block's attack_type/device_id through
            # so the logger line reads "UNTHROTTLE ... gNB=1
            # ..." instead of a blank attack_type or "gNB=unknown" -- same
            # gNB/BNG the source was throttled on, since releasing it is
            # the same control-plane operation, just in reverse.
            attack_type = original.attack_type

            unblock_action = MitigationAction(
                domain=domain,
                device_id=original.device_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                action="unblock",
                attack_type=attack_type,
            )
            adapter = self._adapters.get(domain)
            if adapter:
                adapter.apply_mitigation(unblock_action)
            unblock_actions.append(unblock_action)

            del self._active_mobile_blocks[key]
            self._publish_active_blocks()
            self._mobile_below_threshold_streak.pop(key, None)
            self._mobile_block_started_at.pop(key, None)
            self._bgp_offered_last_seen.pop(key, None)
            self._bb_offered_last_seen.pop(key, None)
            # Same per-flow re-validation as check_unblocks() -- see
            # _validated_flows' declaration comment. original.sources
            # covers a wildcard block; src_ip alone covers the normal
            # per-source case every PER_SOURCE_MITIGATION_DOMAINS block
            # actually uses.
            if src_ip == "*":
                for attacker in original.sources:
                    self._validated_flows.discard((attacker, dst_ip))
            else:
                self._validated_flows.discard((src_ip, dst_ip))

        return unblock_actions
