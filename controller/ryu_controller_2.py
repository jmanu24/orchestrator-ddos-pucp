import time
import logging
from config.baseline import baseline_active

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_link

# force=True re-applies this format even though Ryu's own startup already
# attached handlers to the root logger — without it, basicConfig() would be
# a no-op and every self.logger.* call below would keep printing without a
# timestamp.
logging.basicConfig(
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    force=True,
)

# Forwarding
from forwarding.learning_switch import LearningSwitch

# ── Pipeline layers (Centralized Controller architecture) ──────────────────
# Stage 1 — Telemetry Collection
from telemetry.openflow_adapter import OpenFlowAdapter
from telemetry.mobile_adapter import MobileNetworkAdapter
from telemetry.broadband_adapter import BroadbandAdapter
from telemetry.bgp_adapter import BGPPeeringAdapter

# Stage 2 — Multidomain Correlation
from correlation.correlator import MultidomainCorrelator

# Stage 3 — DDoS Detection Engine
from detection.engine import DDoSDetectionEngine

# Stages 4 + 5 — Decision Engine + Orchestration & Control
from orchestration.controller import OrchestrationController
# ──────────────────────────────────────────────────────────────────────────

import config.settings as settings
from dataclasses import asdict
from core.experiment_audit import emit as audit_emit, thresholds as audit_thresholds
from core.log_format import log_line

# Display verb for the MITIGATION log line, by domain -- the mobile
# domain doesn't block anything on a network path the way an OpenFlow
# drop rule does; MobileNetworkAdapter.apply_mitigation() queues a RAN-
# side throttle (UE quarantined to a near-zero-PRB slice) instead, so
# logging it as "BLOCK"/"UNBLOCK" describes a mechanism this domain
# doesn't actually have. Domains not listed here (openflow, bgp, ...)
# fall back to the action string itself.
_MITIGATION_VERBS = {
    "mobile": {"block": "THROTTLE", "unblock": "UNTHROTTLE"},
}


def _format_mitigation_message(action) -> str:
    """
    OpenFlow's drop rule genuinely is scoped to one flow (src/dst/port/
    protocol), so "source=X destination=Y:Z/W" accurately describes what
    got blocked. The mobile throttle doesn't work that way: it quarantines
    the UE's entire radio link regardless of what it's talking to, so the
    destination it was attacking is irrelevant to *performing* the
    throttle -- it's just what triggered the decision, already reported
    by the ATTACK DETECTED line a few lines up. What an E2SM-RC slice-
    association control actually needs to locate and quarantine the UE
    is its identity and which gNB/E2 node it's attached to (see Option 1
    in the FlexRIC investigation: control_sm_xapp_api() takes a UE id and
    E2 node id, not a destination), plus how long the quarantine should
    last -- so that's what this message reports instead.
    """
    verb = _MITIGATION_VERBS.get(action.domain, {}).get(action.action, action.action.upper())

    if action.domain == "mobile":
        gnb = action.device_id or "unknown"
        # duration only means something for the throttle itself -- the
        # unblock/release action never sets it, so it'd otherwise just
        # leak MitigationAction's dataclass default (60) on every
        # UNTHROTTLE line regardless of how long the real one ran.
        duration_part = f" duration={action.duration}s" if action.action == "block" else ""
        return log_line(
            "mobile", "MITIGATION", verb,
            f"{action.attack_type} UE src_ip={action.src_ip} gNB={gnb}{duration_part}",
        )

    return log_line(
        action.domain, "MITIGATION", verb,
        f"{action.attack_type} source={action.src_ip} "
        f"destination={action.dst_ip}:{action.dst_port}/{action.protocol}",
    )


def _detection_log_lines(d) -> list:
    """One log_line() message PER CONTRIBUTING DOMAIN for DetectionResult
    `d`, not just d.domain (the single "representative" event
    _pick_representative() happened to choose). A DDOS_DISTRIBUTED/
    MULTIDOMAIN_DISTRIBUTED_ATTACK detection's real per-source domain
    attribution already lives in d.source_domains -- confirmed on a real
    review: logging only the representative's domain meant analysis/
    run_vm_lab_trials.py (which matches a DETECTION line's own [domain]
    bracket against each trial row's own domain) could see a Mobile/
    Peering/Broadband row come back with NO detection line at all, even
    though that domain's own sources genuinely were detected -- the line
    was simply never written under that domain's own bracket. A plain
    (non-distributed) detection has no source_domains at all, so this is
    a single-element, unchanged-behavior list for it. Pulled out as a
    pure function (no logger dependency) so it's unit-testable
    without a Ryu runtime."""
    contributing_domains = sorted(set(d.source_domains.values())) if d.source_domains else [d.domain]
    domains_field = ",".join(contributing_domains)
    lines = []
    for domain in contributing_domains:
        domain_sources = (
            ",".join(src for src, sd in d.source_domains.items() if sd == domain)
            if d.source_domains else d.src_ip
        )
        lines.append(log_line(
            domain, "DETECTION", "ATTACK_DETECTED",
            f"{d.attack_type} source={d.src_ip} destination={d.dst_ip}:{d.dst_port}/{d.protocol} "
            f"domains={domains_field} domain_sources={domain_sources}",
        ))
    return lines


class FlowStatsIDS(app_manager.RyuApp):
    """
    Centralized SDN Controller with multidomain DDoS detection.

    This Ryu application is intentionally thin: it owns only the OpenFlow
    protocol interactions (switch features, packet-in, flow/port stats) and
    delegates all business logic to the 5-stage pipeline:

      Telemetry Collection
        └─> Multidomain Correlation
              └─> DDoS Detection Engine
                    └─> Decision Engine
                          └─> Orchestration & Control
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Active datapaths — used to poll flow/port stats
        self.datapaths = {}

        # ── Forwarding ────────────────────────────────────────────────
        # is_blocked/is_validated/is_interswitch_port are resolved lazily
        # (self.orchestrator doesn't exist yet at this point in __init__)
        # so they must stay lambdas, not bound method references.
        self.forwarding = LearningSwitch(
            is_blocked=lambda src_ip, dst_ip, dst_port, proto: self.orchestrator.is_blocked(
                src_ip, dst_ip, dst_port, proto
            ),
            is_validated=lambda src_ip, dst_ip: self.orchestrator.is_validated_flow(src_ip, dst_ip),
            is_interswitch_port=lambda dpid, port: self.orchestrator.is_interswitch_port(dpid, port),
            logger=self.logger,
        )

        # ── Stage 1: Telemetry Collection ────────────────────────────
        self.of_adapter = OpenFlowAdapter(is_host_port=self.forwarding.is_host_port)

        # MobileNetworkAdapter and BroadbandAdapter read the real VM lab
        # (Open5GS/srsRAN telemetry API for mobile, FreeRADIUS accounting
        # on the BNG for broadband -- see each module's docstring).
        # of_adapter IS the Enterprise
        # domain (OpenFlow/SDN over the PE-facing topology) -- there is
        # no separate Enterprise adapter/stub; External Peering (BGP)
        # is instrumented per docs/peering-plan.md.
        self.all_adapters = [
            self.of_adapter,
            MobileNetworkAdapter(logger=self.logger),
            BroadbandAdapter(logger=self.logger),
            BGPPeeringAdapter(logger=self.logger, async_poll=True),
        ]

        # ── Stages 2-5: Correlation → Detection → Decision → Control ─
        # cross_domain toggles "multidomain" (default) vs. "isolated"
        # detection -- see settings.DETECTION_CROSS_DOMAIN_CORRELATION's
        # own comment. A process-start setting (not hot-reloaded):
        # changing it needs a ryu-manager restart.
        self.correlator  = MultidomainCorrelator(
            cross_domain=settings.DETECTION_CROSS_DOMAIN_CORRELATION
        )
        self.detector    = DDoSDetectionEngine()
        self.orchestrator = OrchestrationController(
            self.all_adapters,
            locate_host=self.forwarding.get_host_location,
            locate_source_ingress=self.of_adapter.get_source_ingress,
            yield_fn=lambda: hub.sleep(0),
            logger=self.logger,
        )

        # ── Monitoring loop ───────────────────────────────────────────
        self.monitor_thread = hub.spawn(self._monitor)

        detection_mode = "multidomain" if settings.DETECTION_CROSS_DOMAIN_CORRELATION else "isolated"
        self.logger.info(log_line("controller", "STARTUP", f"DETECTION_MODE={detection_mode}"))
        self.logger.info(log_line("controller", "STARTUP", "READY"))

    # ------------------------------------------------------------------
    # TOPOLOGY
    # ------------------------------------------------------------------

    def _update_topology(self):
        try:
            raw_links = get_link(self, None)

            # Every (dpid, port_no) on either side of a discovered switch-
            # switch link — mitigation must never trust one of these as
            # "the port closest to the attacker": a packet with no
            # matching flow rule triggers packet-in on EVERY switch it
            # passes through, not just the one nearest the source, so the
            # ingress info recorded for an intermediate hop's uplink port
            # is meaningless for scoping a block.
            interswitch_ports = set()
            for lk in raw_links:
                interswitch_ports.add((lk.src.dpid, lk.src.port_no))
                interswitch_ports.add((lk.dst.dpid, lk.dst.port_no))
            self.orchestrator.update_interswitch_ports(interswitch_ports)
        except Exception as e:
            self.logger.error(log_line("controller", "TOPOLOGY", "ERROR", str(e)))

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self._update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        # Forgets this dpid's OpenFlowMitigator datapath -- without this,
        # a disconnected switch's entry lingered forever, and a future
        # block decided to target it (e.g. reusing the same dpid after a
        # switch restart) could resolve to a stale, no-longer-valid
        # datapath handle.
        self.orchestrator.deregister_datapath(ev.switch.dp.id)
        self._update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        self._update_topology()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        self._update_topology()

    # ------------------------------------------------------------------
    # SWITCH FEATURES
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath

        # Install table-miss flow entry
        self.forwarding.switch_features_handler(datapath)

        # Register datapath with the OpenFlow mitigator
        self.orchestrator.register_datapath(datapath)

        self.logger.info(log_line("enterprise", "FORWARDING", "SWITCH_CONNECTED", f"id={datapath.id}"))

    # ------------------------------------------------------------------
    # PACKET IN
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # ── Stage 1: Telemetry Collection (packet-level) ──────────────
        # Classification happens once per cycle in _run_pipeline(); this
        # handler only collects telemetry, it doesn't raise its own alert.
        self.of_adapter.on_packet_in(ev.msg)

        # ── Forwarding ────────────────────────────────────────────────
        self.forwarding.packet_in_handler(ev)

    # ------------------------------------------------------------------
    # MONITOR — periodic pipeline execution
    # ------------------------------------------------------------------

    def _monitor(self):
        while True:
            # Request fresh stats from all connected switches
            for dp in list(self.datapaths.values()):
                try:
                    self._request_flow_stats(dp)
                except Exception as e:
                    self.logger.error(log_line("enterprise", "TELEMETRY", "ERROR", str(e)))

            hub.sleep(settings.COLLECT_INTERVAL)

            # Refresh hosts on the topology graph — switch/link events
            # alone wouldn't pick up a newly-learned host location.
            self._update_topology()

            # Run the full 5-stage pipeline. Wrapped -- confirmed on a
            # real run that an uncaught exception here silently kills
            # this entire hub greenthread: the process stays up (other
            # ryu apps/handlers keep responding), ryu-manager prints
            # nothing visible, and _monitor's while loop simply never
            # iterates again -- no more telemetry collection, detection,
            # or mitigation for any domain, indefinitely, with zero
            # indication anything went wrong. Logged with a full
            # traceback now instead of vanishing.
            try:
                self._run_pipeline()
            except Exception:
                self.logger.exception(log_line("controller", "PIPELINE", "ERROR"))

    def _run_pipeline(self):
        """
        Execute the centralized controller pipeline once per monitoring cycle.

        Stage 1  Telemetry Collection   — drain events from all adapters
        Stage 2  Multidomain Correlation — group by destination IP
        Stage 3  DDoS Detection Engine   — classify attack types
        Stage 4  Decision Engine          — threshold + weighting
        Stage 5  Orchestration & Control  — dispatch mitigation actions
        """
        # Stage 1 — collect from every registered domain adapter (stubs
        # return [] until wired up; MobileNetworkAdapter is real now).
        # Isolated per-adapter so one domain failing (e.g. its CSV not
        # existing yet, or a stub's TODO path) doesn't take down the
        # whole pipeline cycle for every other domain.
        all_events = []
        for adapter in self.all_adapters:
            try:
                all_events.extend(adapter.collect())
            except Exception as e:
                self.logger.error(log_line(adapter.domain_name, "TELEMETRY", "ERROR", str(e)))

        block_counts = self.orchestrator.active_block_counts_by_domain()

        audit_observed={}
        for event in all_events:
            if 0 <= time.time()-event.timestamp <= max(10,2*settings.COLLECT_INTERVAL):
                audit_observed.setdefault(event.domain,set()).add(event.src_ip)
        audit_sources={domain:sorted(sources) for domain,sources in audit_observed.items()}
        # Stage 2 — correlate across domains
        self.correlator.ingest(all_events)
        correlated = self.correlator.correlate()

        # Keep telemetry and forwarding while isolated capacity probes run.
        if settings.LAB_CALIBRATION_MODE or baseline_active(self.orchestrator):
            self.orchestrator.validate(correlated, [])
            audit_emit(self.logger,'cycle',pipeline_active=False,observed_sources=audit_sources,thresholds=audit_thresholds(settings),active_blocks=block_counts)
            return

        # Release blocks whose flow volume has died down — driven by the
        # drop rules' own counters (sampled in flow_stats_reply_handler),
        # not by `correlated`, since a blocked flow's packets never reach
        # this pipeline's telemetry again. Returned (not logged internally)
        # so it goes through the same MITIGATION logger line as
        # every other domain's actions below.
        openflow_unblock_actions = self.orchestrator.check_unblocks()

        # Mobile-domain blocks unblock off this cycle's own telemetry
        # instead (see check_mobile_unblocks's docstring) -- a RAN-side
        # throttle doesn't make the UE's traffic vanish from `correlated`
        # the way an openflow drop rule does. Same return-don't-log
        # convention as openflow_unblock_actions above.
        mobile_unblock_actions = self.orchestrator.check_mobile_unblocks(correlated)

        # Stage 3 — detect attack types.
        # Called every cycle even with nothing correlated, so the detector's
        # activation window keeps ageing.
        detections = self.detector.analyze(correlated)

        # Drop detections for a (src, dst, port, protocol) already under
        # an active block BEFORE they reach validate/process --
        # not just before the log line -- so an attack that's already
        # handled doesn't keep re-logging every cycle.
        detections = [
            d for d in detections
            if not self.orchestrator.is_active_block(d.src_ip, d.dst_ip, d.dst_port, d.protocol, sources=d.sources)
        ]

        # Surface every NEW detection in the event log, classified — this
        # is the descriptive "what's happening" signal.
        for d in detections:
            audit_emit(self.logger,'detection',detection=asdict(d),thresholds=audit_thresholds(settings))

            for msg in _detection_log_lines(d):
                self.logger.warning(msg)

        # Mark destinations seen clean this cycle as validated — only now
        # can LearningSwitch start caching forwarding rules for them. Must
        # run even when there were no detections, so normal traffic still
        # gets validated.
        self.orchestrator.validate(correlated, detections)

        audit_emit(self.logger,'cycle',pipeline_active=True,observed_sources=audit_sources,thresholds=audit_thresholds(settings),active_blocks=block_counts)
        unblock_actions = openflow_unblock_actions + mobile_unblock_actions
        for action in unblock_actions:
            audit_emit(self.logger,'mitigation_release',action=asdict(action))

        # Stages 4 + 5 — decide and orchestrate. A cycle can have no new
        # detections (the attack that triggered a block already stopped)
        # and still have unblocks to report, so the early return only
        # applies when there's neither.
        if not detections and not unblock_actions:
            return

        actions = self.orchestrator.process(detections) if detections else []
        actions += unblock_actions

        # Report mitigations in the log
        for action in actions:
            msg = _format_mitigation_message(action)
            self.logger.warning(msg)

    # ------------------------------------------------------------------
    # FLOW STATS
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        # Clean up forwarding rules left behind for destinations already
        # under an active distributed block — runs every cycle, not just
        # at block time, so stragglers from the detection race window
        # eventually get swept too.
        self.orchestrator.sweep_blocked_forwarding(ev.msg.body)

        # Sample each active block's own drop-rule counters — the only
        # remaining signal of whether an attacker is still flooding a
        # blocked flow, since its packets never reach packet_in again.
        self.orchestrator.record_block_traffic(dpid, ev.msg.body)

        # Stage 1 — push raw stats into the OpenFlow telemetry adapter
        self.of_adapter.on_flow_stats(dpid, ev.msg.body)

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
