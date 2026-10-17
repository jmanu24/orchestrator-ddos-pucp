import math
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from core.models import CorrelatedEvent, DetectionResult, TelemetryEvent
import config.settings as settings


class DDoSDetectionEngine:
    """
    DDoS Detection Engine.

    Receives CorrelatedEvents from the Multidomain Correlation layer and
    classifies them by attack type using per-protocol thresholds defined
    in config/settings.py.

    Attack types detected:
    - SYN_FLOOD        : high TCP PPS toward the same destination
    - UDP_FLOOD        : high UDP PPS toward the same destination
    - ICMP_FLOOD       : high ICMP PPS toward the same destination
    - DDOS_DISTRIBUTED : many distinct (often spoofed) sources, each below the
                         single-source thresholds, jointly flooding one
                         destination with a near-uniform (high-entropy)
                         traffic distribution across source IPs
    - MULTIDOMAIN_DISTRIBUTED_ATTACK : the DDOS_DISTRIBUTED case above,
                         but the contributing sources themselves span more
                         than one network domain (e.g. real enterprise
                         hosts, spoofed mobile UEs, and BNG subscriber
                         sessions all flooding the same destination at
                         once) -- see DetectionResult.source_domains.
                         orchestration/controller.py routes each source
                         through its own domain's real mitigation
                         mechanism for this type, not a single one.

    Confidence is boosted when the same destination is targeted from
    multiple network domains simultaneously (multidomain attack pattern).
    """

    # Confidence multiplier when attack spans more than one domain
    MULTIDOMAIN_BOOST = 1.3

    # Domains with activation hysteresis -> the names of the settings that
    # configure it (looked up at call time). A detection is subject to it
    # only when ALL its contributing sources belong to exactly one of
    # these domains; mobile has its own KPM streak (_mobile_kpm_signal),
    # and anything spanning several domains is reported immediately.
    _ACTIVATION_SETTINGS = {
        "enterprise": ("ENTERPRISE_ACTIVATION_MIN_HITS", "ENTERPRISE_ACTIVATION_WINDOW_S"),
        "bgp": ("PEERING_ACTIVATION_MIN_HITS", "PEERING_ACTIVATION_WINDOW_S"),
        "broadband": ("BROADBAND_ACTIVATION_MIN_HITS", "BROADBAND_ACTIVATION_WINDOW_S"),
        # Mobile SYN floods only (see _activation_domain): other mobile
        # detections are KPM-driven and carry their own streak.
        "mobile_syn": ("MOBILE_SYN_ACTIVATION_MIN_HITS", "MOBILE_SYN_ACTIVATION_WINDOW_S"),
    }

    def __init__(self, clock=time.monotonic):
        # (domain, dst_ip, protocol) -> timestamps of recent cycles in
        # which a single-domain detection was classified toward it. The
        # activation half of the enterprise/bgp hysteresis -- see
        # settings.ENTERPRISE_ACTIVATION_MIN_HITS /
        # PEERING_ACTIVATION_MIN_HITS. Keyed without src_ip or attack_type
        # on purpose: the same flood can flip between SYN_FLOOD and
        # DDOS_DISTRIBUTED, or vary its sources, from one cycle to the next.
        self._clock = clock
        self._activation_hits: Dict[Tuple[str, str, str], List[float]] = {}

        # src_ip -> consecutive cycles a mobile UE has been over the KPM
        # activation thresholds. The activation half of the mitigation
        # hysteresis: a UE is only flagged once this reaches
        # MOBILE_KPM_ACTIVATION_CYCLES, so a single-cycle PRB/throughput
        # spike never throttles a UE. Reset the moment it drops back under.
        self._mobile_kpm_abuse_streak: Dict[str, int] = {}

    def analyze(self, correlated: List[CorrelatedEvent]) -> List[DetectionResult]:
        """
        Analyze a list of CorrelatedEvents and return detected attacks.
        """
        results = []
        now = self._clock()

        for event in correlated:
            detection = self._classify(event)
            if detection and self._activated(detection, now):
                results.append(detection)

        self._expire_hits(now)
        return results

    @classmethod
    def _activation_domain(cls, detection: DetectionResult) -> Optional[str]:
        """The single domain whose activation hysteresis applies to this
        detection, or None (reported immediately) when it spans several
        domains or its domain has none."""
        domains = set(detection.source_domains.values()) if detection.source_domains else {detection.domain}
        if len(domains) != 1:
            return None
        domain = next(iter(domains))
        if domain == "mobile":
            return "mobile_syn" if detection.attack_type == "SYN_FLOOD" else None
        return domain if domain in cls._ACTIVATION_SETTINGS else None

    @classmethod
    def _activation_params(cls, domain: str) -> Tuple[int, float]:
        min_hits_name, window_name = cls._ACTIVATION_SETTINGS[domain]
        return getattr(settings, min_hits_name), getattr(settings, window_name)

    def _activated(self, detection: DetectionResult, now: float) -> bool:
        """Activation hysteresis: records this cycle's hit and reports the
        detection only once the domain's MIN_HITS hits fall inside its
        window. Detections without hysteresis pass through unchanged."""
        domain = self._activation_domain(detection)
        if domain is None:
            return True
        min_hits, window_s = self._activation_params(domain)
        if min_hits <= 1:
            return True

        hits = self._activation_hits.setdefault((domain, detection.dst_ip, detection.protocol), [])
        hits.append(now)
        cutoff = now - window_s
        hits[:] = [t for t in hits if t >= cutoff]
        return len(hits) >= min_hits

    def _expire_hits(self, now: float) -> None:
        """Forget (domain, dst, protocol) entries with no hit inside their
        domain's window."""
        stale = [
            key for key, hits in self._activation_hits.items()
            if not hits or hits[-1] < now - self._activation_params(key[0])[1]
        ]
        for key in stale:
            del self._activation_hits[key]

    # ------------------------------------------------------------------
    # Internal classification logic
    # ------------------------------------------------------------------

    # Per-protocol (attack_type, pps threshold) checked in order. SYN_FLOOD
    # checks "TCP_SYN" specifically (bare SYN, no ACK — a connection
    # attempt) rather than all TCP traffic, so a flood of *completed*
    # connections doesn't get misread as a SYN flood just because it's TCP.
    _PROTOCOL_CHECKS = (
        ("TCP_SYN", "SYN_FLOOD", "SYN_THRESHOLD"),
        ("UDP", "UDP_FLOOD", "UDP_THRESHOLD"),
        ("ICMP", "ICMP_FLOOD", "ICMP_THRESHOLD"),
    )

    def _classify(self, event: CorrelatedEvent) -> Optional[DetectionResult]:
        """
        Classify a single CorrelatedEvent.

        For each protocol whose aggregate pps exceeds its threshold, the
        source-IP distribution decides *how* to classify it — concentrated
        in one/few sources (low entropy) means a single attacker; spread
        evenly across many distinct sources (high entropy) means a
        distributed/spoofed-source flood. This check happens before picking
        an attack_type, so a high aggregate total doesn't get blamed on
        whichever single source happened to have the most pps that cycle.
        """
        for protocol, attack_type, threshold_name in self._PROTOCOL_CHECKS:
            threshold = getattr(settings, threshold_name)

            proto_events = [e for e in event.events if e.protocol == protocol]
            if not proto_events:
                continue
            total_pps = sum(e.pps for e in proto_events)

            # Mobile domain is KPM-driven: the attack signal is the RAN's
            # own UL E2SM-KPM (PRB saturation AND high UL throughput), not
            # conntrack pps -- conntrack only says WHICH flow (this
            # protocol/dst) the UE is on. Every other domain keeps the
            # pps-threshold trigger. non_mobile_pps excludes mobile events
            # so a below-pps-threshold mobile flood (conntrack under-counts
            # over ZMQ) still fires on its KPM alone.
            kpm_attack, kpm_score = self._mobile_kpm_signal(proto_events)
            non_mobile_pps = sum(e.pps for e in proto_events if e.domain != "mobile")

            # Bare SYNs are the exception: mobile TCP_SYN events carry the
            # core-side connection-attempt rate (ue_telemetry_api's NEW
            # conntrack event count -- one bare SYN each, so exact, not an
            # under-count like the flow-list pps), and a SYN flood does not
            # saturate the radio. Measured on the lab: ~900 SYN/s from a UE
            # gave UL 2-3.7 Mbps but PRB 40-43, under MOBILE_KPM_PRB_UL_
            # THRESHOLD (45), so the KPM criterion alone never flags it.
            trigger_pps = total_pps if protocol == "TCP_SYN" else non_mobile_pps

            if trigger_pps <= threshold and not kpm_attack:
                continue

            return self._build_result(
                event, proto_events, total_pps, threshold, attack_type,
                kpm_score=kpm_score if kpm_attack else None,
            )

        # No single protocol's aggregate crossed its threshold — still check
        # the protocol-agnostic case (e.g. raw/no-flag floods tagged "IP").
        return self._classify_distributed(event, event.events, settings.DIST_PPS_THRESHOLD)

    def _mobile_kpm_signal(self, proto_events: List[TelemetryEvent]):
        """
        Mobile (O-RAN) attack signal from the RAN UL E2SM-KPM. A mobile UE
        is flagged only when BOTH its UL PRB usage is near-saturation AND
        its UL throughput is well above normal (AND -- see settings). The
        returned score is the UL-throughput overshoot ratio, so a genuine
        flood scores far above DECISION_THRESHOLD even though conntrack pps
        (which under-counts over ZMQ) would not. Returns (is_attack, score).
        """
        attack = False
        best_score = 0.0
        for e in proto_events:
            if e.domain != "mobile" or not e.kpm:
                continue
            # conntrack picks the carrier flow: only a flow actually
            # carrying volume this cycle is a candidate, so a KPM-flagged
            # UE's incidental low-rate flow on another protocol isn't
            # itself flagged. The attack VERDICT is still the KPM below.
            if e.pps <= settings.MOBILE_KPM_MIN_CARRIER_PPS:
                continue
            prb_ul = e.kpm.get("RRU.PrbUsedUl", 0) or 0
            thp_ul = e.kpm.get("DRB.UEThpUl", 0) or 0
            over_thresholds = (prb_ul >= settings.MOBILE_KPM_PRB_UL_THRESHOLD
                               and thp_ul >= settings.MOBILE_KPM_THPUL_KBPS_THRESHOLD)
            # Activation hysteresis: require N consecutive over-threshold
            # reports for this UE before flagging it, so a one-cycle spike
            # doesn't throttle. Streak is keyed per source and reset the
            # moment the UE drops back under either threshold.
            if over_thresholds:
                streak = self._mobile_kpm_abuse_streak.get(e.src_ip, 0) + 1
                self._mobile_kpm_abuse_streak[e.src_ip] = streak
                if streak >= settings.MOBILE_KPM_ACTIVATION_CYCLES:
                    attack = True
                    best_score = max(best_score,
                                     thp_ul / settings.MOBILE_KPM_THPUL_KBPS_THRESHOLD)
            else:
                self._mobile_kpm_abuse_streak.pop(e.src_ip, None)
        return attack, best_score

    def _build_result(
        self,
        event: CorrelatedEvent,
        proto_events: List[TelemetryEvent],
        total_pps: float,
        threshold: float,
        single_source_attack_type: str,
        kpm_score: Optional[float] = None,
    ) -> DetectionResult:
        """
        Decide, for traffic that already crossed a protocol's threshold,
        whether it's concentrated in one source (single-source flood) or
        spread across many (distributed flood), and build the matching
        DetectionResult.

        kpm_score (mobile only): when set, this detection was triggered by
        the RAN UL KPM, not conntrack pps -- the score comes from the KPM
        overshoot so the decision escalates correctly even though the
        conntrack pps that only identified the flow is low.
        """
        pps_by_src: Dict[str, float] = defaultdict(float)
        for e in proto_events:
            pps_by_src[e.src_ip] += e.pps

        distinct_sources = len(pps_by_src)
        entropy = self._normalized_entropy(pps_by_src.values())

        is_distributed = (
            distinct_sources >= settings.DIST_MIN_SOURCES
            and entropy >= settings.DIST_ENTROPY_THRESHOLD
        )

        score = kpm_score if kpm_score is not None else total_pps / threshold
        total_bps = sum(e.bps for e in proto_events)
        multidomain = len(event.domains) > 1

        if is_distributed:
            # No single attacker to scope a switch/port block to — many
            # sources, so the representative is just domain/protocol/port
            # context, picked from whichever event has the most pps.
            representative = self._pick_representative(proto_events)
            confidence = min(entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)
            # See DetectionResult.source_device_ids -- each contributing
            # source's own device_id (e.g. a mobile UE's real gNB), not
            # the single representative event's.
            source_device_ids = {e.src_ip: e.device_id for e in proto_events}
            # See DetectionResult.source_domains -- each contributing
            # source's own domain, built from the SAME protocol-filtered
            # proto_events pps_by_src already came from (not the coarser
            # event.domains above, which includes unrelated benign
            # traffic from other domains toward the same dst_ip and
            # would misclassify a genuinely single-domain flood).
            source_domains = {e.src_ip: e.domain for e in proto_events}
            distributed_attack_type = (
                "MULTIDOMAIN_DISTRIBUTED_ATTACK" if len(set(source_domains.values())) > 1
                else "DDOS_DISTRIBUTED"
            )
            return DetectionResult(
                domain=representative.domain,
                device_id=representative.device_id,
                src_ip="*",
                dst_ip=event.dst_ip,
                dst_port=representative.dst_port,
                protocol=self._normalize_protocol(representative.protocol),
                attack_type=distributed_attack_type,
                score=score,
                confidence=confidence,
                sources=list(pps_by_src.keys()),
                source_device_ids=source_device_ids,
                source_domains=source_domains,
                pps=total_pps,
                bps=total_bps,
            )

        # Single attacker — narrow down to its own events first, then among
        # those prefer one tagged with a real ingress port (from packet-in)
        # over a flow-stats-derived one (which never carries in_port), so
        # mitigation can scope the block to the switch+port closest to it.
        dominant_src = max(pps_by_src, key=pps_by_src.get)
        dominant_events = [e for e in proto_events if e.src_ip == dominant_src]
        representative = self._pick_representative(dominant_events)

        base_confidence = min(score / 10.0, 1.0)
        confidence = min(base_confidence * (self.MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip=representative.src_ip,
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=self._normalize_protocol(representative.protocol),
            attack_type=single_source_attack_type,
            score=score,
            confidence=confidence,
            in_port=representative.in_port,
            pps=total_pps,
            bps=total_bps,
        )

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        """
        "TCP_SYN" is an internal-only tag distinguishing bare SYN packets
        for SYN_FLOOD matching — mitigation/openflow_mitigator.py's L4
        match builder only knows "TCP"/"UDP"/"ICMP", so it's collapsed
        back to "TCP" before ever leaving the detection engine.
        """
        return "TCP" if protocol == "TCP_SYN" else protocol

    @staticmethod
    def _pick_representative(events: List[TelemetryEvent]) -> TelemetryEvent:
        """
        Prefer an event tagged with a real ingress port (in_port != 0,
        meaning it came from packet-in) over a flow-stats-derived one,
        which never carries in_port. Among the preferred pool, pick the
        highest-pps event.
        """
        tagged = [e for e in events if e.in_port]
        pool = tagged if tagged else events
        return max(pool, key=lambda e: e.pps)

    def _classify_distributed(
        self,
        event: CorrelatedEvent,
        candidate_events: List[TelemetryEvent],
        pps_threshold: float,
    ) -> Optional[DetectionResult]:
        """
        Protocol-agnostic fallback distributed-flood check, used only when
        no single protocol's aggregate pps crossed its own threshold (e.g.
        raw IP traffic with no recognizable L4 protocol).
        """
        total_pps = sum(e.pps for e in candidate_events)

        if total_pps < pps_threshold:
            return None

        pps_by_src: Dict[str, float] = defaultdict(float)
        for e in candidate_events:
            pps_by_src[e.src_ip] += e.pps

        if len(pps_by_src) < settings.DIST_MIN_SOURCES:
            return None

        entropy = self._normalized_entropy(pps_by_src.values())

        if entropy < settings.DIST_ENTROPY_THRESHOLD:
            return None

        score = total_pps / pps_threshold
        total_bps = sum(e.bps for e in candidate_events)

        multidomain = len(event.domains) > 1
        confidence = min(
            entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0),
            1.0
        )

        # No single attacking IP to point at — representative is just used
        # for domain/device/protocol/port context.
        representative: TelemetryEvent = max(candidate_events, key=lambda e: e.pps)
        # See DetectionResult.source_device_ids -- each contributing
        # source's own device_id (e.g. a mobile UE's real gNB), not the
        # single representative event's.
        source_device_ids = {e.src_ip: e.device_id for e in candidate_events}
        # See DetectionResult.source_domains -- built from the same
        # candidate_events pps_by_src came from, not the coarser
        # event.domains (see _build_result's matching comment).
        source_domains = {e.src_ip: e.domain for e in candidate_events}
        distributed_attack_type = (
            "MULTIDOMAIN_DISTRIBUTED_ATTACK" if len(set(source_domains.values())) > 1
            else "DDOS_DISTRIBUTED"
        )

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip="*",
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=self._normalize_protocol(representative.protocol),
            attack_type=distributed_attack_type,
            score=score,
            confidence=confidence,
            sources=list(pps_by_src.keys()),
            source_device_ids=source_device_ids,
            source_domains=source_domains,
            pps=total_pps,
            bps=total_bps,
        )

    @staticmethod
    def _normalized_entropy(weights) -> float:
        """
        Shannon entropy of a weight distribution, normalized to [0, 1] by
        the maximum possible entropy for that number of buckets (uniform
        distribution). 1.0 means traffic is split perfectly evenly across
        all sources; values near 0 mean it's concentrated in a few.
        """
        total = sum(weights)
        if total <= 0:
            return 0.0

        probs = [w / total for w in weights if w > 0]

        if len(probs) <= 1:
            return 0.0

        entropy = -sum(p * math.log2(p) for p in probs)
        max_entropy = math.log2(len(probs))

        return entropy / max_entropy if max_entropy > 0 else 0.0
