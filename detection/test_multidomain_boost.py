"""MULTIDOMAIN_BOOST (and the MULTIDOMAIN_DISTRIBUTED_ATTACK label) must
depend on the domains of the detection's OWN contributing sources
(DetectionResult.source_domains), never on CorrelatedEvent.domains -- the
correlated group's full domain set, which in multidomain-correlation mode
routinely also contains unrelated, benign traffic from the other domains
sharing the same dst_ip. Calls engine._classify() directly to inspect a
single cycle's classification without activation hysteresis in the way.

Also covers DIST_PER_SOURCE_MIN_PPS: a distributed detection's own
`sources` list (what orchestration/controller.py actually quarantines per
source) must exclude a contributing source whose individual pps never
cleared that floor, even though it's still counted toward the aggregate
pps/entropy that triggered the detection -- except mobile sources, which
are always kept regardless (conntrack under-counts a UE's real rate over
ZMQ, see _blockable_sources's own docstring)."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine

DST = "10.55.0.100"


def _event(domain, src_ip, protocol, pps, device_id="1", kpm=None):
    return TelemetryEvent(domain=domain, device_id=device_id, src_ip=src_ip, dst_ip=DST,
                          dst_port=53, protocol=protocol, pps=pps, bps=pps * 100,
                          kpm=kpm or {})


def _correlated(events, domains):
    return CorrelatedEvent(dst_ip=DST, total_pps=sum(e.pps for e in events),
                           total_bps=0, domains=domains, events=events)


class SingleSourceBoostTests(unittest.TestCase):
    """A single-source detection is, by construction, attributed to
    exactly one domain -- it must never get MULTIDOMAIN_BOOST, regardless
    of what else CorrelatedEvent.domains lists."""

    def setUp(self):
        self.engine = DDoSDetectionEngine()

    def test_unboosted_even_when_the_group_also_has_another_domains_benign_traffic(self):
        # Enterprise UDP flood well past UDP_THRESHOLD (200): 600pps -> score 3.0.
        attacker = _event("enterprise", "10.70.0.11", "UDP", 43546.92)
        # Benign mobile SYN traffic toward the SAME dst_ip, same cycle, far
        # below SYN_THRESHOLD (10) -- never itself a detection, but its mere
        # presence used to be enough (via CorrelatedEvent.domains) to boost
        # the enterprise detection above.
        benign = _event("mobile", "10.45.1.2", "TCP_SYN", 2.0)
        event = _correlated([attacker, benign], domains=["enterprise", "mobile"])

        detection = self.engine._classify(event)

        self.assertEqual(detection.attack_type, "UDP_FLOOD")
        self.assertEqual(detection.domain, "enterprise")
        self.assertAlmostEqual(detection.confidence, 0.3)  # min(3.0/10, 1.0), no x1.3

    def test_boosted_confidence_would_have_been_different(self):
        # Sanity check the test's own arithmetic: 0.3 * MULTIDOMAIN_BOOST
        # would be a visibly different, wrong number if the bug came back.
        self.assertNotAlmostEqual(0.3 * DDoSDetectionEngine.MULTIDOMAIN_BOOST, 0.3)


class DistributedBoostTests(unittest.TestCase):
    """Distributed detections: the boost and the MULTIDOMAIN_DISTRIBUTED_
    ATTACK label must be the SAME condition (both driven by source_domains),
    never decided separately."""

    def setUp(self):
        self.engine = DDoSDetectionEngine()

    def _five_enterprise_sources(self, pps=3628.9):
        return [_event("enterprise", f"10.70.0.{i}", "UDP", pps) for i in range(1, 6)]

    def test_single_domain_distributed_attack_is_not_boosted(self):
        # 5 equal enterprise sources, 250pps total (> UDP_THRESHOLD=200),
        # uniform distribution (entropy 1.0) -- a textbook DDOS_DISTRIBUTED,
        # but CorrelatedEvent.domains ALSO lists bgp from unrelated benign
        # traffic elsewhere in the group that never matched "UDP".
        sources = self._five_enterprise_sources()
        benign_bgp = _event("bgp", "10.30.0.2", "ICMP", 1.0)  # different protocol entirely
        event = _correlated(sources + [benign_bgp], domains=["enterprise", "bgp"])

        detection = self.engine._classify(event)

        self.assertEqual(detection.attack_type, "DDOS_DISTRIBUTED")
        self.assertAlmostEqual(detection.confidence, 1.0)  # entropy 1.0, no x1.3 applied
        self.assertEqual(set(detection.source_domains.values()), {"enterprise"})

    def test_genuinely_multidomain_distributed_attack_is_still_boosted(self):
        # Same shape, but this time the sources themselves really do span
        # two domains -- the boost and the label must still fire. pps
        # raised to 100 (not 50) because UDP's trigger excludes mobile's
        # own pps from the threshold check (detection/engine.py's
        # non_mobile_pps -- mobile is KPM-driven, not pps-driven): with
        # only enterprise(200)+broadband(100)=300 counted, it still
        # clears UDP_THRESHOLD (200) even though 2 of the 5 sources here
        # don't count toward that check at all.
        sources = [
            _event("enterprise", "10.70.0.1", "UDP", 7257.82),
            _event("enterprise", "10.70.0.2", "UDP", 7257.82),
            _event("mobile", "10.45.1.2", "UDP", 7257.82),
            _event("mobile", "10.45.1.3", "UDP", 7257.82),
            _event("broadband", "10.20.0.201", "UDP", 7257.82),
        ]
        event = _correlated(sources, domains=["enterprise", "mobile", "broadband"])

        detection = self.engine._classify(event)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.attack_type, "MULTIDOMAIN_DISTRIBUTED_ATTACK")
        self.assertAlmostEqual(detection.confidence,
                               min(1.0 * DDoSDetectionEngine.MULTIDOMAIN_BOOST, 1.0))

    def test_fallback_ip_distributed_path_uses_source_domains_too(self):
        # _classify_distributed (the protocol-agnostic fallback, used when
        # no single protocol's own aggregate crossed its threshold) must
        # apply the identical source_domains-based rule, reading the
        # domains of its own candidate_events (here, all 5 real sources),
        # never CorrelatedEvent.domains (deliberately set to also list
        # "mobile" below, even though no mobile EVENT is actually present
        # -- the only way to prove the code isn't reading that field at
        # all for this decision).
        sources = [_event("enterprise", f"10.70.0.{i}", "IP", 80.0) for i in range(1, 6)]
        event = _correlated(sources, domains=["enterprise", "mobile"])

        detection = self.engine._classify(event)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.attack_type, "DDOS_DISTRIBUTED")
        self.assertAlmostEqual(detection.confidence, 1.0)


class PerSourceMinPpsTests(unittest.TestCase):
    """DIST_PER_SOURCE_MIN_PPS: a contributing source below the floor is
    counted toward the aggregate/entropy that triggers the detection, but
    excluded from the per-source `sources` list mitigation actually acts
    on."""

    def setUp(self):
        self.engine = DDoSDetectionEngine()
        p = mock.patch.object(settings, "DIST_PER_SOURCE_MIN_PPS", 1.0)
        p.start()
        self.addCleanup(p.stop)

    def test_trivial_contributor_is_excluded_from_sources_but_not_from_detection(self):
        sources = [_event("enterprise", f"10.70.0.{i}", "UDP", 3628.9) for i in range(1, 6)]
        trivial = _event("enterprise", "10.70.0.99", "UDP", 0.5)  # below the 1.0pps floor
        event = _correlated(sources + [trivial], domains=["enterprise"])

        detection = self.engine._classify(event)

        self.assertIsNotNone(detection)  # still detected: aggregate/entropy saw all 6
        self.assertNotIn("10.70.0.99", detection.sources)
        self.assertEqual(len(detection.sources), 5)
        # but still resolvable if a caller looks it up (harmless to keep):
        self.assertIn("10.70.0.99", detection.source_domains)

    def test_all_contributors_above_the_floor_are_all_kept(self):
        sources = [_event("enterprise", f"10.70.0.{i}", "UDP", 3628.9) for i in range(1, 6)]
        event = _correlated(sources, domains=["enterprise"])

        detection = self.engine._classify(event)

        self.assertEqual(set(detection.sources), {s.src_ip for s in sources})

    def test_mobile_source_is_never_dropped_by_the_floor(self):
        # Confirmed on a real run (2026-10-18): conntrack under-counts a
        # UE's real send rate over ZMQ badly enough that a genuinely
        # attacking UE's measured pps can land under this floor even
        # while it's a real contributor -- mobile has its own KPM-based
        # activation gate deciding whether it's attacking at all, so the
        # pps floor must never be the thing that drops it from `sources`.
        enterprise_sources = [_event("enterprise", f"10.70.0.{i}", "UDP", 3628.9) for i in range(1, 6)]
        under_reported_ue = _event("mobile", "10.45.1.6", "UDP", 0.3)  # under the 1.0pps floor
        event = _correlated(enterprise_sources + [under_reported_ue], domains=["enterprise", "mobile"])

        detection = self.engine._classify(event)

        self.assertIsNotNone(detection)
        self.assertIn("10.45.1.6", detection.sources)


if __name__ == "__main__":
    unittest.main()
