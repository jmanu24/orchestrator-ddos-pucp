"""Activation hysteresis: a single-domain enterprise/bgp detection is
reported only after the domain's MIN_HITS cycles within its WINDOW_S
(ENTERPRISE_ACTIVATION_*, PEERING_ACTIVATION_*); mobile and multidomain
detections are immediate."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine

DST = "10.55.0.100"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _enterprise_flood(src="10.70.0.11", pps=900.0):
    ev = TelemetryEvent(domain="enterprise", device_id="1", src_ip=src, dst_ip=DST,
                        dst_port=53, protocol="UDP", pps=pps, bps=pps * 100)
    return CorrelatedEvent(dst_ip=DST, total_pps=pps, total_bps=pps * 100,
                           domains=["enterprise"], events=[ev])


def _bgp_flood(pps=900.0):
    ev = TelemetryEvent(domain="bgp", device_id="r1", src_ip="10.30.0.2", dst_ip=DST,
                        dst_port=53, protocol="UDP", pps=pps, bps=pps * 100)
    return CorrelatedEvent(dst_ip=DST, total_pps=pps, total_bps=pps * 100,
                           domains=["bgp"], events=[ev])


class EnterpriseActivationTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.engine = DDoSDetectionEngine(clock=self.clock)
        for name, value in (("ENTERPRISE_ACTIVATION_MIN_HITS", 3), ("ENTERPRISE_ACTIVATION_WINDOW_S", 3.0)):
            p = mock.patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _cycle(self, correlated, dt=0.5):
        self.clock.advance(dt)
        return self.engine.analyze(correlated)

    def test_single_spike_is_not_reported(self):
        self.assertEqual(self._cycle([_enterprise_flood()]), [])
        self.assertEqual(self._cycle([]), [])
        self.assertEqual(self._cycle([]), [])

    def test_reported_on_third_hit_in_window(self):
        self.assertEqual(self._cycle([_enterprise_flood()]), [])
        self.assertEqual(self._cycle([_enterprise_flood()]), [])
        out = self._cycle([_enterprise_flood()])
        self.assertEqual([d.attack_type for d in out], ["UDP_FLOOD"])

    def test_data_gap_does_not_reset_the_count(self):
        # A flow-stats gap cycle (no detection) between hits is tolerated:
        # this is "k of a window", not "k consecutive".
        self._cycle([_enterprise_flood()])
        self._cycle([])
        self._cycle([_enterprise_flood()])
        out = self._cycle([_enterprise_flood()])
        self.assertEqual(len(out), 1)

    def test_hits_outside_the_window_expire(self):
        self._cycle([_enterprise_flood()])
        self._cycle([_enterprise_flood()])
        out = self._cycle([_enterprise_flood()], dt=5.0)  # older hits aged out
        self.assertEqual(out, [])
        self.assertEqual(len(self._cycle([_enterprise_flood()])), 0)
        self.assertEqual(len(self._cycle([_enterprise_flood()])), 1)

    def test_state_is_forgotten_when_attack_stops(self):
        self._cycle([_enterprise_flood()])
        self._cycle([], dt=10.0)
        self.assertEqual(self.engine._activation_hits, {})

    def test_varying_sources_still_count_toward_the_same_destination(self):
        self._cycle([_enterprise_flood(src="10.70.0.11")])
        self._cycle([_enterprise_flood(src="10.70.0.12")])
        out = self._cycle([_enterprise_flood(src="10.70.0.13")])
        self.assertEqual(len(out), 1)

    def test_domains_do_not_share_hit_counts(self):
        # Same destination/protocol: an enterprise hit must not count
        # toward bgp's activation, and vice versa.
        with mock.patch.object(settings, "PEERING_ACTIVATION_MIN_HITS", 2):
            self._cycle([_enterprise_flood()])
            self._cycle([_enterprise_flood()])
            self.assertEqual(self._cycle([_bgp_flood()]), [])

    def test_multidomain_detection_is_not_delayed(self):
        ev_e = TelemetryEvent(domain="enterprise", device_id="1", src_ip="10.70.0.11", dst_ip=DST,
                              dst_port=53, protocol="UDP", pps=300.0, bps=1)
        ev_b = TelemetryEvent(domain="bgp", device_id="r1", src_ip="10.30.0.2", dst_ip=DST,
                              dst_port=53, protocol="UDP", pps=300.0, bps=1)
        ev_x = [TelemetryEvent(domain=d, device_id="x", src_ip=f"10.9.0.{i}", dst_ip=DST,
                               dst_port=53, protocol="UDP", pps=300.0, bps=1)
                for i, d in enumerate(("enterprise", "bgp", "enterprise", "bgp", "enterprise"))]
        corr = CorrelatedEvent(dst_ip=DST, total_pps=1500.0, total_bps=1,
                               domains=["enterprise", "bgp"], events=ev_x)
        out = self._cycle([corr])
        self.assertEqual([d.attack_type for d in out], ["MULTIDOMAIN_DISTRIBUTED_ATTACK"])

    def test_disabled_when_min_hits_is_one(self):
        with mock.patch.object(settings, "ENTERPRISE_ACTIVATION_MIN_HITS", 1):
            self.assertEqual(len(self._cycle([_enterprise_flood()])), 1)


class PeeringActivationTests(unittest.TestCase):
    """bgp telemetry arrives in bursts (one per nfcapd rotation, ~2s), so
    its hits are bursts: 2 within 6s by default."""

    def setUp(self):
        self.clock = FakeClock()
        self.engine = DDoSDetectionEngine(clock=self.clock)
        for name, value in (("PEERING_ACTIVATION_MIN_HITS", 2), ("PEERING_ACTIVATION_WINDOW_S", 6.0),
                            ("ENTERPRISE_ACTIVATION_MIN_HITS", 3), ("ENTERPRISE_ACTIVATION_WINDOW_S", 3.0)):
            p = mock.patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _cycle(self, correlated, dt=0.5):
        self.clock.advance(dt)
        return self.engine.analyze(correlated)

    def test_single_burst_is_not_reported(self):
        self.assertEqual(self._cycle([_bgp_flood()]), [])
        for _ in range(6):                      # empty cycles between bursts
            self.assertEqual(self._cycle([]), [])

    def test_two_bursts_two_seconds_apart_are_reported(self):
        self.assertEqual(self._cycle([_bgp_flood()]), [])
        for _ in range(3):
            self._cycle([])
        out = self._cycle([_bgp_flood()])        # next nfcapd file, ~2s later
        self.assertEqual([d.domain for d in out], ["bgp"])

    def test_a_skipped_burst_is_tolerated_within_the_window(self):
        self._cycle([_bgp_flood()])
        for _ in range(7):                      # one burst missed (~4s)
            self._cycle([])
        self.assertEqual(len(self._cycle([_bgp_flood()])), 1)

    def test_bursts_further_apart_than_the_window_do_not_add_up(self):
        self._cycle([_bgp_flood()])
        out = self._cycle([_bgp_flood()], dt=7.0)
        self.assertEqual(out, [])

    def test_state_is_forgotten_when_the_flood_stops(self):
        self._cycle([_bgp_flood()])
        self._cycle([], dt=10.0)
        self.assertEqual(self.engine._activation_hits, {})

    def test_enterprise_is_unaffected_by_bgp_parameters(self):
        self.assertEqual(self._cycle([_enterprise_flood()]), [])
        self.assertEqual(self._cycle([_enterprise_flood()]), [])
        self.assertEqual(len(self._cycle([_enterprise_flood()])), 1)

    def test_disabled_when_min_hits_is_one(self):
        with mock.patch.object(settings, "PEERING_ACTIVATION_MIN_HITS", 1):
            self.assertEqual(len(self._cycle([_bgp_flood()])), 1)


if __name__ == "__main__":
    unittest.main()
