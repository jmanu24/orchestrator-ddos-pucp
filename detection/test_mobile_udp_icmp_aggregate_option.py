"""D4-B (thesis attack-plan regeneration, 2026-10-20): the PREPARED,
NOT-APPLIED MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE option. Proves both
behaviors: default (false) is byte-identical to before this flag
existed; true widens UDP/ICMP's trigger_pps to include mobile, on top
of (never instead of) the existing KPM-based mobile signal."""
import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine, observed_benign_rates

DST = "10.55.0.100"


def _event(domain, protocol, pps, src="10.70.0.11"):
    return TelemetryEvent(domain=domain, device_id="1", src_ip=src, dst_ip=DST,
                           dst_port=53, protocol=protocol, pps=pps, bps=pps * 100)


def _correlated(events, domains):
    return CorrelatedEvent(dst_ip=DST, total_pps=sum(e.pps for e in events),
                            total_bps=sum(e.bps for e in events), domains=domains, events=events)


class MobileAggregateOptionTests(unittest.TestCase):
    def test_default_is_false_and_unchanged_from_prior_behavior(self):
        self.assertFalse(settings.MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE)
        events = [_event("enterprise", "UDP", 40.0), _event("mobile", "UDP", 500.0, src="10.60.0.5")]
        correlated = _correlated(events, ["enterprise", "mobile"])
        udp = observed_benign_rates([correlated])[0]["protocols"]["UDP"]
        self.assertEqual(udp["trigger_pps"], 40.0)  # mobile excluded, same as before this flag

    @mock.patch.object(settings, "MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE", True)
    def test_enabled_includes_mobile_in_udp_trigger_pps(self):
        events = [_event("enterprise", "UDP", 40.0), _event("mobile", "UDP", 500.0, src="10.60.0.5")]
        correlated = _correlated(events, ["enterprise", "mobile"])
        udp = observed_benign_rates([correlated])[0]["protocols"]["UDP"]
        self.assertEqual(udp["trigger_pps"], 540.0)  # total_pps now, mobile included

    @mock.patch.object(settings, "MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE", True)
    def test_enabled_includes_mobile_in_icmp_trigger_pps_too(self):
        events = [_event("fixed", "ICMP", 10.0), _event("mobile", "ICMP", 300.0, src="10.60.0.5")]
        correlated = _correlated(events, ["fixed", "mobile"])
        icmp = observed_benign_rates([correlated])[0]["protocols"]["ICMP"]
        self.assertEqual(icmp["trigger_pps"], 310.0)

    @mock.patch.object(settings, "MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE", True)
    def test_tcp_syn_already_included_mobile_unaffected_by_the_flag(self):
        events = [_event("enterprise", "TCP_SYN", 10.0), _event("mobile", "TCP_SYN", 900.0, src="10.60.0.5")]
        correlated = _correlated(events, ["enterprise", "mobile"])
        syn = observed_benign_rates([correlated])[0]["protocols"]["TCP_SYN"]
        self.assertEqual(syn["trigger_pps"], 910.0)  # same with the flag on or off

    @mock.patch.object(settings, "MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE", True)
    def test_enabled_can_push_a_below_threshold_udp_group_into_detection(self):
        """The actual behavior change this flag exists for: a UDP group
        that would NOT cross UDP_THRESHOLD on non-mobile pps alone DOES
        cross it once mobile's own pps is added in."""
        events = [_event("fixed", "UDP", settings.UDP_THRESHOLD - 5),
                  _event("mobile", "UDP", 20.0, src="10.60.0.5")]
        correlated = _correlated(events, ["fixed", "mobile"])
        engine = DDoSDetectionEngine()
        with mock.patch.object(engine, "_mobile_kpm_signal", return_value=(False, None)):
            result = engine._classify(correlated)
        self.assertIsNotNone(result)
        self.assertEqual(result.attack_type, "UDP_FLOOD")

    def test_disabled_the_same_group_does_not_cross_the_threshold(self):
        """Same scenario, flag at its default (false): must NOT detect --
        confirms the previous test's detection came from the flag, not
        from some other change."""
        events = [_event("fixed", "UDP", settings.UDP_THRESHOLD - 5),
                  _event("mobile", "UDP", 20.0, src="10.60.0.5")]
        correlated = _correlated(events, ["fixed", "mobile"])
        engine = DDoSDetectionEngine()
        with mock.patch.object(engine, "_mobile_kpm_signal", return_value=(False, None)):
            result = engine._classify(correlated)
        self.assertIsNone(result)

    @mock.patch.object(settings, "MOBILE_INCLUDED_IN_UDP_ICMP_AGGREGATE", True)
    def test_mobile_kpm_signal_still_called_and_can_still_fire_independently(self):
        """The flag only widens the pps-based trigger -- it must never
        replace or skip the existing KPM-based mobile signal."""
        events = [_event("mobile", "UDP", 1.0, src="10.60.0.5")]  # trivially below any pps threshold
        correlated = _correlated(events, ["mobile"])
        engine = DDoSDetectionEngine()
        with mock.patch.object(engine, "_mobile_kpm_signal", return_value=(True, 0.9)) as kpm:
            result = engine._classify(correlated)
        kpm.assert_called_once()
        self.assertIsNotNone(result)  # KPM alone still triggers, flag or no flag


if __name__ == "__main__":
    unittest.main()
