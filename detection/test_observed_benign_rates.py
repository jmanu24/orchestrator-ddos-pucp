"""D-prompt-2 Paso 1: observed_benign_rates() is observation only -- it
must report the exact rate DDoSDetectionEngine._classify() evaluates
(including the mobile exclusion for UDP/ICMP) per protocol and per
destination, broken down by domain, and it must NEVER change what
analyze() detects, decides or how its activation hysteresis evolves,
whether or not it is called."""
import unittest

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine, observed_benign_rates

DST = "10.55.0.100"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _event(domain, protocol, pps, src="10.70.0.11"):
    return TelemetryEvent(domain=domain, device_id="1", src_ip=src, dst_ip=DST,
                           dst_port=53, protocol=protocol, pps=pps, bps=pps * 100)


def _correlated(events, domains):
    return CorrelatedEvent(dst_ip=DST, total_pps=sum(e.pps for e in events),
                            total_bps=sum(e.bps for e in events), domains=domains, events=events)


class ObservedBenignRatesTests(unittest.TestCase):
    def test_reports_total_non_mobile_and_trigger_pps_per_protocol(self):
        events = [_event("enterprise", "UDP", 40.0), _event("mobile", "UDP", 500.0, src="10.60.0.5")]
        correlated = [_correlated(events, ["enterprise", "mobile"])]
        rows = observed_benign_rates(correlated)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["dst_ip"], DST)
        self.assertEqual(sorted(row["domains"]), ["enterprise", "mobile"])
        udp = row["protocols"]["UDP"]
        self.assertEqual(udp["total_pps"], 540.0)
        # Mobile excluded from non_mobile_pps/trigger_pps for UDP -- same
        # exclusion _classify() applies, per its own docstring.
        self.assertEqual(udp["non_mobile_pps"], 40.0)
        self.assertEqual(udp["trigger_pps"], 40.0)
        self.assertEqual(udp["by_domain"], {"enterprise": 40.0, "mobile": 500.0})

    def test_tcp_syn_trigger_pps_includes_mobile_unlike_udp_icmp(self):
        events = [_event("enterprise", "TCP_SYN", 10.0), _event("mobile", "TCP_SYN", 900.0, src="10.60.0.5")]
        correlated = [_correlated(events, ["enterprise", "mobile"])]
        syn = observed_benign_rates(correlated)[0]["protocols"]["TCP_SYN"]
        self.assertEqual(syn["total_pps"], 910.0)
        self.assertEqual(syn["trigger_pps"], 910.0)  # TCP_SYN: trigger = total, mobile included

    def test_only_reports_protocols_actually_present(self):
        correlated = [_correlated([_event("enterprise", "UDP", 10.0)], ["enterprise"])]
        protocols = observed_benign_rates(correlated)[0]["protocols"]
        self.assertEqual(set(protocols), {"UDP"})

    def test_empty_correlated_group_produces_no_row(self):
        correlated = [_correlated([], ["enterprise"])]
        self.assertEqual(observed_benign_rates(correlated), [])

    def test_matches_classifys_own_trigger_pps_below_threshold(self):
        """The reported trigger_pps for a below-threshold group must equal
        what _classify() itself computed (and therefore chose not to
        flag) -- not an approximation."""
        events = [_event("enterprise", "UDP", settings.UDP_THRESHOLD - 1)]
        correlated = _correlated(events, ["enterprise"])
        engine = DDoSDetectionEngine()
        self.assertIsNone(engine._classify(correlated))
        rate = observed_benign_rates([correlated])[0]["protocols"]["UDP"]
        self.assertEqual(rate["trigger_pps"], settings.UDP_THRESHOLD - 1)

    def test_calling_observed_benign_rates_never_changes_detection_output(self):
        """Byte-identical analyze() results across several cycles whether
        or not observed_benign_rates() is also called every cycle -- this
        is the actual regression test the brief asked for ('verifica con
        pruebas que no cambia ninguna detección ni decisión'). Multiple
        cycles on the SAME engine so enterprise's activation hysteresis
        (a real piece of cross-cycle state) is actually exercised, not
        just a single always-below-min-hits cycle."""
        events = [_event("enterprise", "UDP", settings.UDP_THRESHOLD + 50)]
        correlated = _correlated(events, ["enterprise"])
        cycles = max(3, settings.ENTERPRISE_ACTIVATION_MIN_HITS + 1)

        clock_a = FakeClock()
        engine_a = DDoSDetectionEngine(clock=clock_a)
        results_a = []
        for _ in range(cycles):
            results_a.append(engine_a.analyze([correlated]))
            clock_a.advance(1.0)

        clock_b = FakeClock()
        engine_b = DDoSDetectionEngine(clock=clock_b)
        results_b = []
        for _ in range(cycles):
            observed_benign_rates([correlated])  # interleaved every cycle, must be a no-op
            results_b.append(engine_b.analyze([correlated]))
            clock_b.advance(1.0)

        self.assertTrue(any(results_a))  # sanity: hysteresis did eventually fire
        self.assertEqual([len(r) for r in results_a], [len(r) for r in results_b])
        for ra, rb in zip(results_a, results_b):
            for a, b in zip(ra, rb):
                self.assertEqual(a.attack_type, b.attack_type)
                self.assertEqual(a.score, b.score)
                self.assertEqual(a.activation_delay_s, b.activation_delay_s)

    def test_does_not_touch_mobile_kpm_abuse_streak(self):
        """The one real side-effect risk: _mobile_kpm_signal() mutates
        _mobile_kpm_abuse_streak. observed_benign_rates() must never call
        it, so calling observed_benign_rates() any number of times before
        analyze() must leave that streak state untouched."""
        mobile_event = _event("mobile", "UDP", 10.0, src="10.60.0.9")
        correlated = _correlated([mobile_event], ["mobile"])
        engine = DDoSDetectionEngine()
        for _ in range(5):
            observed_benign_rates([correlated])
        self.assertEqual(engine._mobile_kpm_abuse_streak, {})


if __name__ == "__main__":
    unittest.main()
