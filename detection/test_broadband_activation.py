"""Broadband activation hysteresis: a single-domain detection is reported only
after BROADBAND_ACTIVATION_MIN_HITS reports (one FreeRADIUS Interim-Update
each) inside BROADBAND_ACTIVATION_WINDOW_S."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine

DST = "10.55.0.100"


class FakeClock:
    now = 1000.0

    def __call__(self):
        return self.now


def _syn_report(src="10.20.0.201", pps=900.0):
    ev = TelemetryEvent(domain="broadband", device_id="bng", src_ip=src, dst_ip=DST,
                        dst_port=443, protocol="TCP_SYN", pps=pps, bps=pps * 480)
    return CorrelatedEvent(dst_ip=DST, total_pps=pps, total_bps=pps * 480,
                           domains=["broadband"], events=[ev])


class BroadbandActivationTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.engine = DDoSDetectionEngine(clock=self.clock)
        for name, value in (("BROADBAND_ACTIVATION_MIN_HITS", 2), ("BROADBAND_ACTIVATION_WINDOW_S", 4.0)):
            p = mock.patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _report(self, correlated, dt):
        self.clock.now += dt
        return self.engine.analyze(correlated)

    def test_one_interim_report_is_not_enough(self):
        self.assertEqual(self._report([_syn_report()], 1.0), [])

    def test_two_consecutive_interims_activate(self):
        self.assertEqual(self._report([_syn_report()], 1.0), [])
        out = self._report([_syn_report()], 1.0)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].domain, "broadband")

    def test_reports_further_apart_than_the_window_do_not_add_up(self):
        self.assertEqual(self._report([_syn_report()], 1.0), [])
        self.assertEqual(self._report([_syn_report()], 10.0), [])

    def test_a_missed_report_in_between_still_activates_within_the_window(self):
        self.assertEqual(self._report([_syn_report()], 1.0), [])
        self.assertEqual(self._report([], 2.0), [])          # no report this time
        self.assertEqual(len(self._report([_syn_report()], 1.0)), 1)

    def test_min_hits_one_disables_the_gate(self):
        with mock.patch.object(settings, "BROADBAND_ACTIVATION_MIN_HITS", 1):
            self.assertEqual(len(self._report([_syn_report()], 1.0)), 1)


if __name__ == "__main__":
    unittest.main()
