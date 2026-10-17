"""Mobile SYN floods are decided from the core-side connection-attempt rate
(TCP_SYN rows from ue_telemetry_api), not from the radio KPM -- a SYN flood
does not saturate the PRBs (measured: 900 SYN/s gave UL 2-3.7 Mbps but PRB
40-43, under the 45 threshold)."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, TelemetryEvent
from detection.engine import DDoSDetectionEngine

DST = "10.55.0.100"


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


def _ue_event(protocol, pps, src="10.45.1.4", dst_port=443, kpm=None):
    return TelemetryEvent(domain="mobile", device_id="411", src_ip=src, dst_ip=DST, dst_port=dst_port,
                          protocol=protocol, pps=pps, bps=pps * 60, imsi="001010123456790",
                          kpm=kpm if kpm is not None else {"DRB.UEThpUl": 2032.0, "RRU.PrbUsedUl": 40})


def _corr(*events):
    return CorrelatedEvent(dst_ip=DST, total_pps=sum(e.pps for e in events), total_bps=0,
                           domains=["mobile"], events=list(events))


class MobileSynTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.engine = DDoSDetectionEngine(clock=self.clock)
        for name, value in (("MOBILE_SYN_ACTIVATION_MIN_HITS", 3), ("MOBILE_SYN_ACTIVATION_WINDOW_S", 3.0)):
            p = mock.patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)

    def cycle(self, *events, dt=0.5):
        self.clock.now += dt
        return self.engine.analyze([_corr(*events)] if events else [])

    def test_syn_flood_is_detected_from_the_attempt_rate_without_kpm_saturation(self):
        flood = _ue_event("TCP_SYN", 900.0)           # PRB 40 < 45: KPM alone would not flag it
        self.assertEqual(self.cycle(flood), [])        # activation: 3 hits in 3s
        self.assertEqual(self.cycle(flood), [])
        out = self.cycle(flood)
        self.assertEqual([(d.attack_type, d.domain, d.src_ip, d.protocol) for d in out],
                         [("SYN_FLOOD", "mobile", "10.45.1.4", "TCP")])

    def test_a_one_cycle_burst_is_not_reported(self):
        self.assertEqual(self.cycle(_ue_event("TCP_SYN", 900.0)), [])
        self.assertEqual(self.cycle(), [])
        self.assertEqual(self.cycle(), [])

    def test_a_low_attempt_rate_is_not_a_flood(self):
        quiet = _ue_event("TCP_SYN", 4.0)
        for _ in range(6):
            self.assertEqual(self.cycle(quiet), [])

    def test_plain_tcp_rows_do_not_trigger_the_syn_check(self):
        for _ in range(6):
            self.assertEqual(self.cycle(_ue_event("TCP", 900.0)), [])

    def test_udp_floods_still_need_the_kpm_verdict(self):
        udp_no_kpm = _ue_event("UDP", 900.0, kpm={"DRB.UEThpUl": 2032.0, "RRU.PrbUsedUl": 40})
        for _ in range(6):
            self.assertEqual(self.cycle(udp_no_kpm), [])


if __name__ == "__main__":
    unittest.main()
