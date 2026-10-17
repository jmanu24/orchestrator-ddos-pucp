#!/usr/bin/env python3
"""Unit tests for MultidomainCorrelator's cross_domain flag (item 1:
isolated vs. multidomain detection -- see config/settings.py's
DETECTION_CROSS_DOMAIN_CORRELATION for the full rationale)."""

import unittest

from core.models import TelemetryEvent
from correlation.correlator import MultidomainCorrelator


def _event(domain: str, src_ip: str, dst_ip: str = "10.55.0.100") -> TelemetryEvent:
    return TelemetryEvent(domain=domain, device_id="dev", src_ip=src_ip, dst_ip=dst_ip,
                          dst_port=53, protocol="UDP", pps=100.0, bps=8000.0)


class CorrelatorModeTests(unittest.TestCase):
    def test_multidomain_mode_merges_across_domains(self):
        # Default/previous-only behavior: cross_domain=True.
        c = MultidomainCorrelator(cross_domain=True)
        c.ingest([_event("enterprise", "10.70.0.11"), _event("mobile", "10.45.1.2")])
        correlated = c.correlate()
        self.assertEqual(len(correlated), 1)  # one bucket, same dst_ip
        self.assertEqual(set(correlated[0].domains), {"enterprise", "mobile"})

    def test_isolated_mode_never_merges_domains(self):
        c = MultidomainCorrelator(cross_domain=False)
        c.ingest([_event("enterprise", "10.70.0.11"), _event("mobile", "10.45.1.2")])
        correlated = c.correlate()
        self.assertEqual(len(correlated), 2)  # one bucket PER domain, same dst_ip
        for event in correlated:
            self.assertEqual(len(event.domains), 1)

    def test_isolated_mode_does_not_sum_pps_across_domains(self):
        # The multidomain-boost math (detection/engine.py) depends on
        # total_pps already including every contributing domain -- in
        # isolated mode each domain's own total must stay its own.
        c = MultidomainCorrelator(cross_domain=False)
        c.ingest([_event("enterprise", "10.70.0.11"), _event("mobile", "10.45.1.2")])
        correlated = c.correlate()
        for event in correlated:
            self.assertEqual(event.total_pps, 100.0)  # not 200.0

    def test_correlate_clears_the_buffer(self):
        c = MultidomainCorrelator()
        c.ingest([_event("enterprise", "10.70.0.11")])
        c.correlate()
        self.assertEqual(c.correlate(), [])


if __name__ == "__main__":
    unittest.main()
