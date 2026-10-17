"""Regression test for 2nd review pass, finding 1: a DDOS_DISTRIBUTED/
MULTIDOMAIN_DISTRIBUTED_ATTACK DetectionResult used to produce only ONE
ATTACK_DETECTED log line, under whichever domain _pick_representative()
happened to choose -- even though DetectionResult.source_domains already
carries the real, full per-source domain attribution. analysis/
run_vm_lab_trials.py matches a DETECTION line's own [domain] bracket
against each trial row's own domain, so a Mobile/Peering/Broadband row
could come back with no detection at all despite the architecture
correctly detecting and attributing that domain's own sources.

Run with the venv (this imports controller.ryu_controller_2, which
imports ryu -- the system python3 cannot import ryu at all here):
    source venv/bin/activate && python3 -m unittest controller.test_detection_log_lines
"""

import unittest

from controller.ryu_controller_2 import _detection_log_lines
from core.models import DetectionResult


class DetectionLogLinesTests(unittest.TestCase):
    def test_single_domain_detection_logs_once_under_its_own_domain(self):
        d = DetectionResult(
            domain="enterprise", device_id="1", src_ip="10.70.0.11",
            dst_ip="10.55.0.100", dst_port=443, protocol="TCP",
            attack_type="SYN_FLOOD", score=2.0, confidence=1.0,
        )
        lines = _detection_log_lines(d)
        self.assertEqual(len(lines), 1)
        self.assertIn("[enterprise]", lines[0])
        self.assertIn("ATTACK_DETECTED", lines[0])

    def test_multidomain_distributed_attack_logs_once_per_contributing_domain(self):
        d = DetectionResult(
            domain="enterprise",  # the representative _pick_representative() chose
            device_id="1", src_ip="*", dst_ip="10.55.0.100", dst_port=53,
            protocol="UDP", attack_type="MULTIDOMAIN_DISTRIBUTED_ATTACK",
            score=3.0, confidence=1.0,
            sources=["10.70.0.11", "10.45.1.2", "10.30.0.2"],
            source_domains={
                "10.70.0.11": "enterprise",
                "10.45.1.2": "mobile",
                "10.30.0.2": "bgp",
            },
        )
        lines = _detection_log_lines(d)
        self.assertEqual(len(lines), 3)
        domains_logged = set()
        for line in lines:
            self.assertIn("ATTACK_DETECTED", line)
            self.assertIn("MULTIDOMAIN_DISTRIBUTED_ATTACK", line)
            for domain in ("enterprise", "mobile", "bgp"):
                if f"[{domain}]" in line:
                    domains_logged.add(domain)
        self.assertEqual(domains_logged, {"enterprise", "mobile", "bgp"})

    def test_each_per_domain_line_carries_only_that_domains_own_sources(self):
        d = DetectionResult(
            domain="mobile", device_id="1", src_ip="*", dst_ip="10.55.0.100",
            dst_port=53, protocol="UDP", attack_type="MULTIDOMAIN_DISTRIBUTED_ATTACK",
            score=3.0, confidence=1.0,
            sources=["10.45.1.2", "10.45.1.3", "10.30.0.2"],
            source_domains={
                "10.45.1.2": "mobile",
                "10.45.1.3": "mobile",
                "10.30.0.2": "bgp",
            },
        )
        lines = _detection_log_lines(d)
        mobile_line = next(l for l in lines if "[mobile]" in l)
        bgp_line = next(l for l in lines if "[bgp]" in l)
        self.assertIn("10.45.1.2", mobile_line)
        self.assertIn("10.45.1.3", mobile_line)
        self.assertNotIn("10.30.0.2", mobile_line.split("domain_sources=")[1])
        self.assertIn("10.30.0.2", bgp_line)
        self.assertNotIn("10.45.1.2", bgp_line.split("domain_sources=")[1])


if __name__ == "__main__":
    unittest.main()
