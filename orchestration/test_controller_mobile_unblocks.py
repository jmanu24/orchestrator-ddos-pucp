"""Regression test for item 3 (code review): check_mobile_unblocks() used
to key its per-destination lookup by dst_ip alone (`by_dst = {c.dst_ip: c
for c in correlated}`), which silently collapses multiple CorrelatedEvents
sharing a destination into whichever one a dict comprehension visits last.
In isolated-detection mode (config.settings.DETECTION_CROSS_DOMAIN_
CORRELATION=False), correlation/correlator.py's own bucket key is
(domain, dst_ip), so correlate() can legitimately return one
CorrelatedEvent PER DOMAIN that shares the same dst_ip -- exactly the
case this test reproduces.
"""

import unittest

from core.models import CorrelatedEvent, MitigationAction, TelemetryEvent
from orchestration.controller import OrchestrationController


def _controller() -> OrchestrationController:
    return OrchestrationController(adapters=[])


class MobileUnblockIsolatedModeTests(unittest.TestCase):
    def test_multiple_domains_same_dst_does_not_drop_presence(self):
        """Two CorrelatedEvents share dst_ip (isolated-mode shape). The
        active mobile block's own domain/src_ip DOES have a matching
        event, just not in the CorrelatedEvent a dst_ip-only dict would
        have kept last -- still_present must be computed from the
        mobile-domain event regardless of dict insertion order, so the
        block's streak counter resets to 0 (not silently invalidated by
        the collision)."""
        controller = _controller()
        dst_ip = "10.55.0.100"
        mobile_src = "10.45.1.2"
        key = (mobile_src, dst_ip, 0, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="gnb1", src_ip=mobile_src, dst_ip=dst_ip,
            dst_port=0, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )
        # Pre-existing streak > 0, so a regression (streak NOT reset) is
        # observable even if it takes more than one cycle to show up as
        # a wrong unblock.
        controller._mobile_below_threshold_streak[key] = 5

        enterprise_event = TelemetryEvent(
            domain="enterprise", device_id="sw1", src_ip="10.70.0.11",
            dst_ip=dst_ip, dst_port=443, protocol="TCP", pps=500.0, bps=0.0,
        )
        mobile_event = TelemetryEvent(
            domain="mobile", device_id="gnb1", src_ip=mobile_src,
            dst_ip=dst_ip, dst_port=0, protocol="UDP", pps=800.0, bps=0.0,
        )
        correlated = [
            CorrelatedEvent(dst_ip=dst_ip, total_pps=500.0, total_bps=0.0,
                            domains=["enterprise"], events=[enterprise_event]),
            CorrelatedEvent(dst_ip=dst_ip, total_pps=800.0, total_bps=0.0,
                            domains=["mobile"], events=[mobile_event]),
        ]

        unblock_actions = controller.check_mobile_unblocks(correlated)

        self.assertEqual(unblock_actions, [])
        self.assertEqual(controller._mobile_below_threshold_streak[key], 0)
        self.assertIn(key, controller._active_mobile_blocks)

    def test_insertion_order_does_not_matter(self):
        """Same scenario, with the two CorrelatedEvents in the opposite
        order -- a dst_ip-keyed dict would have kept a DIFFERENT one of
        the two depending on iteration order, so this must behave
        identically either way."""
        controller = _controller()
        dst_ip = "10.55.0.100"
        mobile_src = "10.45.1.2"
        key = (mobile_src, dst_ip, 0, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="gnb1", src_ip=mobile_src, dst_ip=dst_ip,
            dst_port=0, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )
        controller._mobile_below_threshold_streak[key] = 5

        enterprise_event = TelemetryEvent(
            domain="enterprise", device_id="sw1", src_ip="10.70.0.11",
            dst_ip=dst_ip, dst_port=443, protocol="TCP", pps=500.0, bps=0.0,
        )
        mobile_event = TelemetryEvent(
            domain="mobile", device_id="gnb1", src_ip=mobile_src,
            dst_ip=dst_ip, dst_port=0, protocol="UDP", pps=800.0, bps=0.0,
        )
        correlated = [
            CorrelatedEvent(dst_ip=dst_ip, total_pps=800.0, total_bps=0.0,
                            domains=["mobile"], events=[mobile_event]),
            CorrelatedEvent(dst_ip=dst_ip, total_pps=500.0, total_bps=0.0,
                            domains=["enterprise"], events=[enterprise_event]),
        ]

        unblock_actions = controller.check_mobile_unblocks(correlated)

        self.assertEqual(unblock_actions, [])
        self.assertEqual(controller._mobile_below_threshold_streak[key], 0)

    def test_mobile_source_genuinely_absent_still_counts_toward_unblock(self):
        """Sanity check the fix didn't disable the real absence path:
        when NO CorrelatedEvent carries the mobile domain at all (the
        attacker really did stop), the streak must still increment."""
        controller = _controller()
        dst_ip = "10.55.0.100"
        mobile_src = "10.45.1.2"
        key = (mobile_src, dst_ip, 0, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="gnb1", src_ip=mobile_src, dst_ip=dst_ip,
            dst_port=0, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )
        controller._mobile_below_threshold_streak[key] = 0

        enterprise_event = TelemetryEvent(
            domain="enterprise", device_id="sw1", src_ip="10.70.0.11",
            dst_ip=dst_ip, dst_port=443, protocol="TCP", pps=500.0, bps=0.0,
        )
        correlated = [
            CorrelatedEvent(dst_ip=dst_ip, total_pps=500.0, total_bps=0.0,
                            domains=["enterprise"], events=[enterprise_event]),
        ]

        controller.check_mobile_unblocks(correlated)

        self.assertEqual(controller._mobile_below_threshold_streak[key], 1)


if __name__ == "__main__":
    unittest.main()
