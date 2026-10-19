"""is_validated_flow()/validate(): pe's own OpenFlow view of mobile/
broadband traffic is always the address AFTER NAT (the BNG for
broadband, the UPF/backbone for mobile) -- 10.91.0.2 / 10.92.0.2, per
telemetry/openflow_adapter.py's own _DISTRIBUTED_NON_ENTERPRISE_SUBNETS
comment -- never the real per-UE/per-subscriber address telemetry
reports and validate() keys _validated_flows by. Before this fix,
is_validated_flow() queried with that post-NAT address could never
match anything in _validated_flows, so LearningSwitch's forwarding rule
for broadband/mobile traffic toward any destination stayed on
PROVISIONAL_TIMEOUT=2s forever instead of ever reaching
VALIDATED_FLOW_HARD_TIMEOUT=30s -- confirmed on a real run (2026-10-19)
causing periodic ConnectionResetError on sustained high-throughput
transfers.

Checked in BOTH directions -- the subscriber/UE-to-victim direction
(src_ip NAT'd) and the victim-to-subscriber/UE direction (dst_ip NAT'd,
the higher-volume one for a download). A first version of this fix only
covered the former and still left downloads resetting every 2s.

Enterprise and peering never cross a NAT boundary before pe (confirmed:
peering's backbone leg keeps the real external peer address unchanged),
so they keep the exact pre-fix behavior throughout."""

import unittest

from core.models import CorrelatedEvent, DetectionResult, MitigationAction, TelemetryEvent
from orchestration.controller import OrchestrationController

DST = "10.55.0.100"
BROADBAND_NAT_ADDR = "10.92.0.2"   # pe's own view of ANY broadband subscriber's traffic
MOBILE_NAT_ADDR = "10.91.0.2"      # pe's own view of ANY mobile UE's traffic
REAL_SUBSCRIBER = "10.20.0.201"
REAL_UE = "10.45.1.2"


def _controller() -> OrchestrationController:
    return OrchestrationController(adapters=[])


def _broadband_event(src_ip=REAL_SUBSCRIBER, dst_ip=DST):
    return TelemetryEvent(domain="broadband", device_id="bng", src_ip=src_ip, dst_ip=dst_ip,
                          dst_port=443, protocol="TCP", pps=1.0, bps=100.0)


def _mobile_event(src_ip=REAL_UE, dst_ip=DST):
    return TelemetryEvent(domain="mobile", device_id="402", src_ip=src_ip, dst_ip=dst_ip,
                          dst_port=9999, protocol="UDP", pps=1.0, bps=100.0)


class NatBackboneValidationTests(unittest.TestCase):
    def test_brand_new_nat_flow_is_not_blindly_trusted(self):
        """Never evaluated at all yet -- must behave exactly like any
        other brand-new flow (PROVISIONAL_TIMEOUT), not pre-validated."""
        controller = _controller()
        self.assertFalse(controller.is_validated_flow(BROADBAND_NAT_ADDR, DST))
        self.assertFalse(controller.is_validated_flow(MOBILE_NAT_ADDR, DST))

    def test_clean_cycle_validates_the_nat_backbone_address_too(self):
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["broadband"], events=[_broadband_event()])]
        controller.validate(correlated, detections=[])

        # The real pre-NAT address is still what _validated_flows itself
        # stores (unchanged, regression check)...
        self.assertTrue(controller.is_validated_flow(REAL_SUBSCRIBER, DST))
        # ...but pe never sees that address -- it sees the NAT backbone
        # one, which must now ALSO validate.
        self.assertTrue(controller.is_validated_flow(BROADBAND_NAT_ADDR, DST))

    def test_the_reverse_direction_validates_too(self):
        """The victim-to-subscriber direction (e.g. a download's bulk
        data) is queried as (src_ip=victim, dst_ip=NAT backbone address)
        -- the NAT'd address on the OTHER side of the tuple from the
        forward-direction case above. A fix that only handled src_ip
        being NAT'd would still leave this direction's rule stuck on
        PROVISIONAL_TIMEOUT."""
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["broadband"], events=[_broadband_event()])]
        controller.validate(correlated, detections=[])

        self.assertTrue(controller.is_validated_flow(DST, BROADBAND_NAT_ADDR))

    def test_reverse_direction_also_respects_an_active_block(self):
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["mobile"], events=[_mobile_event()])]
        controller.validate(correlated, detections=[])
        self.assertTrue(controller.is_validated_flow(DST, MOBILE_NAT_ADDR))

        key = (REAL_UE, DST, 9999, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="402", src_ip=REAL_UE, dst_ip=DST,
            dst_port=9999, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )
        self.assertFalse(controller.is_validated_flow(DST, MOBILE_NAT_ADDR))

    def test_an_active_block_on_any_real_source_keeps_the_aggregate_unvalidated(self):
        """Even after the domain has been evaluated once (so the "seen"
        gate alone would pass), a currently-active block on ANY real
        subscriber/UE of that domain toward this dst must keep the WHOLE
        NAT backbone address unvalidated -- the fix must never create a
        mitigation blind spot."""
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["broadband"], events=[_broadband_event("10.20.0.202")])]
        controller.validate(correlated, detections=[])
        self.assertTrue(controller.is_validated_flow(BROADBAND_NAT_ADDR, DST))

        # A DIFFERENT subscriber of the same domain is currently blocked
        # toward the same destination.
        key = (REAL_SUBSCRIBER, DST, 443, "TCP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="broadband", device_id="bng", src_ip=REAL_SUBSCRIBER, dst_ip=DST,
            dst_port=443, protocol="TCP", action="block", duration=60,
            attack_type="SYN_FLOOD",
        )

        self.assertFalse(controller.is_validated_flow(BROADBAND_NAT_ADDR, DST))
        # The other, still-clean subscriber's own exact flow is unaffected.
        self.assertTrue(controller.is_validated_flow("10.20.0.202", DST))

    def test_aggregate_revalidates_once_the_block_clears(self):
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["mobile"], events=[_mobile_event()])]
        controller.validate(correlated, detections=[])

        key = (REAL_UE, DST, 9999, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="402", src_ip=REAL_UE, dst_ip=DST,
            dst_port=9999, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )
        self.assertFalse(controller.is_validated_flow(MOBILE_NAT_ADDR, DST))

        del controller._active_mobile_blocks[key]
        self.assertTrue(controller.is_validated_flow(MOBILE_NAT_ADDR, DST))

    def test_a_different_domains_block_does_not_poison_this_one(self):
        """An active mobile block must never affect broadband's own NAT
        backbone validation toward the same dst, and vice versa."""
        controller = _controller()
        correlated = [CorrelatedEvent(dst_ip=DST, total_pps=1.0, total_bps=100.0,
                                      domains=["broadband"], events=[_broadband_event()])]
        controller.validate(correlated, detections=[])

        key = (REAL_UE, DST, 9999, "UDP")
        controller._active_mobile_blocks[key] = MitigationAction(
            domain="mobile", device_id="402", src_ip=REAL_UE, dst_ip=DST,
            dst_port=9999, protocol="UDP", action="rate_limit", duration=60,
            attack_type="UDP_FLOOD",
        )

        self.assertTrue(controller.is_validated_flow(BROADBAND_NAT_ADDR, DST))

    def test_enterprise_and_peering_addresses_never_hit_the_nat_fallback(self):
        """Neither domain crosses a NAT boundary before pe -- an
        unvalidated exact address for them must stay unvalidated, not
        accidentally match the broadband/mobile backbone fallback."""
        controller = _controller()
        self.assertFalse(controller.is_validated_flow("10.70.0.11", DST))   # enterprise
        self.assertFalse(controller.is_validated_flow("10.30.0.2", DST))    # peering, real ext. peer


if __name__ == "__main__":
    unittest.main()
