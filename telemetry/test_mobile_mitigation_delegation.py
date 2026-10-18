"""MobileNetworkAdapter.apply_mitigation() resolves action.src_ip to the
attacking UE's imsi (the only place that mapping lives -- MitigationAction
only ever carries the IP DDoSDetectionEngine classified) and hands a
resolved copy of the action to mitigation/mobile_mitigator.py's
RCMitigator, or refuses to delegate at all when resolution fails. The
actual RIC push/queue plumbing is tested in isolation in
mitigation/test_mobile_mitigator.py; this file only covers the
resolve-then-delegate half."""

import unittest
from unittest import mock

from core.models import MitigationAction
from telemetry.mobile_adapter import MobileNetworkAdapter

IP = "10.45.1.7"
IMSI = "001010123456793"


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.mitigator = mock.Mock()
        self.mitigator.apply.return_value = True
        self.adapter = MobileNetworkAdapter(mitigator=self.mitigator)

    def _action(self, action="block"):
        return MitigationAction(domain="mobile", device_id="402", src_ip=IP,
                                 dst_ip="10.55.0.100", dst_port=9999, protocol="UDP",
                                 action=action, attack_type="UDP_FLOOD")

    def test_resolved_imsi_is_attached_before_delegating(self):
        self.adapter._imsi_by_ip[IP] = IMSI
        self.assertTrue(self.adapter.apply_mitigation(self._action()))
        (sent_action,), _ = self.mitigator.apply.call_args
        self.assertEqual(sent_action.imsi, IMSI)
        self.assertEqual(sent_action.src_ip, IP)  # untouched otherwise

    def test_unresolved_imsi_never_reaches_the_mitigator(self):
        # Unlike broadband's mac (where terminate-by-IP is still useful
        # with no mac), mobile has no partial action without an imsi --
        # the adapter must refuse to delegate at all.
        self.assertFalse(self.adapter.apply_mitigation(self._action()))
        self.mitigator.apply.assert_not_called()

    def test_delegation_result_is_returned_as_is(self):
        self.adapter._imsi_by_ip[IP] = IMSI
        self.mitigator.apply.return_value = False
        self.assertFalse(self.adapter.apply_mitigation(self._action("unblock")))


if __name__ == "__main__":
    unittest.main()
