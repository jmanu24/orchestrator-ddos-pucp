"""BroadbandAdapter.apply_mitigation() resolves action.src_ip to the
subscriber's MAC (the only place that mapping lives -- MitigationAction
only ever carries the IP DDoSDetectionEngine classified) and hands a
resolved copy of the action to mitigation/broadband_mitigator.py's
BngMitigator. The actual accel-cmd/FreeRADIUS/kick plumbing is tested in
isolation in mitigation/test_broadband_mitigator.py; this file only
covers the resolve-then-delegate half. Needs eventlet (venv)."""

import unittest
from unittest import mock

from core.models import MitigationAction
from telemetry.broadband_adapter import BroadbandAdapter

IP = "10.20.0.41"
MAC = "02:00:00:00:00:07"


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.mitigator = mock.Mock()
        self.mitigator.apply.return_value = True
        self.adapter = BroadbandAdapter(mitigator=self.mitigator)

    def _action(self, action="block"):
        return MitigationAction(domain="broadband", device_id="bng", src_ip=IP,
                                 dst_ip="10.55.0.100", dst_port=80, protocol="TCP",
                                 action=action, attack_type="UDP_FLOOD")

    def test_resolved_mac_is_attached_before_delegating(self):
        self.adapter._mac_by_ip[IP] = MAC
        self.assertTrue(self.adapter.apply_mitigation(self._action()))
        (sent_action,), _ = self.mitigator.apply.call_args
        self.assertEqual(sent_action.mac, MAC)
        self.assertEqual(sent_action.src_ip, IP)  # untouched otherwise

    def test_unresolved_mac_is_passed_through_as_empty_not_skipped(self):
        # No mapping learned yet for this src_ip -- BngMitigator still
        # gets called (it can terminate the session by IP alone), just
        # with mac="", never None (see MitigationAction's own docstring).
        self.assertTrue(self.adapter.apply_mitigation(self._action()))
        (sent_action,), _ = self.mitigator.apply.call_args
        self.assertEqual(sent_action.mac, "")

    def test_delegation_result_is_returned_as_is(self):
        self.adapter._mac_by_ip[IP] = MAC
        self.mitigator.apply.return_value = False
        self.assertFalse(self.adapter.apply_mitigation(self._action("unblock")))


if __name__ == "__main__":
    unittest.main()
