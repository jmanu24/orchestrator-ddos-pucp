"""RCMitigator delivers an already-resolved block/unblock command to the
Near-RT RIC's E2SM-RC actuator (HTTP POST, best-effort) and durably queues
it as JSONL. Pure actuation: action.imsi is always passed in already
resolved here -- see telemetry/test_mobile_mitigation_delegation.py for
the resolve-then-delegate half (telemetry/mobile_adapter.py)."""

import json
import tempfile
import unittest
import urllib.error
from unittest import mock

from core.models import MitigationAction
from mitigation.mobile_mitigator import RCMitigator

IMSI = "001010123456780"


def _action(action="block", imsi=IMSI, duration=60):
    return MitigationAction(domain="mobile", device_id="402", src_ip="10.45.1.7",
                             dst_ip="10.55.0.100", dst_port=9999, protocol="UDP",
                             action=action, attack_type="UDP_FLOOD", duration=duration, imsi=imsi)


class RCMitigatorTests(unittest.TestCase):
    def setUp(self):
        self.queue_file = tempfile.NamedTemporaryFile(mode="r+", suffix=".jsonl", delete=False)
        self.addCleanup(self.queue_file.close)
        self.mitigator = RCMitigator(
            rc_command_queue_path=self.queue_file.name,
            rc_actuator_url="",  # queue-only: no live RIC in these tests
        )

    def _queued_commands(self):
        self.queue_file.seek(0)
        return [json.loads(line) for line in self.queue_file if line.strip()]

    def test_resolved_action_is_queued(self):
        self.assertTrue(self.mitigator.apply(_action()))
        commands = self._queued_commands()
        self.assertEqual(commands, [{
            "imsi": IMSI, "action": "block", "duration": 60, "attack_type": "UDP_FLOOD",
        }])

    def test_unresolved_imsi_is_not_queued(self):
        # Defensive only -- the real caller (MobileNetworkAdapter) never
        # hands over an action with no imsi; see its own apply_mitigation().
        self.assertFalse(self.mitigator.apply(_action(imsi="")))
        self.assertEqual(self._queued_commands(), [])

    def test_unblock_is_queued_with_its_own_action_string(self):
        self.mitigator.apply(_action(action="unblock"))
        self.assertEqual(self._queued_commands()[0]["action"], "unblock")

    def test_actuator_push_failure_does_not_fail_the_mitigation(self):
        mitigator = RCMitigator(
            rc_command_queue_path=self.queue_file.name,
            rc_actuator_url="http://10.10.0.4:8768/rc",
        )
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            self.assertTrue(mitigator.apply(_action()))
        self.assertEqual(len(self._queued_commands()), 1)

    def test_actuator_push_is_skipped_when_no_url_configured(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.mitigator.apply(_action())
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
