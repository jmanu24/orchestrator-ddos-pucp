"""OrchestrationController publishes its active blocks to a JSON file on
every change, so analysis/run_vm_lab_trials.py's mitigation_withdrawn probe
can tell whether a given block is still enforced."""

import json
import os
import tempfile
import unittest
from unittest import mock

import config.settings as settings
from core.models import MitigationAction
from orchestration.controller import OrchestrationController


def _action(src_ip: str) -> MitigationAction:
    return MitigationAction(
        domain="mobile", device_id="gnb1", src_ip=src_ip, dst_ip="10.55.0.100",
        dst_port=53, protocol="UDP", action="block", attack_type="UDP_FLOOD",
    )


class ActiveBlocksPublishTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "sub", "active_blocks.json")
        patcher = mock.patch.object(settings, "ACTIVE_BLOCKS_STATE_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.dir.cleanup)
        self.controller = OrchestrationController(adapters=[])

    def _read(self):
        with open(self.path) as f:
            return json.load(f)

    def test_block_then_manual_unblock_updates_file(self):
        self.assertTrue(self.controller._dispatch(_action("10.45.0.2")))
        blocks = self._read()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(
            (blocks[0]["src_ip"], blocks[0]["dst_ip"], blocks[0]["dst_port"], blocks[0]["protocol"]),
            ("10.45.0.2", "10.55.0.100", 53, "UDP"),
        )

        self.assertTrue(self.controller.force_unblock("10.45.0.2", "10.55.0.100", 53, "UDP"))
        self.assertEqual(self._read(), [])

    def test_unwritable_path_never_breaks_mitigation(self):
        with mock.patch.object(settings, "ACTIVE_BLOCKS_STATE_PATH", "/proc/nope/active_blocks.json"):
            self.assertTrue(self.controller._dispatch(_action("10.45.0.3")))

    def test_empty_path_disables_publishing(self):
        with mock.patch.object(settings, "ACTIVE_BLOCKS_STATE_PATH", ""):
            self.assertTrue(self.controller._dispatch(_action("10.45.0.4")))
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
