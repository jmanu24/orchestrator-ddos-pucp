"""Broadband blocks are released on offered-load hysteresis: only after the
blocked MAC's traffic into bng has stayed below UNBLOCK_RATIO x threshold for
settings.BROADBAND_RELEASE_QUIET_S. Without a measurement it falls back to the
block's fixed duration (never to "quiet")."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import MitigationAction
from orchestration.controller import OrchestrationController

DST = "10.55.0.100"
SRC = "10.20.0.201"
T0 = 9000.0


class FakeBroadbandAdapter:
    domain_name = "broadband"

    def __init__(self):
        self.pps = None
        self.actions = []
        self.asked = []

    def collect(self):
        return []

    def is_connected(self):
        return True

    def offered_pps(self, src_ip, protocol):
        self.asked.append((src_ip, protocol))
        return self.pps

    def apply_mitigation(self, action):
        self.actions.append(action)
        return True


def _block():
    return MitigationAction(domain="broadband", device_id="bng", src_ip=SRC, dst_ip=DST, dst_port=443,
                            protocol="TCP", action="block", attack_type="SYN_FLOOD", duration=60)


class BroadbandReleaseTests(unittest.TestCase):
    def setUp(self):
        self.adapter = FakeBroadbandAdapter()
        self.controller = OrchestrationController(adapters=[self.adapter])
        self.clock = [T0]
        for target, name, value in (
            ("orchestration.controller.time.time", None, None),
        ):
            p = mock.patch(target, lambda: self.clock[0])
            p.start()
            self.addCleanup(p.stop)
        for name, value in (("BROADBAND_RELEASE_QUIET_S", 10.0), ("ACTIVE_BLOCKS_STATE_PATH", "")):
            p = mock.patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)
        action = _block()
        self.assertTrue(self.controller._dispatch(action))
        self.key = (SRC, DST, 443, "TCP")

    def _tick(self, dt=0.5):
        self.clock[0] += dt
        return self.controller.check_mobile_unblocks([])

    def test_still_flooding_keeps_the_block_past_the_fixed_hold(self):
        self.adapter.pps = 900.0
        for _ in range(240):                      # 120s > the 60s duration
            self.assertEqual(self._tick(), [])
        self.assertIn(self.key, self.controller._active_mobile_blocks)

    def test_released_only_after_the_quiet_window(self):
        self.adapter.pps = 900.0
        self._tick()
        self.adapter.pps = 0.0
        for _ in range(19):                       # 9.5s < 10s
            self.assertEqual(self._tick(), [])
        out = []
        for _ in range(2):
            out += self._tick()
        self.assertEqual([a.action for a in out], ["unblock"])
        self.assertNotIn(self.key, self.controller._active_mobile_blocks)
        self.assertEqual(self.adapter.actions[-1].action, "unblock")

    def test_a_burst_inside_the_window_restarts_the_wait(self):
        self.adapter.pps = 0.0
        for _ in range(18):
            self._tick()
        self.adapter.pps = 900.0
        self._tick()
        self.adapter.pps = 0.0
        for _ in range(19):
            self.assertEqual(self._tick(), [])
        self.assertIn(self.key, self.controller._active_mobile_blocks)

    def test_rate_under_half_the_threshold_counts_as_quiet(self):
        self.adapter.pps = settings.SYN_THRESHOLD * 0.4     # < 0.5 x 10 pps
        out = []
        for _ in range(24):
            out += self._tick()
        self.assertEqual(len(out), 1)

    def test_asks_the_adapter_about_the_blocked_source_and_protocol(self):
        self.adapter.pps = 900.0
        self._tick()
        self.assertEqual(self.adapter.asked[-1], (SRC, "TCP"))

    def test_without_a_measurement_it_holds_the_fixed_duration(self):
        self.adapter.pps = None
        for _ in range(100):                      # 50s < 60s
            self.assertEqual(self._tick(), [])
        out = []
        for _ in range(30):                       # crosses 60s
            out += self._tick()
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
