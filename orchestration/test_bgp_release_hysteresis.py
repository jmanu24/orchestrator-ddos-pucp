"""bgp FlowSpec blocks are released on offered-load hysteresis: only after
the attack's offered load (seen in pre-drop NetFlow) has stayed below the
release threshold for settings.PEERING_RELEASE_QUIET_S seconds."""

import unittest
from unittest import mock

import config.settings as settings
from core.models import CorrelatedEvent, MitigationAction, TelemetryEvent
from orchestration.controller import OrchestrationController

DST = "10.55.0.100"
T0 = 5000.0


class FakeBgpAdapter:
    domain_name = "bgp"

    def __init__(self):
        self.connected = True
        self.actions = []

    def collect(self):
        return []

    def is_connected(self):
        return self.connected

    def apply_mitigation(self, action):
        self.actions.append(action)
        return True


def _block(src_ip="*", protocol="UDP", dst_port=53):
    return MitigationAction(
        domain="bgp", device_id="r1", src_ip=src_ip, dst_ip=DST, dst_port=dst_port,
        protocol=protocol, action="bgp_flowspec_discard", attack_type="DDOS_DISTRIBUTED",
    )


def _correlated(pps, protocol="UDP", dst_port=53, src="10.30.0.2", domain="bgp"):
    events = []
    if pps is not None:
        events.append(TelemetryEvent(domain=domain, device_id="r1", src_ip=src, dst_ip=DST,
                                     dst_port=dst_port, protocol=protocol, pps=pps, bps=pps * 100))
    return [CorrelatedEvent(dst_ip=DST, total_pps=pps or 0.0, total_bps=0.0,
                            domains=[domain], events=events)]


class BgpReleaseTests(unittest.TestCase):
    def setUp(self):
        self.adapter = FakeBgpAdapter()
        self.controller = OrchestrationController(adapters=[self.adapter])
        self.clock = [T0]
        p = mock.patch("orchestration.controller.time.time", lambda: self.clock[0])
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(settings, "PEERING_RELEASE_QUIET_S", 8.0)
        p2.start()
        self.addCleanup(p2.stop)
        # no file output from the active-blocks publisher
        p3 = mock.patch.object(settings, "ACTIVE_BLOCKS_STATE_PATH", "")
        p3.start()
        self.addCleanup(p3.stop)

    def _block_it(self, **kw):
        action = _block(**kw)
        self.assertTrue(self.controller._dispatch(action))
        return (action.src_ip, DST, action.dst_port, action.protocol)

    def _tick(self, correlated, dt=0.5):
        self.clock[0] += dt
        return self.controller.check_mobile_unblocks(correlated)

    def test_attack_still_running_keeps_the_block_past_any_fixed_hold(self):
        key = self._block_it()
        # 60s of continuous offered load (>> the old 30s fixed hold).
        for _ in range(120):
            self.assertEqual(self._tick(_correlated(900.0)), [])
        self.assertIn(key, self.controller._active_mobile_blocks)

    def test_released_after_quiet_window_only(self):
        key = self._block_it()
        self._tick(_correlated(900.0))                 # last offered load seen
        for _ in range(15):                            # 7.5s quiet < 8s
            self.assertEqual(self._tick(_correlated(None)), [])
        out = []
        for _ in range(2):                             # crosses 8s
            out += self._tick(_correlated(None))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].action, "unblock")
        self.assertNotIn(key, self.controller._active_mobile_blocks)
        self.assertEqual(self.adapter.actions[-1].action, "unblock")

    def test_gaps_between_netflow_bursts_do_not_release(self):
        key = self._block_it()
        # nfcapd bursts every ~2s: 1 cycle with load, 3 empty, repeated.
        for _ in range(10):
            self._tick(_correlated(900.0))
            for _ in range(3):
                self.assertEqual(self._tick(_correlated(None)), [])
        self.assertIn(key, self.controller._active_mobile_blocks)

    def test_load_below_release_threshold_counts_as_quiet(self):
        # "*" block: threshold = DIST_PPS_THRESHOLD * UNBLOCK_RATIO = 150 pps
        key = self._block_it()
        out = []
        for _ in range(20):
            out += self._tick(_correlated(100.0))
        self.assertEqual(len(out), 1)
        self.assertNotIn(key, self.controller._active_mobile_blocks)

    def test_other_protocol_or_port_does_not_keep_the_block_alive(self):
        key = self._block_it(protocol="UDP", dst_port=53)
        out = []
        for _ in range(20):
            out += self._tick(_correlated(900.0, protocol="ICMP", dst_port=0))
            out += self._tick(_correlated(900.0, protocol="UDP", dst_port=9999))
        self.assertEqual(len(out), 1)
        self.assertNotIn(key, self.controller._active_mobile_blocks)

    def test_tcp_syn_telemetry_matches_a_tcp_block(self):
        key = self._block_it(protocol="TCP", dst_port=443)
        for _ in range(40):
            self.assertEqual(self._tick(_correlated(900.0, protocol="TCP_SYN", dst_port=443)), [])
        self.assertIn(key, self.controller._active_mobile_blocks)

    def test_per_source_block_only_counts_its_own_source(self):
        key = self._block_it(src_ip="10.30.0.2", protocol="UDP")
        # Single-source threshold for UDP is 200 -> release below 100 pps.
        out = []
        for _ in range(20):
            out += self._tick(_correlated(900.0, src="10.30.0.99"))
        self.assertEqual(len(out), 1)
        self.assertNotIn(key, self.controller._active_mobile_blocks)

    def test_telemetry_source_down_holds_the_block(self):
        key = self._block_it()
        self.adapter.connected = False
        for _ in range(60):
            self.assertEqual(self._tick(_correlated(None)), [])
        self.assertIn(key, self.controller._active_mobile_blocks)
        self.adapter.connected = True                  # source back, still quiet
        out = []
        for _ in range(20):
            out += self._tick(_correlated(None))
        self.assertEqual(len(out), 1)

    def test_other_domains_events_do_not_keep_a_bgp_block_alive(self):
        key = self._block_it()
        out = []
        for _ in range(20):
            out += self._tick(_correlated(900.0, domain="enterprise"))
        self.assertEqual(len(out), 1)
        self.assertNotIn(key, self.controller._active_mobile_blocks)


if __name__ == "__main__":
    unittest.main()
