"""FlowCollector's same-poll key-collision guard.

Investigated as a candidate cause of the enterprise ~2x transient SYN
spike (docs/ENTERPRISE_FLOW_STATS_KEY_COLLISION.md) -- live probing
with dpid+priority logging confirmed this exact collision (two stat
entries for the same key in one OFPFlowStatsReply body, e.g. a
hard_timeout'd entry being replaced by a fresh one with the identical
OFPMatch) never actually occurs for that spike; the real cause turned
out to be a different, cross-layer double-count (on_packet_in +
on_flow_stats both reporting the same traffic during a hard_timeout
transition -- see the doc). This guard is kept anyway: it is correct,
free, and defends against the same-key-collision failure mode in case
it does occur under different load/topology.
"""
import time
import unittest

import config.settings as settings
from collectors.flow_collector import FlowCollector

DPID = 1
SRC, DST = "10.70.0.11", "10.55.0.100"


def _match():
    return {"eth_type": 0x0800, "ipv4_src": SRC, "ipv4_dst": DST, "ip_proto": 6}


class _Stat:
    def __init__(self, packets, priority=10):
        self.priority = priority
        self.byte_count = packets * 60
        self.packet_count = packets
        self.match = _match()


class FlowCollectorKeyCollisionTests(unittest.TestCase):
    def test_normal_single_stat_per_cycle_computes_a_clean_rate(self):
        collector = FlowCollector()
        collector.process_stats(DPID, [_Stat(1000)])
        time.sleep(settings.MIN_FLOW_RATE_DT + 0.05)
        flows = collector.process_stats(DPID, [_Stat(1300)])
        self.assertEqual(len(flows), 1)
        self.assertGreater(flows[0]["packet_rate"], 0)
        self.assertLess(flows[0]["packet_rate"], 10000)  # sane, not a spike

    def test_two_stats_same_key_in_one_body_emits_no_spurious_spike(self):
        """The exact collision: within ONE process_stats() call, a dying
        high-count entry and a fresh low-count entry share the same
        (dpid, src, dst, proto, port) key. Must not emit a rate computed
        from one against the other."""
        collector = FlowCollector()
        collector.process_stats(DPID, [_Stat(1000)])
        time.sleep(settings.MIN_FLOW_RATE_DT + 0.05)

        # Same key, two stats in one body: the old dying entry (high
        # cumulative count) and the just-installed fresh one (low count).
        flows = collector.process_stats(DPID, [_Stat(50), _Stat(5189)])
        self.assertEqual(flows, [])  # no event this cycle -- not a spike, not silently wrong

    def test_collision_rebaselines_on_the_larger_count_for_next_cycle(self):
        collector = FlowCollector()
        collector.process_stats(DPID, [_Stat(1000)])
        time.sleep(settings.MIN_FLOW_RATE_DT + 0.05)
        collector.process_stats(DPID, [_Stat(50), _Stat(5189)])
        time.sleep(settings.MIN_FLOW_RATE_DT + 0.05)

        # Next cycle, a single fresh stat continuing to grow from the
        # larger (5189) of the two collided entries -- should compute a
        # normal, modest rate, not treat 5189->5300 as a negative-delta
        # reset (which would happen if the smaller, 50, had won).
        flows = collector.process_stats(DPID, [_Stat(5300)])
        self.assertEqual(len(flows), 1)
        self.assertGreater(flows[0]["packet_rate"], 0)
        self.assertLess(flows[0]["packet_rate"], 10000)

    def test_twin_rule_priority_does_not_affect_the_key(self):
        """syn_only is still derived correctly from priority even though
        priority itself is not part of the dedup key."""
        collector = FlowCollector()
        twin_stat = _Stat(100, priority=settings.SYN_TWIN_PRIORITY)
        collector.process_stats(DPID, [twin_stat])
        time.sleep(settings.MIN_FLOW_RATE_DT + 0.05)
        flows = collector.process_stats(DPID, [_Stat(200, priority=settings.SYN_TWIN_PRIORITY)])
        self.assertEqual(len(flows), 1)
        self.assertTrue(flows[0]["syn_only"])


if __name__ == "__main__":
    unittest.main()
