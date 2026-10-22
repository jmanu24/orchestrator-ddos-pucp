import time

from collectors.flow_collector import FlowCollector


class _FakeStat:
    def __init__(self, priority, match, byte_count, packet_count):
        self.priority = priority
        self.match = match
        self.byte_count = byte_count
        self.packet_count = packet_count


def _match(src="10.10.0.21", dst="10.55.0.100", proto=6, dst_port=80):
    return {
        "eth_type": 0x0800,
        "ipv4_src": src,
        "ipv4_dst": dst,
        "ip_proto": proto,
        "tcp_dst": dst_port,
    }


def test_single_stat_per_key_computes_a_normal_rate():
    c = FlowCollector()
    c.process_stats(1, [_FakeStat(10, _match(), 1000, 10)])
    time.sleep(0.15)
    flows = c.process_stats(1, [_FakeStat(10, _match(), 2000, 20)])
    assert len(flows) == 1
    assert flows[0]["packets"] == 20


def test_duplicate_stat_for_same_key_in_one_body_never_diffs_against_itself():
    """Regression for the ENTERPRISE_FLOW_STATS_KEY_COLLISION bug
    (docs/ENTERPRISE_FLOW_STATS_KEY_COLLISION.md): a hard_timeout'd flow
    entry being replaced by a fresh one with the identical OFPMatch can
    make OVS report BOTH in the same OFPFlowStatsReply body. Before the
    fix, the collector read/wrote self.prev_flows stat-by-stat in a
    single pass, so the second entry for the same key was diffed against
    whatever the first entry had *just* written in this same call --
    producing a spurious rate spike instead of being recognized as a
    same-cycle collision."""
    c = FlowCollector()
    c.process_stats(1, [_FakeStat(10, _match(), 1000, 10)])
    time.sleep(0.15)

    # Same cycle: the dying old entry (high cumulative counters) and the
    # just-installed new one (freshly reset counters) for the identical
    # key, in the same body.
    dying = _FakeStat(10, _match(), 50000, 500)
    fresh = _FakeStat(10, _match(), 64, 1)
    flows = c.process_stats(1, [dying, fresh])

    assert flows == []


def test_duplicate_stat_rebaselines_on_the_larger_cumulative_count():
    c = FlowCollector()
    c.process_stats(1, [_FakeStat(10, _match(), 1000, 10)])
    time.sleep(0.15)

    dying = _FakeStat(10, _match(), 50000, 500)
    fresh = _FakeStat(10, _match(), 64, 1)
    c.process_stats(1, [dying, fresh])

    key = (1, "10.10.0.21", "10.55.0.100", 6, 80)
    assert c.prev_flows[key]["packets"] == 500

    time.sleep(0.15)
    flows = c.process_stats(1, [_FakeStat(10, _match(), 50500, 505)])
    assert len(flows) == 1
    assert flows[0]["packets"] == 505
