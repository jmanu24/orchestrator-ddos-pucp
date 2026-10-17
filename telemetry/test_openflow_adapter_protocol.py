"""Protocol labeling of flow-stats events (OpenFlowAdapter.on_flow_stats).

LearningSwitch's L3 rule matches only (ipv4_src, ipv4_dst), so the rule
itself carries no ip_proto: the protocol of its volume comes from the
packet-in metadata (_flow_meta). A bare-SYN tag describes one packet, so it
is reported as plain TCP; UDP/ICMP/TCP tags are kept so single-source
floods of those protocols still classify. Needs ryu (run with the venv).
"""

import time
import unittest
from types import SimpleNamespace

from telemetry.openflow_adapter import OpenFlowAdapter

SRC, DST = "10.70.0.11", "10.55.0.100"


def _stat(packets, ip_proto=None):
    match = {"eth_type": 0x0800, "ipv4_src": SRC, "ipv4_dst": DST}
    if ip_proto is not None:
        match["ip_proto"] = ip_proto
    return SimpleNamespace(priority=10, duration_sec=5, byte_count=packets * 60,
                           packet_count=packets, match=match)


def _events(meta_protocol, dst_port=53, ip_proto=None, with_meta=True):
    adapter = OpenFlowAdapter()
    if with_meta:
        adapter._flow_meta[(SRC, DST)] = {
            "protocol": meta_protocol, "dst_port": dst_port, "dpid": 1,
            "in_port": 3, "timestamp": time.time(),
        }
    adapter.on_flow_stats(1, [_stat(1000, ip_proto)])
    time.sleep(0.15)
    return adapter.on_flow_stats(1, [_stat(1300, ip_proto)])


class FlowStatsProtocolTests(unittest.TestCase):
    def test_udp_metadata_is_kept(self):
        ev = _events("UDP")
        self.assertEqual([(e.protocol, e.dst_port) for e in ev], [("UDP", 53)])
        self.assertGreater(ev[0].pps, 0)

    def test_icmp_metadata_is_kept(self):
        self.assertEqual([e.protocol for e in _events("ICMP", dst_port=0)], ["ICMP"])

    def test_established_tcp_metadata_is_kept(self):
        self.assertEqual([e.protocol for e in _events("TCP", dst_port=443)], ["TCP"])

    def test_bare_syn_tag_is_not_applied_to_the_whole_rule_volume(self):
        ev = _events("TCP_SYN", dst_port=443)
        self.assertEqual([(e.protocol, e.dst_port) for e in ev], [("TCP", 443)])

    def test_without_fresh_metadata_falls_back_to_the_rule_protocol(self):
        self.assertEqual([e.protocol for e in _events(None, ip_proto=17, with_meta=False)], ["UDP"])
        self.assertEqual([e.protocol for e in _events(None, with_meta=False)], ["IP"])

    def test_stale_metadata_is_ignored(self):
        adapter = OpenFlowAdapter()
        adapter._flow_meta[(SRC, DST)] = {"protocol": "UDP", "dst_port": 53, "dpid": 1,
                                          "in_port": 3, "timestamp": time.time() - 3600}
        adapter.on_flow_stats(1, [_stat(1000)])
        time.sleep(0.15)
        self.assertEqual([e.protocol for e in adapter.on_flow_stats(1, [_stat(1300)])], ["IP"])


if __name__ == "__main__":
    unittest.main()
