"""SYN twin rules: a second, higher-priority rule per validated L3 pair that
matches only bare SYNs, so a single-source TCP SYN flood is measurable from
flow-stats. Needs ryu (run with the venv)."""

import time
import unittest
from types import SimpleNamespace
from unittest import mock

from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3 as of, ofproto_v1_3_parser as parser

import config.settings as settings
from collectors.flow_collector import FlowCollector
from forwarding.learning_switch import LearningSwitch
from forwarding.syn_twin import BARE_SYN_FLAGS, syn_twin_match
from mitigation.openflow_mitigator import OpenFlowMitigator
from orchestration.controller import OrchestrationController
from telemetry.openflow_adapter import OpenFlowAdapter

SRC, DST = "10.70.0.11", "10.55.0.100"
MAC_A, MAC_B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"


class FakeDatapath:
    id = 1
    ofproto = of
    ofproto_parser = parser

    def __init__(self):
        self.sent = []

    def send_msg(self, msg):
        self.sent.append(msg)

    def set_xid(self, msg):
        msg.xid = 1

    def flow_mods(self):
        return [m for m in self.sent if isinstance(m, parser.OFPFlowMod)]


def _packet_in(dp, l4):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(dst=MAC_B, src=MAC_A, ethertype=0x0800))
    pkt.add_protocol(ipv4.ipv4(proto=6 if isinstance(l4, tcp.tcp) else 17, src=SRC, dst=DST))
    pkt.add_protocol(l4)
    pkt.serialize()
    msg = SimpleNamespace(datapath=dp, match={"in_port": 3}, data=bytes(pkt.data), buffer_id=of.OFP_NO_BUFFER)
    return SimpleNamespace(msg=msg)


def _syn():
    return tcp.tcp(src_port=40000, dst_port=443, bits=tcp.TCP_SYN)


def _switch(validated):
    ls = LearningSwitch(is_validated=lambda s, d: validated)
    ls.mac_to_port[1] = {MAC_B: 5}  # known destination -> a concrete out port
    return ls


class LearningSwitchTwinTests(unittest.TestCase):
    def test_validated_pair_gets_an_l3_rule_and_a_syn_twin(self):
        dp = FakeDatapath()
        _switch(True).packet_in_handler(_packet_in(dp, _syn()))
        mods = {m.priority: m for m in dp.flow_mods()}
        self.assertEqual(set(mods), {settings.FORWARDING_PRIORITY, settings.SYN_TWIN_PRIORITY})
        l3, twin = mods[settings.FORWARDING_PRIORITY], mods[settings.SYN_TWIN_PRIORITY]
        self.assertGreater(twin.priority, l3.priority)
        # same forwarding action and lifetime
        self.assertEqual([i.actions[0].port for i in l3.instructions], [5])
        self.assertEqual([i.actions[0].port for i in twin.instructions], [5])
        self.assertEqual((twin.idle_timeout, twin.hard_timeout), (l3.idle_timeout, l3.hard_timeout))
        # the twin matches bare SYNs only, for this exact pair
        fields = dict(twin.match._fields2)
        self.assertEqual(fields["ipv4_src"], SRC)
        self.assertEqual(fields["ipv4_dst"], DST)
        self.assertEqual(fields["ip_proto"], 6)
        self.assertEqual(fields["tcp_flags"], BARE_SYN_FLAGS)
        self.assertNotIn("tcp_flags", dict(l3.match._fields2))

    def test_the_twin_is_installed_even_when_the_first_packet_is_not_tcp(self):
        # A pair first seen via UDP can start a SYN flood later through the
        # same cached L3 rule, with no new packet-in to trigger an install.
        dp = FakeDatapath()
        _switch(True).packet_in_handler(_packet_in(dp, udp.udp(src_port=5000, dst_port=53)))
        self.assertIn(settings.SYN_TWIN_PRIORITY, [m.priority for m in dp.flow_mods()])

    def test_provisional_pair_gets_no_twin(self):
        dp = FakeDatapath()
        _switch(False).packet_in_handler(_packet_in(dp, _syn()))
        self.assertEqual([m.priority for m in dp.flow_mods()], [settings.FORWARDING_PRIORITY])

    def test_twin_can_be_disabled(self):
        dp = FakeDatapath()
        with mock.patch.object(settings, "SYN_TWIN_ENABLED", False):
            _switch(True).packet_in_handler(_packet_in(dp, _syn()))
        self.assertEqual([m.priority for m in dp.flow_mods()], [settings.FORWARDING_PRIORITY])

    def test_twin_match_serializes_to_what_open_vswitch_decodes(self):
        # Verified against Open vSwitch 3.7.1 with `ovs-ofctl ofp-parse`:
        # tcp,nw_src=..,nw_dst=..,tcp_flags=+syn-ack. Here: the ONF
        # experimenter OXM is on the wire (0x4F4E4600).
        buf = bytearray()
        syn_twin_match(parser, SRC, DST).serialize(buf, 0)
        self.assertIn(bytes.fromhex("4f4e4600"), bytes(buf))


class MitigatorTwinTests(unittest.TestCase):
    def test_clearing_forwarding_rules_removes_each_pair_twin_too(self):
        dp = FakeDatapath()
        mitigator = OpenFlowMitigator()
        mitigator.register(dp)
        mitigator.clear_forwarding_rules(DST, ["10.70.0.11", "10.70.0.12"])
        deletes = dp.flow_mods()
        self.assertEqual(len(deletes), 4)
        self.assertTrue(all(m.command == of.OFPFC_DELETE_STRICT for m in deletes))
        self.assertEqual(sorted(m.priority for m in deletes),
                         [settings.FORWARDING_PRIORITY] * 2 + [settings.SYN_TWIN_PRIORITY] * 2)
        twins = [m for m in deletes if m.priority == settings.SYN_TWIN_PRIORITY]
        self.assertTrue(all(dict(m.match._fields2)["tcp_flags"] == BARE_SYN_FLAGS for m in twins))


def _stat(priority, packets, ip_proto=None, tcp_flags=False, duration=5):
    match = {"eth_type": 0x0800, "ipv4_src": SRC, "ipv4_dst": DST}
    if ip_proto:
        match["ip_proto"] = ip_proto
    if tcp_flags:
        match["tcp_flags"] = BARE_SYN_FLAGS
    return SimpleNamespace(priority=priority, duration_sec=duration, byte_count=packets * 54,
                           packet_count=packets, match=match)


class TelemetryTests(unittest.TestCase):
    def test_flow_collector_marks_only_the_twin_as_syn_only(self):
        fc = FlowCollector()
        body = lambda n: [_stat(settings.FORWARDING_PRIORITY, n), _stat(settings.SYN_TWIN_PRIORITY, n, 6, True)]
        fc.process_stats(1, body(100))
        time.sleep(0.15)
        flows = fc.process_stats(1, body(400))
        self.assertEqual(sorted((f["syn_only"], f["protocol"]) for f in flows), [(False, 0), (True, 6)])

    def _events(self, meta):
        adapter = OpenFlowAdapter()
        if meta:
            adapter._flow_meta[(SRC, DST)] = dict(meta, dpid=1, in_port=3, timestamp=time.time())
        body = lambda n: [_stat(settings.SYN_TWIN_PRIORITY, n, 6, True)]
        adapter.on_flow_stats(1, body(1000))
        time.sleep(0.15)
        return adapter.on_flow_stats(1, body(1300))

    def test_twin_volume_is_reported_as_tcp_syn_with_its_own_rate(self):
        ev = self._events({"protocol": "TCP", "dst_port": 443})
        self.assertEqual([(e.protocol, e.dst_port) for e in ev], [("TCP_SYN", 443)])
        self.assertGreater(ev[0].pps, 500)

    def test_twin_volume_ignores_a_non_tcp_pair_tag_and_still_counts_as_syn(self):
        ev = self._events({"protocol": "UDP", "dst_port": 53})
        self.assertEqual([(e.protocol, e.dst_port) for e in ev], [("TCP_SYN", 0)])

    def test_twin_volume_without_any_metadata(self):
        ev = self._events(None)
        self.assertEqual([(e.protocol, e.dst_port) for e in ev], [("TCP_SYN", 0)])


class SweepTests(unittest.TestCase):
    def test_sweep_deletes_the_twin_of_a_blocked_pair_as_well(self):
        dp = FakeDatapath()
        controller = OrchestrationController(adapters=[])
        controller.of_mitigator.register(dp)
        controller._active_blocks[(SRC, DST, 443, "TCP")] = SimpleNamespace(sources=[], attack_type="SYN_FLOOD")
        controller.sweep_blocked_forwarding([_stat(settings.SYN_TWIN_PRIORITY, 10, 6, True)])
        self.assertEqual(sorted(m.priority for m in dp.flow_mods()),
                         [settings.FORWARDING_PRIORITY, settings.SYN_TWIN_PRIORITY])


class DetectionTests(unittest.TestCase):
    def test_a_single_source_syn_flood_through_the_twin_is_classified_syn_flood(self):
        from core.models import CorrelatedEvent
        from detection.engine import DDoSDetectionEngine

        adapter = OpenFlowAdapter()
        adapter.on_flow_stats(1, [_stat(settings.SYN_TWIN_PRIORITY, 1000, 6, True)])
        time.sleep(0.15)
        events = adapter.on_flow_stats(1, [_stat(settings.SYN_TWIN_PRIORITY, 1400, 6, True)])
        corr = CorrelatedEvent(dst_ip=DST, total_pps=sum(e.pps for e in events), total_bps=0,
                               domains=["enterprise"], events=events)
        with mock.patch.object(settings, "ENTERPRISE_ACTIVATION_MIN_HITS", 1):
            result = DDoSDetectionEngine().analyze([corr])
        self.assertEqual([(d.attack_type, d.src_ip, d.protocol) for d in result],
                         [("SYN_FLOOD", SRC, "TCP")])


if __name__ == "__main__":
    unittest.main()
