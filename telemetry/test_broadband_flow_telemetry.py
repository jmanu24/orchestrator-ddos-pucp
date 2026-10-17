"""BroadbandAdapter.collect(): events come from the conntrack sidecar's
/telemetry payload (real destination/protocol/port), not from RADIUS
accounting or the traffic generator's state. Needs eventlet (venv)."""

import subprocess
import unittest
from unittest import mock

from telemetry import broadband_adapter
from telemetry.broadband_adapter import BroadbandAdapter

IP = "10.20.0.201"
MAC = "02:00:00:00:00:01"


def row(proto="UDP", dst="10.55.0.100", port=53, pps=900.0, bps=54000.0, at=1.0, src=IP, mac=MAC):
    return {"src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": port,
            "pps": pps, "bps": bps, "updated_at": at, "mac": mac, "session_id": "sid1"}


class FlowTelemetryTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(broadband_adapter, "_ssh",
                              lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
        p.start()
        self.addCleanup(p.stop)
        self.adapter = BroadbandAdapter()
        self.payload = None
        self.adapter._read_flow_api = lambda: self.payload

    def serve(self, flows, sessions=(), connected=True):
        self.payload = {"flows": list(flows), "sessions": list(sessions), "conntrack_connected": connected}
        return self.adapter.collect()

    def test_event_carries_the_observed_flow_attributes(self):
        (e,) = self.serve([row("UDP", "10.55.0.100", 53)])
        self.assertEqual((e.domain, e.src_ip, e.dst_ip, e.dst_port, e.protocol, e.pps),
                         ("broadband", IP, "10.55.0.100", 53, "UDP", 900.0))

    def test_other_destinations_are_not_rewritten_to_the_default_target(self):
        (e,) = self.serve([row("TCP", "198.51.100.7", 8443)])
        self.assertEqual((e.dst_ip, e.dst_port), ("198.51.100.7", 8443))

    def test_tcp_syn_rows_pass_through_as_tcp_syn(self):
        (e,) = self.serve([row("TCP_SYN", port=443, pps=700.0)])
        self.assertEqual((e.protocol, e.pps), ("TCP_SYN", 700.0))

    def test_a_sample_is_counted_once(self):
        self.assertEqual(len(self.serve([row(at=1.0)])), 1)
        self.assertEqual(self.serve([row(at=1.0)]), [])      # sidecar re-served the same sample
        self.assertEqual(len(self.serve([row(at=2.0)])), 1)  # a fresh one

    def test_idle_flows_make_no_event(self):
        self.assertEqual(self.serve([row(pps=0.0, bps=0.0)]), [])

    def test_unreachable_sidecar_or_lost_conntrack_gives_nothing(self):
        self.payload = None
        self.assertEqual(self.adapter.collect(), [])
        self.assertEqual(self.serve([row()], connected=False), [])

    def test_malformed_rows_are_skipped(self):
        events = self.serve([{"src_ip": IP}, row(port=80)])
        self.assertEqual([e.dst_port for e in events], [80])

    def test_subscriber_identity_is_learned_and_kept_for_mitigation(self):
        self.serve([], sessions=[{"ip": IP, "mac": MAC, "session_id": "sid1"}])
        self.assertEqual(self.adapter._mac_by_ip[IP], MAC)
        self.serve([row(mac=None)])
        self.serve([], sessions=[])  # session terminated by a block: mapping must survive
        self.assertEqual(self.adapter._mac_by_ip[IP], MAC)
        self.assertEqual(self.adapter._session_by_ip[IP], "sid1")


if __name__ == "__main__":
    unittest.main()
