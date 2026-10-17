"""BroadbandAdapter.offered_pps(): rate of what a blocked MAC still sends,
from the per-MAC/protocol nft counters on `bng`. Needs eventlet (venv)."""

import json
import subprocess
import unittest
from unittest import mock

import config.settings as settings
from telemetry import broadband_adapter
from telemetry.broadband_adapter import BroadbandAdapter

MAC = "02:00:00:00:00:01"
IP = "10.20.0.201"


def _chain(packets, mac=MAC, kind="tcp_syn"):
    return json.dumps({"nftables": [
        {"metainfo": {"version": "1.0.2"}},
        {"rule": {"family": "netdev", "table": "ddos_bb", "chain": "offered", "handle": 4,
                  "comment": f"{mac} {kind}",
                  "expr": [{"match": {}}, {"counter": {"packets": packets, "bytes": packets * 60}}]}},
        {"rule": {"family": "netdev", "table": "ddos_bb", "chain": "offered", "handle": 5,
                  "comment": f"{mac} udp",
                  "expr": [{"match": {}}, {"counter": {"packets": 7, "bytes": 700}}]}},
    ]})


class OfferedLoadTests(unittest.TestCase):
    def setUp(self):
        self.out = _chain(0)
        self.rc = 0
        self.calls = []

        def fake_ssh(user, host, args, timeout=10, input_text=None):
            self.calls.append(list(args))
            if "nft" in args:
                return subprocess.CompletedProcess(args, self.rc, self.out if not self.rc else "", "denied" if self.rc else "")
            return subprocess.CompletedProcess(args, 0, "", "")

        p = mock.patch.object(broadband_adapter, "_ssh", fake_ssh)
        p.start()
        self.addCleanup(p.stop)
        self.adapter = BroadbandAdapter()
        self.adapter._mac_by_ip[IP] = MAC
        self.now = [100.0]
        self.adapter._clock = lambda: self.now[0]

    def _poll(self, packets, dt=1.0):
        self.now[0] += dt
        self.out = _chain(packets)
        return self.adapter.offered_pps(IP, "TCP")

    def test_parse_picks_counters_by_comment(self):
        parsed = BroadbandAdapter._parse_offered_counters(_chain(42))
        self.assertEqual(parsed[(MAC, "tcp_syn")], 42)
        self.assertEqual(parsed[(MAC, "udp")], 7)

    def test_first_reading_has_no_rate_yet(self):
        self.assertIsNone(self._poll(1000))

    def test_rate_is_the_counter_delta_over_time(self):
        self._poll(1000)
        self.assertAlmostEqual(self._poll(1900, dt=1.0), 900.0)

    def test_stopped_attacker_reads_zero_not_none(self):
        self._poll(1000)
        self.assertAlmostEqual(self._poll(1000, dt=1.0), 0.0)

    def test_counter_reset_gives_no_bogus_rate(self):
        self._poll(5000)
        self.assertAlmostEqual(self._poll(5900), 900.0)
        # Table recreated: counter goes backwards. No negative/garbage
        # rate; the last good one is kept for this round...
        self.assertEqual(self._poll(10), 900.0)
        # ...and the next reading is measured from the new baseline.
        self.assertAlmostEqual(self._poll(110), 100.0)

    def test_unreadable_counters_are_none_not_quiet(self):
        self._poll(1000)
        self.rc = 1
        self.now[0] += settings.BROADBAND_OFFERED_MAX_AGE_S + 1
        self.assertIsNone(self.adapter.offered_pps(IP, "TCP"))

    def test_unknown_ip_or_protocol_is_none(self):
        self.assertIsNone(self.adapter.offered_pps("10.20.0.99", "TCP"))
        self.assertIsNone(self.adapter.offered_pps(IP, "SCTP"))

    def test_polling_is_rate_limited(self):
        self._poll(1000)
        before = len([c for c in self.calls if "nft" in c])
        self.adapter.offered_pps(IP, "TCP")   # same instant: no new ssh
        self.assertEqual(len([c for c in self.calls if "nft" in c]), before)


if __name__ == "__main__":
    unittest.main()
