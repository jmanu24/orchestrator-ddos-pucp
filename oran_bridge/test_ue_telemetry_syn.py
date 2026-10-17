"""ue_telemetry_api's new-TCP-connection rate (the mobile domain's SYN signal).

The sample lines are real `conntrack -E -e NEW -p tcp` output captured on
core5g during a SYN flood from a UE (and its ordinary neighbours)."""

import unittest

from oran_bridge import ue_telemetry_api as api

FLOOD = ("    [NEW] tcp      6 120 SYN_SENT src=10.45.1.4 dst=10.55.0.100 sport=42190 dport=443 "
         "[UNREPLIED] src=10.55.0.100 dst=10.91.0.2 sport=443 dport=42190")
NOT_A_UE = ("    [NEW] tcp      6 120 SYN_SENT src=10.10.0.1 dst=10.10.0.5 sport=32838 dport=8766 "
            "[UNREPLIED] src=10.10.0.5 dst=10.10.0.1 sport=8766 dport=32838")
LOOPBACK = ("    [NEW] tcp      6 120 SYN_SENT src=127.0.0.20 dst=127.0.0.20 sport=49728 dport=7777 "
            "[UNREPLIED] src=127.0.0.20 dst=127.0.0.20 sport=7777 dport=49728")
ESTABLISHED_PICKUP = ("    [NEW] tcp      6 432000 ESTABLISHED src=10.45.1.4 dst=10.55.0.100 sport=42190 dport=443 "
                      "src=10.55.0.100 dst=10.91.0.2 sport=443 dport=42190 [ASSURED]")


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


class ParseTests(unittest.TestCase):
    def test_a_ue_connection_attempt_is_parsed(self):
        self.assertEqual(api.parse_new_syn_event(FLOOD), ("10.45.1.4", "10.55.0.100", 443))

    def test_non_ue_sources_are_ignored(self):
        self.assertIsNone(api.parse_new_syn_event(NOT_A_UE))
        self.assertIsNone(api.parse_new_syn_event(LOOPBACK))

    def test_only_syn_sent_entries_count_as_attempts(self):
        self.assertIsNone(api.parse_new_syn_event(ESTABLISHED_PICKUP))

    def test_noise_lines_are_ignored(self):
        for line in ("", "conntrack v1.4.6 (conntrack-tools): 1442 flow events have been shown.",
                     "    [UPDATE] tcp 6 60 SYN_RECV src=10.45.1.4 dst=10.55.0.100 sport=1 dport=2",
                     "    [NEW] udp      17 30 src=10.45.1.4 dst=10.55.0.100 sport=1 dport=53 [UNREPLIED]"):
            self.assertIsNone(api.parse_new_syn_event(line), line)


class RateWindowTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.win = api.SynRateWindow(window_s=2.0, clock=self.clock)
        self.key = ("10.45.1.4", "10.55.0.100", 443)

    def test_rate_is_attempts_per_second_over_the_window(self):
        for _ in range(1800):
            self.win.record(self.key)
        self.assertEqual(self.win.rates(), {self.key: 900.0})

    def test_old_attempts_leave_the_window(self):
        for _ in range(100):
            self.win.record(self.key)
        self.clock.now += 1.0
        for _ in range(50):
            self.win.record(self.key)
        self.assertEqual(self.win.rates()[self.key], 75.0)
        self.clock.now += 1.5          # first 100 are now 2.5s old
        self.assertEqual(self.win.rates()[self.key], 25.0)

    def test_an_idle_key_is_forgotten(self):
        self.win.record(self.key)
        self.clock.now += 5.0
        self.assertEqual(self.win.rates(), {})
        self.assertEqual(self.win._events, {})

    def test_keys_are_independent(self):
        other = ("10.45.1.5", "10.55.0.100", 80)
        self.win.record(self.key); self.win.record(other); self.win.record(other)
        self.assertEqual(self.win.rates(), {self.key: 0.5, other: 1.0})


class RowTests(unittest.TestCase):
    def test_syn_rate_becomes_a_tcp_syn_row_with_the_ues_identity_and_kpm(self):
        sessions = {"10.45.1.4": {"imsi": "001010123456790", "amf_ue_ngap_id": 7, "nr_cell_id": 1,
                                  "gnb_id": 411, "cell_local_id": 1}}
        kpm = {"001010123456790": {"metrics": {"DRB.UEThpUl": 2032.0, "RRU.PrbUsedUl": 40}, "updated_at": 5.0}}
        rows = api.build_flow_rows([], {("10.45.1.4", "10.55.0.100", 443): 900.0}, sessions, kpm, now=10.0)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["protocol"], r["dst_port"], r["pps"]), ("TCP_SYN", 443, 900.0))
        self.assertEqual(r["bps"], 900.0 * api.SYN_FRAME_BYTES)  # bytes/s, like every other row
        self.assertEqual((r["imsi"], r["gnb_id"]), ("001010123456790", 411))
        self.assertEqual(r["kpm"]["DRB.UEThpUl"], 2032.0)

    def test_list_based_flows_are_kept_alongside(self):
        flow = {"src_ip": "10.45.1.4", "dst_ip": "10.55.0.100", "protocol": "UDP", "dst_port": 53,
                "pps": 5.0, "bps": 500.0, "updated_at": 1.0}
        rows = api.build_flow_rows([flow], {("10.45.1.4", "10.55.0.100", 443): 20.0}, {}, {}, now=2.0)
        self.assertEqual(sorted(r["protocol"] for r in rows), ["TCP_SYN", "UDP"])
        self.assertTrue(all(r["imsi"] is None and r["kpm"] == {} for r in rows))


if __name__ == "__main__":
    unittest.main()
