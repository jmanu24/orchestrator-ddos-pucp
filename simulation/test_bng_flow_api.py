"""bng_flow_api: subscriber flows from conntrack, connection attempts, and the
accel-ppp session list. Sample lines are real `conntrack` / `accel-cmd`
output shapes captured on bng (subscriber traffic is masqueraded toward the
backbone, so the original tuple keeps the subscriber's own address)."""

import unittest

from simulation import bng_flow_api as api

UDP = ("udp      17 28 src=10.20.0.201 dst=10.55.0.100 sport=40000 dport=53 packets=300 bytes=18000 "
       "src=10.55.0.100 dst=10.92.0.2 sport=53 dport=40000 packets=2 bytes=120 [ASSURED] mark=0 use=1")
ICMP = ("icmp     1 29 src=10.20.0.202 dst=10.55.0.100 type=8 code=0 id=7 packets=50 bytes=4200 "
        "src=10.55.0.100 dst=10.92.0.2 type=0 code=0 id=7 packets=50 bytes=4200 mark=0 use=1")
TCP = ("tcp      6 117 SYN_SENT src=10.20.0.203 dst=10.55.0.100 sport=51000 dport=443 packets=1 bytes=60 "
       "[UNREPLIED] src=10.55.0.100 dst=10.92.0.2 sport=443 dport=51000 packets=0 bytes=0 mark=0 use=1")
FROM_BNG = ("udp      17 28 src=10.20.0.1 dst=10.20.0.201 sport=67 dport=68 packets=2 bytes=600 "
            "src=10.20.0.201 dst=10.20.0.1 sport=68 dport=67 packets=2 bytes=600 mark=0 use=1")
TO_BNG = ("udp      17 28 src=10.20.0.201 dst=10.20.0.1 sport=68 dport=67 packets=2 bytes=600 "
          "[UNREPLIED] src=10.20.0.1 dst=10.20.0.201 sport=67 dport=68 packets=0 bytes=0 mark=0 use=1")
OTHER_HOST = ("tcp      6 100 ESTABLISHED src=10.10.0.1 dst=10.10.0.2 sport=40000 dport=22 packets=9 bytes=900 "
              "src=10.10.0.2 dst=10.10.0.1 sport=22 dport=40000 packets=9 bytes=900 [ASSURED] mark=0 use=1")
NEW_SYN = ("    [NEW] tcp      6 120 SYN_SENT src=10.20.0.203 dst=10.55.0.100 sport=51000 dport=443 "
           "[UNREPLIED] src=10.55.0.100 dst=10.92.0.2 sport=443 dport=51000")
SESSIONS = """     ip      |    calling-sid    |        sid
-------------+-------------------+------------------
 10.20.0.204 | 02:00:00:00:00:04 | ecf78982f2cb719f
 10.20.0.202 | 02:00:00:00:00:0A | ecf78982f2cb71a0
"""


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


class ParseFlowTests(unittest.TestCase):
    def parse(self, *lines):
        return list(api.parse_conntrack_flows("\n".join(lines)))

    def test_original_direction_of_a_subscriber_flow(self):
        self.assertEqual(self.parse(UDP), [("10.20.0.201", "10.55.0.100", "UDP", 53, 300, 18000)])

    def test_icmp_has_no_port(self):
        self.assertEqual(self.parse(ICMP), [("10.20.0.202", "10.55.0.100", "ICMP", 0, 50, 4200)])

    def test_tcp_flow(self):
        self.assertEqual(self.parse(TCP)[0][:4], ("10.20.0.203", "10.55.0.100", "TCP", 443))

    def test_bng_own_and_non_subscriber_traffic_is_ignored(self):
        self.assertEqual(self.parse(FROM_BNG, TO_BNG, OTHER_HOST, "", "conntrack v1.4.6"), [])


class SynEventTests(unittest.TestCase):
    def test_subscriber_connection_attempt(self):
        self.assertEqual(api.parse_new_syn_event(NEW_SYN), ("10.20.0.203", "10.55.0.100", 443))

    def test_other_states_hosts_and_noise_are_ignored(self):
        for line in (NEW_SYN.replace("SYN_SENT", "ESTABLISHED"),
                     NEW_SYN.replace("src=10.20.0.203", "src=10.10.0.1", 1),
                     NEW_SYN.replace("dst=10.55.0.100", "dst=10.20.0.1", 1),
                     "", "conntrack v1.4.6: 12 flow events have been shown."):
            self.assertIsNone(api.parse_new_syn_event(line), line)

    def test_rate_is_attempts_over_the_window(self):
        clock = Clock()
        w = api.SynRateWindow(window_s=2.0, clock=clock)
        for _ in range(40):
            w.record(("10.20.0.203", "10.55.0.100", 443))
        self.assertEqual(w.rates()[("10.20.0.203", "10.55.0.100", 443)], 20.0)
        clock.now += 3.0
        self.assertEqual(w.rates(), {})


class RateTests(unittest.TestCase):
    def test_entries_of_one_flow_are_summed(self):
        rows = [("a", "b", "UDP", 53, 10, 100), ("a", "b", "UDP", 53, 5, 50), ("a", "b", "UDP", 80, 1, 1)]
        self.assertEqual(api.aggregate_flows(rows), {("a", "b", "UDP", 53): (15, 150), ("a", "b", "UDP", 80): (1, 1)})

    def test_rate_is_the_counter_delta_over_time(self):
        prev = {}
        key = ("a", "b", "UDP", 53)
        first = api.compute_rates({key: (100, 6000)}, prev, 10.0, 1000.0)
        self.assertEqual(first[key]["pps"], 0.0)  # no delta yet
        second = api.compute_rates({key: (300, 18000)}, prev, 11.0, 1001.0)
        self.assertEqual(second[key]["pps"], 200.0)
        self.assertEqual(second[key]["bps"], 12000.0)  # bytes per second
        self.assertEqual(second[key]["updated_at"], 1001.0)

    def test_a_shrinking_sum_is_no_rate_not_a_negative_one(self):
        prev = {}
        key = ("a", "b", "UDP", 53)
        api.compute_rates({key: (300, 18000)}, prev, 10.0, 0)
        out = api.compute_rates({key: (100, 6000)}, prev, 11.0, 1)
        self.assertEqual((out[key]["pps"], out[key]["bps"]), (0.0, 0.0))

    def test_vanished_flows_are_forgotten(self):
        prev = {}
        api.compute_rates({("a", "b", "UDP", 1): (1, 1)}, prev, 1.0, 1.0)
        api.compute_rates({}, prev, 2.0, 2.0)
        self.assertEqual(prev, {})


class SessionAndRowTests(unittest.TestCase):
    def test_sessions_parse_ip_mac_and_session_id(self):
        s = api.parse_sessions(SESSIONS)
        self.assertEqual(s["10.20.0.204"], {"mac": "02:00:00:00:00:04", "session_id": "ecf78982f2cb719f"})
        self.assertEqual(s["10.20.0.202"]["mac"], "02:00:00:00:00:0a")

    def test_garbage_gives_no_sessions(self):
        self.assertEqual(api.parse_sessions(""), {})
        self.assertEqual(api.parse_sessions("no such command"), {})

    def test_rows_carry_identity_and_a_tcp_syn_row_per_attempt_key(self):
        flows = [{"src_ip": "10.20.0.204", "dst_ip": "10.55.0.100", "protocol": "UDP", "dst_port": 53,
                  "pps": 5.0, "bps": 300.0, "updated_at": 1.0}]
        rows = api.build_rows(flows, {("10.20.0.202", "10.55.0.100", 443): 500.0},
                              api.parse_sessions(SESSIONS), now=2.0)
        udp, syn = rows
        self.assertEqual((udp["mac"], udp["session_id"]), ("02:00:00:00:00:04", "ecf78982f2cb719f"))
        self.assertEqual((syn["protocol"], syn["pps"], syn["dst_port"], syn["mac"]),
                         ("TCP_SYN", 500.0, 443, "02:00:00:00:00:0a"))

    def test_unknown_subscriber_has_no_identity(self):
        rows = api.build_rows([{"src_ip": "10.20.0.99", "dst_ip": "d", "protocol": "UDP", "dst_port": 1,
                                "pps": 1.0, "bps": 1.0, "updated_at": 1.0}], {}, {})
        self.assertIsNone(rows[0]["mac"])


if __name__ == "__main__":
    unittest.main()
