"""PeeringFlowCollector._parse_csv()'s duration floor.

Bug found live during threshold calibration (2026-10-20): nfdump reports
`td` as ~0 for a short flow (a lone SYN, say); the old floor
(max(td, 0.001)) turned that into an absurd pps (packets/0.001), which
correlation/correlator.py and detection/engine.py then SUM per cycle
with every other event -- peering/bgp benign cycles were observed
reading up to ~29,000 "SYN pps" this way. The floor is now
COLLECT_INTERVAL, this pipeline's own real sampling granularity."""
import unittest

import config.settings as settings
from collectors.peering_flow_collector import PeeringFlowCollector

HEADER = "sa,da,dp,pr,td,ipkt,ibyt,flg\n"


def csv_row(src="10.30.0.2", dst="10.55.0.100", dport=9001, proto="TCP",
            td="0.000", ipkt=1, ibyt=64, flg="......S."):
    return f"{src},{dst},{dport},{proto},{td},{ipkt},{ibyt},{flg}\n"


class PeeringFlowCollectorDurationFloorTests(unittest.TestCase):
    def test_a_near_zero_duration_flow_is_floored_at_collect_interval_not_1ms(self):
        output = HEADER + csv_row(td="0.000", ipkt=1, ibyt=64)
        records = PeeringFlowCollector._parse_csv(output)
        self.assertEqual(len(records), 1)
        # packets/COLLECT_INTERVAL, not packets/0.001 (which would be 1000).
        self.assertAlmostEqual(records[0]["pps"], 1 / settings.COLLECT_INTERVAL)
        self.assertLess(records[0]["pps"], 100)

    def test_several_short_flows_in_one_cycle_no_longer_sum_to_tens_of_thousands(self):
        """The actual failure mode: many ordinary short benign flows in
        one correlation cycle, summed, used to reach ~29,000 apparent
        SYN pps. Reproduced here with 20 one-packet flows."""
        output = HEADER + "".join(csv_row(td="0.000", ipkt=1) for _ in range(20))
        records = PeeringFlowCollector._parse_csv(output)
        total_pps = sum(r["pps"] for r in records)
        self.assertEqual(len(records), 20)
        self.assertAlmostEqual(total_pps, 20 / settings.COLLECT_INTERVAL)
        self.assertLess(total_pps, 100)  # would have been ~20,000 before the fix

    def test_a_flow_with_a_genuinely_longer_duration_is_unaffected(self):
        """max() must only engage for the suspiciously-short-duration
        case this bug actually hit -- a real, longer-lived flow's own
        reported duration is trusted as before."""
        output = HEADER + csv_row(td="4.0", ipkt=400, ibyt=25600)
        records = PeeringFlowCollector._parse_csv(output)
        self.assertEqual(len(records), 1)
        self.assertAlmostEqual(records[0]["pps"], 400 / 4.0)
        self.assertAlmostEqual(records[0]["bps"], 25600 / 4.0)

    def test_duration_exactly_at_collect_interval_uses_its_own_value(self):
        output = HEADER + csv_row(td=str(settings.COLLECT_INTERVAL), ipkt=5, ibyt=320)
        records = PeeringFlowCollector._parse_csv(output)
        self.assertAlmostEqual(records[0]["pps"], 5 / settings.COLLECT_INTERVAL)


if __name__ == "__main__":
    unittest.main()
