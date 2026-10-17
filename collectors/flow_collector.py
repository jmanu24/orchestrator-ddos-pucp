import time
from collections import defaultdict

import config.settings as settings


class FlowCollector:

    def __init__(self):
        self.prev_flows = {}

    def process_stats(self, dpid, body, exclude_flow=None):

        flows = []
        now = time.time()

        for stat in body:

            # Skip mitigation drop rules — they keep counting matched
            # (dropped) packets, and feeding that volume back into
            # telemetry would make the mitigation's own counters look like
            # a fresh attack and trigger a second, redundant block.
            if stat.priority >= settings.MITIGATION_DROP_PRIORITY:
                continue

            match = stat.match

            if match.get("eth_type") != 0x0800:
                continue

            src_ip = match.get("ipv4_src")
            dst_ip = match.get("ipv4_dst")
            proto = match.get("ip_proto", 0)

            # Optional Callable[[str, str], bool] -- flows whose (src,
            # dst) this returns True for belong to another domain's own
            # detection pipeline (see telemetry/openflow_adapter.py's
            # mobile-UE-subnet exclusion, which checks BOTH ends -- a
            # real host's reply traffic back toward a UE is just as much
            # excluded as the UE's own attack traffic) and are skipped
            # entirely, without even touching prev_flows for them.
            if exclude_flow and exclude_flow(src_ip, dst_ip):
                continue

            # ---- ONLY destination port ----
            dst_port = None

            if proto == 6:
                dst_port = match.get("tcp_dst", 0)

            elif proto == 17:
                dst_port = match.get("udp_dst", 0)

            if dst_port is None:
                dst_port = 0
            # -------------------------------

            key = (
                dpid,
                src_ip,
                dst_ip,
                proto,
                dst_port
            )

            prev = self.prev_flows.get(key)

            if prev is None:
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now
                }
                continue

            dt = now - prev["time"]

            if dt < settings.MIN_FLOW_RATE_DT:
                # Too little time between samples to trust a rate from —
                # likely two stats replies landing almost simultaneously
                # rather than a real second sample. Leave prev_flows
                # untouched so the next, properly-spaced sample measures
                # across the full elapsed window instead of this sliver.
                continue

            byte_delta = stat.byte_count - prev["bytes"]
            packet_delta = stat.packet_count - prev["packets"]

            if byte_delta < 0 or packet_delta < 0:
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now
                }
                continue

            byte_rate = byte_delta / dt
            packet_rate = packet_delta / dt

            flows.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "dst_port": dst_port,
                # True for the SYN twin rule (forwarding/syn_twin.py): all of
                # this flow's volume is bare SYNs by construction, whatever
                # any packet-in metadata says about the pair.
                "syn_only": stat.priority == settings.SYN_TWIN_PRIORITY,
                "byte_rate": byte_rate,
                "packet_rate": packet_rate,
                "bytes": stat.byte_count,
                "packets": stat.packet_count
            })

            self.prev_flows[key] = {
                "bytes": stat.byte_count,
                "packets": stat.packet_count,
                "time": now
            }

        return flows
