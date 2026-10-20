import logging
import time
from collections import defaultdict

import config.settings as settings

# TEMPORARY -- verifying whether the same-poll key-collision guard below
# ever actually fires during the still-observed enterprise spike
# (2026-10-20, round 2). Removed once resolved.
_debug_logger = logging.getLogger("collectors.flow_collector.collision_debug")


class FlowCollector:

    def __init__(self):
        self.prev_flows = {}

    def process_stats(self, dpid, body, exclude_flow=None):

        flows = []
        now = time.time()
        # Snapshot taken once, before any update from this body -- never
        # read self.prev_flows mid-loop. A hard_timeout'd flow entry
        # (forwarding/learning_switch.py's VALIDATED_FLOW_HARD_TIMEOUT)
        # being replaced by a fresh one with the IDENTICAL OFPMatch can
        # make OVS briefly report both the dying old entry (high
        # cumulative counters) and the just-installed new one (freshly
        # reset counters) in the SAME OFPFlowStatsReply body -- same key
        # here (dpid, src, dst, proto, port) ignores priority/duration,
        # so without this snapshot the second stat processed would diff
        # against the first stat's just-written counters instead of the
        # true previous cycle's baseline, producing a large spurious
        # rate spike (observed live: ~2x the real rate, see
        # docs/ENTERPRISE_FLOW_STATS_KEY_COLLISION.md). Keyed collisions
        # within this one body are collected in _seen_this_call and
        # resolved after the main loop.
        prev_snapshot = dict(self.prev_flows)

        # First pass: group this body's stats by key. Almost always one
        # stat per key; a second one for the same key is the collision
        # described above.
        by_key = {}
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

            key = (dpid, src_ip, dst_ip, proto, dst_port)
            by_key.setdefault(key, []).append((stat, src_ip, dst_ip, proto, dst_port))

        for key, entries in by_key.items():
            if key[1:3] == ("10.70.0.11", "10.55.0.100"):
                _debug_logger.info(
                    "COLLISION_DEBUG key=%s n_entries=%s counts=%s",
                    key, len(entries), [e[0].packet_count for e in entries])

            if len(entries) > 1:
                # Collision: this cycle's body reported more than one
                # flow-table entry for the same (dpid, src, dst, proto,
                # port) -- almost certainly a hard_timeout'd entry being
                # replaced by a fresh one with the identical OFPMatch.
                # Never diff one against the other (that's what produced
                # the spurious ~2x spikes). Re-baseline on whichever has
                # the larger cumulative packet_count -- the entry further
                # along, most likely the one still live after this
                # transition -- and skip emitting a rate for this key
                # this cycle, exactly like the dt-too-small/negative-delta
                # skips below.
                stat, src_ip, dst_ip, proto, dst_port = max(entries, key=lambda e: e[0].packet_count)
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now
                }
                continue

            stat, src_ip, dst_ip, proto, dst_port = entries[0]
            prev = prev_snapshot.get(key)

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
