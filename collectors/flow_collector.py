import time
from collections import defaultdict

import config.settings as settings


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
            syn_only = stat.priority == settings.SYN_TWIN_PRIORITY
            duration_sec = getattr(stat, "duration_sec", None)

            if prev is None:
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now,
                    "duration_sec": duration_sec,
                    "zero_streak": 0,
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
                    "time": now,
                    "duration_sec": duration_sec,
                    "zero_streak": 0,
                }
                continue

            # same_instance: this flow entry's own OVS-reported age grew by
            # about as much as our own polling interval did, confirming
            # it's still the SAME flow (not a hard_timeout'd one silently
            # replaced with a fresh, identically-keyed entry -- duration_sec
            # would reset close to 0 for that case instead). Only relevant
            # for the stuck-twin-counter check below; never gates a normal
            # rate computation.
            same_instance = (
                duration_sec is not None and prev.get("duration_sec") is not None
                and duration_sec >= prev["duration_sec"]
            )

            if packet_delta == 0 and syn_only and same_instance:
                # Confirmed live on the real network (see docs/
                # SYN_TWIN_COUNTER_STALL.md): the SYN twin rule's own
                # OpenFlow-level packet counter can freeze at whatever it
                # read on its first poll after installation and never grow
                # again for the rest of that flow entry's lifetime, even
                # while real bare-SYN traffic keeps arriving and the OVS
                # kernel datapath (a separate counter, `ovs-appctl dpctl/
                # dump-flows`) keeps counting it correctly -- an OVS
                # kernel/userspace revalidator race around flow_mod
                # install time, not a bug in this collector or in
                # forwarding/learning_switch.py's flow-install logic
                # (confirmed live: the SAME rule, reinstalled moments
                # later, counted a fresh flood perfectly from 0 onward,
                # with no code change in between). Not fixable here --
                # only detectable. STUCK_STREAK_THRESHOLD consecutive
                # zero-growth cycles on the SAME flow instance means this
                # cycle's (and every cycle's, until the flow is replaced
                # or starts growing again) sample is unreliable: skip
                # emitting it entirely, the same "no sample" treatment as
                # dt-too-small above, rather than reporting a confidently
                # wrong 0 pps.
                zero_streak = prev.get("zero_streak", 0) + 1
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now,
                    "duration_sec": duration_sec,
                    "zero_streak": zero_streak,
                }
                if zero_streak >= settings.SYN_TWIN_STUCK_STREAK_THRESHOLD:
                    continue
            else:
                self.prev_flows[key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now,
                    "duration_sec": duration_sec,
                    "zero_streak": 0,
                }

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
                "syn_only": syn_only,
                "byte_rate": byte_rate,
                "packet_rate": packet_rate,
                "bytes": stat.byte_count,
                "packets": stat.packet_count
            })

        return flows
