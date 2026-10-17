import ipaddress
import time
from typing import Dict, List, Optional, Tuple

from ryu.lib.packet import packet, ipv4, tcp, udp

import config.settings as settings
from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from collectors.flow_collector import FlowCollector
from collectors.ddos_collector import DDoSCollector


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Other domains' data-plane ranges that cross the shared PE OpenFlow
# bridge but belong to another detector. The PE sees mobile and fixed
# traffic after NAT (10.91.0.2 / 10.92.0.2), while peering keeps the
# external source (10.30.0.2). Treating those transit addresses as
# enterprise made one physical packet appear twice in correlation and
# allowed enterprise mitigation to race the owning domain.
_DISTRIBUTED_NON_ENTERPRISE_SUBNETS = (
    ipaddress.ip_network("10.45.0.0/16"),  # Open5GS PDU pool
    ipaddress.ip_network("10.20.0.0/24"),  # fixed BNG access sessions
    ipaddress.ip_network("10.30.0.0/24"),  # external peering segment
    ipaddress.ip_network("10.91.0.0/30"),  # mobile backbone
    ipaddress.ip_network("10.92.0.0/30"),  # fixed backbone
    ipaddress.ip_network("10.93.0.0/30"),  # peering backbone
)


def _is_distributed_non_enterprise_source(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _DISTRIBUTED_NON_ENTERPRISE_SUBNETS)


def _is_simulated_domain_source(ip: Optional[str]) -> bool:
    """Union of every other domain's simulated-traffic address space that
    happens to also transit this domain's real OpenFlow switches."""
    return _is_distributed_non_enterprise_source(ip)


def _is_simulated_domain_flow(src_ip: Optional[str], dst_ip: Optional[str]) -> bool:
    """
    True if EITHER end belongs to another simulated domain -- not just
    the attack direction (that domain's source), but also reply/
    reflection traffic a real host sends back the other way (e.g. h2's
    ICMP echo replies to a flooded UE's spoofed source: src=h2's real
    IP, dst=the UE). That reverse direction is just as much the other
    domain's own business as the forward one -- excluding only by
    source left mobile UE traffic fully visible to this domain's
    detection early on, which is exactly what raced and blocked it
    instead of the mobile pipeline.
    """
    return _is_simulated_domain_source(src_ip) or _is_simulated_domain_source(dst_ip)

# How long a _flow_meta entry is trusted for. Once a (src,dst) pair has a
# cached L3 forwarding rule, traffic between them never triggers another
# packet-in — even if a completely different L4 protocol starts flowing
# through that same cached rule later (e.g. a ping, then minutes later a
# UDP flood between the same two hosts). Without a TTL, flow-stats volume
# would keep getting confidently mislabeled with whatever protocol the
# *first* packet ever seen on that pair happened to be, for as long as the
# rule stays alive (which, under continuous attack traffic, is forever —
# idle_timeout keeps resetting). Past this TTL, an unrefreshed entry is
# distrusted and classification falls back to generic "IP" rather than a
# stale, possibly wrong protocol label. Matches
# settings.VALIDATED_FLOW_HARD_TIMEOUT, which forces the cached rule
# itself to expire and trigger a fresh packet-in before this TTL runs out.
_FLOW_META_TTL = settings.VALIDATED_FLOW_HARD_TIMEOUT


class OpenFlowAdapter(DomainAdapter):
    """
    Telemetry adapter for the Enterprise Services domain, implemented over
    an OpenFlow / SDN topology -- "OpenFlow"/"SDN" is the
    technical mechanism, "Enterprise" is the domain it represents in the
    controller's 4-domain model (Enterprise, Mobile, Broadband, External
    Peering). Kept the class/file name "OpenFlow" since that's the real,
    implemented mechanism a reader of this code will actually see.

    Wraps the existing FlowCollector (periodic per-flow stats via
    OFPFlowStatsReply) and DDoSCollector (real-time packet-in analysis)
    to produce normalized TelemetryEvents for the Correlation layer.

    Forwarding flow rules are installed at L3 only (src/dst IP), so
    OFPFlowStatsReply carries no L4 detail. To keep attack classification
    and mitigation L4-aware anyway, this adapter remembers the protocol/
    dst_port seen on the first packet of each (src_ip, dst_ip) pair (via
    packet-in) and reapplies it to the bulk volume events that come later
    from flow stats.

    Mitigation for this domain is handled by OpenFlowMitigator, which
    needs a live datapath reference — so apply_mitigation() is intentionally
    a no-op here.
    """

    domain_name = "enterprise"

    def __init__(self, is_host_port=None):
        self._flow_collector = FlowCollector()
        self._ddos_collector = DDoSCollector()
        self._pending: List[TelemetryEvent] = []
        # (src_ip, dst_ip) -> {"protocol": str, "dst_port": int, "dpid",
        # "in_port"}, learned from packet-in. protocol/dst_port/timestamp
        # refresh on every sighting regardless of where it came from;
        # dpid/in_port only ever get set from a confirmed genuine HOST
        # port (see is_host_port below) and then stay sticky — a later
        # sighting of the same pair via an inter-switch link or the
        # router's own interface (which happens for every cross-subnet
        # attack, at the victim's switch) never overwrites a good
        # location with the wrong end of the path.
        self._flow_meta: Dict[Tuple[str, str], dict] = {}
        # Optional Callable[[dpid, in_port], bool] — True only for a port
        # a real host is directly attached to (LearningSwitch.is_host_port).
        # None means "trust every sighting" (used in tests / when this
        # filtering isn't wired up).
        self._is_host_port = is_host_port

    # ------------------------------------------------------------------
    # Push handlers — called from Ryu event callbacks
    # ------------------------------------------------------------------

    def on_flow_stats(self, dpid, body) -> List[TelemetryEvent]:
        """
        Process an OFPFlowStatsReply body and convert flows to TelemetryEvents.
        Called by the controller's flow_stats_reply_handler.
        """
        flows = self._flow_collector.process_stats(dpid, body, exclude_flow=_is_simulated_domain_flow)
        events: List[TelemetryEvent] = []

        for flow in flows:
            src_ip = flow.get("src_ip") or "0.0.0.0"
            dst_ip = flow.get("dst_ip") or "0.0.0.0"

            meta = self._fresh_meta(src_ip, dst_ip)

            if flow.get("syn_only"):
                # The SYN twin rule's counters: exactly this pair's bare-SYN
                # volume. The port is a best effort from the pair's TCP
                # sighting (the twin matches no port); 0 means "any TCP
                # port" to the mitigator.
                tcp_port = meta["dst_port"] if meta and meta["protocol"] in ("TCP", "TCP_SYN") else 0
                events.append(TelemetryEvent(
                    domain=self.domain_name,
                    device_id=str(dpid),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=tcp_port,
                    protocol="TCP_SYN",
                    pps=flow["packet_rate"],
                    bps=flow["byte_rate"],
                ))
                continue

            if meta:
                proto = meta["protocol"]
                if proto == "TCP_SYN":
                    # The packet-in tag describes ONE packet (a bare SYN),
                    # never all the volume accumulated in this L3 rule,
                    # which may be established-connection traffic. Labeling
                    # that volume TCP_SYN would count it toward
                    # SYN_THRESHOLD. SYN floods are classified from the
                    # packet-in events instead (on_packet_in), where each
                    # packet is individually tagged.
                    proto = "TCP"
                dst_port = meta["dst_port"]
            else:
                proto = _PROTO_NAMES.get(flow["protocol"], "IP")
                dst_port = flow.get("dst_port", 0)

            ev = TelemetryEvent(
                domain=self.domain_name,
                device_id=str(dpid),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                pps=flow["packet_rate"],
                bps=flow["byte_rate"],
            )
            events.append(ev)

        self._pending.extend(events)
        return events

    def on_packet_in(self, msg) -> List[TelemetryEvent]:
        """
        Process a packet-in message for per-destination DDoS metrics.
        Called by the controller's packet_in_handler.

        Returns one TelemetryEvent per distinct source IP seen toward this
        destination during the window — not a single aggregate event —
        so the Correlation/Detection layers can compute source-IP entropy
        for distributed/spoofed-source attacks.
        """
        self._remember_flow_meta(msg)

        result = self._ddos_collector.process_packet(msg)
        if not result:
            return []

        if _is_simulated_domain_source(result["dst_ip"]):
            # This whole window's destination belongs to another
            # other domain (a mobile UE or a BNG session) -- e.g. a real host's ICMP echo
            # replies flowing back toward a flooded UE's spoofed source.
            # Every src_ip in this result shares the same dst_ip
            # (DDoSCollector.process_packet windows per destination), so
            # this excludes the entire result at once rather than relying
            # only on the per-source check below. See
            # _is_simulated_domain_flow's docstring.
            return []

        # Distribute the window's aggregate bps proportionally across
        # sources by their share of packets, since bytes aren't tracked
        # per-source.
        bytes_per_packet = result["bps"] / result["pps"] if result["pps"] else 0.0

        # Fallback for sources this window's aggregation picked up that
        # weren't the one that just triggered _remember_flow_meta above —
        # still better than nothing, since a source typically keeps
        # entering via the same physical port in a static topology.
        fallback_dpid = msg.datapath.id
        fallback_in_port = msg.match["in_port"]

        events = []
        for src_ip, pps in result["src_pps"].items():
            if _is_simulated_domain_source(src_ip):
                # Real packets from a simulated mobile UE or bridged BNG
                # session -- belongs to that other domain's own pipeline,
                # not this one's detection. See _MOBILE_UE_SUBNET's/
                # _BNG_NETWORK_SUBNET's comments.
                continue
            meta = self._fresh_meta(src_ip, result["dst_ip"])
            dpid = meta["dpid"] if meta else fallback_dpid
            in_port = meta["in_port"] if meta else fallback_in_port

            events.append(TelemetryEvent(
                domain=self.domain_name,
                device_id=str(dpid),
                src_ip=src_ip,
                dst_ip=result["dst_ip"],
                dst_port=result["dst_port"],
                protocol=result["protocol"],
                pps=pps,
                bps=pps * bytes_per_packet,
                in_port=in_port,
            ))

        self._pending.extend(events)
        return events

    def _remember_flow_meta(self, msg) -> None:
        """
        Record the L4 protocol/port for this (src_ip, dst_ip) pair so
        that later, L4-blind flow-stats volume events can be tagged
        correctly — refreshed on every sighting, regardless of which
        switch/port it came from.

        Also records its ingress (dpid, in_port), but ONLY from a
        confirmed genuine host port, and only ever once: a packet
        between two hosts on different subnets triggers packet-in at
        BOTH the attacker's switch (real host port) and the victim's
        switch (the router's port there, since the packet arrives via
        the router) — recording indiscriminately would let whichever of
        those gets processed last win, which for a cross-subnet attack
        could easily be the victim's own router-facing port. Once a good
        location is set it's never downgraded by a later non-host-port
        sighting of the same pair.
        """
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        if _is_simulated_domain_flow(ip_pkt.src, ip_pkt.dst):
            # Belongs to another simulated domain's own pipeline, not
            # this one's -- see _is_simulated_domain_flow's docstring
            # (covers reply traffic too, not just the attack direction).
            # Since on_packet_in/on_flow_stats never emit events for
            # this pair either, there's nothing downstream that would
            # ever consult metadata recorded here.
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt and (tcp_pkt.bits & tcp.TCP_RST):
            # Same reasoning as DDoSCollector: a victim's RST reply isn't
            # part of any flood — don't let it tag this (src,dst) pair's
            # metadata, or later flow-stats volume for the reply direction
            # would inherit a misleading "TCP" classification from it.
            return

        if tcp_pkt:
            # Same SYN-vs-established distinction as DDoSCollector — only
            # a bare SYN (no ACK) is a connection attempt worth feeding
            # into SYN_FLOOD; established-connection traffic shouldn't
            # keep tagging this pair's flow-stats volume as "the same
            # attack" once the handshake is done.
            is_bare_syn = (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK)
            proto = "TCP_SYN" if is_bare_syn else "TCP"
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            proto, dst_port = "UDP", udp_pkt.dst_port
        elif ip_pkt.proto == 1:
            proto, dst_port = "ICMP", 0
        else:
            proto, dst_port = "IP", 0

        key = (ip_pkt.src, ip_pkt.dst)
        meta = self._flow_meta.setdefault(key, {
            "protocol": proto, "dst_port": dst_port,
            "dpid": None, "in_port": None, "timestamp": 0.0,
        })
        meta["protocol"] = proto
        meta["dst_port"] = dst_port
        meta["timestamp"] = time.time()

        dpid, in_port = msg.datapath.id, msg.match["in_port"]

        if self._is_host_port is None or self._is_host_port(dpid, in_port):
            meta["dpid"] = dpid
            meta["in_port"] = in_port

    def _fresh_meta(self, src_ip: str, dst_ip: str):
        """_flow_meta entry for (src_ip, dst_ip) if it's younger than
        _FLOW_META_TTL, else None."""
        meta = self._flow_meta.get((src_ip, dst_ip))
        if meta and (time.time() - meta["timestamp"]) <= _FLOW_META_TTL:
            return meta
        return None

    def get_source_ingress(self, src_ip: str, dst_ip: str) -> Tuple[Optional[int], Optional[int]]:
        """
        (dpid, in_port) of the genuine HOST port this (src_ip, dst_ip)
        pair was confirmed entering on, from packet-in — works even when
        src_ip is spoofed/fabricated, since it reflects where the packet
        physically arrived, not an ARP-learned host location (a spoofed
        IP never ARPs, so LearningSwitch.get_host_location would never
        resolve it). Used to scope a distributed attack's block to the
        exact switch+port that source's traffic is actually coming
        through — NEVER network-wide, so this returns None, None (no
        fallback) whenever no confirmed host-port sighting exists yet,
        even if this pair has been seen via an inter-switch or router
        port (see _remember_flow_meta).
        """
        meta = self._fresh_meta(src_ip, dst_ip)
        if meta and meta["dpid"] is not None:
            return meta["dpid"], meta["in_port"]
        return None, None

    # ------------------------------------------------------------------
    # DomainAdapter interface
    # ------------------------------------------------------------------

    def collect(self) -> List[TelemetryEvent]:
        """Drain and return accumulated events."""
        events = self._pending.copy()
        self._pending.clear()
        return events

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # OpenFlow mitigation requires a live datapath — handled by
        # OpenFlowMitigator in the Orchestration layer.
        return False
