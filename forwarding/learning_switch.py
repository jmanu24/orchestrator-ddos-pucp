import logging

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp

import config.settings as settings
from core.log_format import log_line
from forwarding.syn_twin import syn_twin_match


class LearningSwitch:

    # Lifetime, in seconds, of the provisional flow installed for a
    # destination that hasn't been validated yet. Only a few detection
    # cycles long (COLLECT_INTERVAL=0.5s in config/settings.py), so it
    # never amounts to a long-term trust decision — it just keeps a
    # high-rate flood from punting every single packet to the controller
    # (which would starve the detection pipeline itself of CPU time) while
    # validation keeps being re-checked on every expiry.
    PROVISIONAL_TIMEOUT = 2

    def __init__(self, is_blocked=None, is_validated=None, is_interswitch_port=None, logger=None):

        self.mac_to_port = {}

        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)

        # Optional Callable[[src_ip, dst_ip, dst_port, protocol], bool],
        # queried before installing a new IP forwarding rule. Lets the
        # Orchestration layer veto caching traffic for a flow that's
        # already individually blocked, or whose destination is under an
        # active destination-wide block.
        self._is_blocked = is_blocked

        # Optional Callable[[src_ip, dst_ip], bool], queried before
        # installing an IP forwarding rule. Until this exact (src_ip,
        # dst_ip) flow has been through at least one full detection cycle
        # without src_ip triggering an attack toward dst_ip, no rule —
        # permit or block — gets cached for it; packets are still forwarded,
        # just one at a time via packet-out, going through the controller
        # every time until validation completes. Scoped per-flow, not per-
        # destination, so one source under attack toward a shared
        # destination doesn't force every OTHER source's already-clean
        # traffic toward that same destination back through this
        # provisional path too.
        self._is_validated = is_validated

        # Optional Callable[[dpid, port_no], bool] — True if that port is a
        # discovered switch-switch link. A packet with no matching flow
        # rule triggers packet-in on every switch along its path, not just
        # the one nearest the actual source, so this is needed to tell
        # "this IP is truly attached here" apart from "this switch just
        # forwarded the packet along".
        self._is_interswitch_port = is_interswitch_port

        # ip -> mac, and mac -> (dpid, port) where that mac was last seen
        # arriving on a *non* switch-switch port — i.e. the genuine
        # edge/host attachment point, not just any hop the traffic passed
        # through. Used by the Orchestration layer to scope a mitigation
        # block to the switch+port actually closest to an attacker.
        self._ip_to_mac = {}
        self._host_location = {}

        # (dpid, port) pairs where the router's interface lives, learned
        # from ARP replies/requests whose src_ip ends in ".1" (this
        # codebase's gateway-IP convention). Needed to tell a genuine HOST
        # port apart from a router-facing one: both pass the "not an
        # inter-switch link" test that _host_location uses, but a block
        # must never be scoped to the router's port — that's not where
        # an attacker is, it's where ALL cross-subnet traffic legitimately
        # enters a victim's switch.
        self._router_ports = set()

    def get_host_location(self, ip):
        """(dpid, port) this IP's mac was last confirmed attached to via a
        non switch-switch port, or None if not known yet."""
        mac = self._ip_to_mac.get(ip)
        if mac is None:
            return None
        return self._host_location.get(mac)

    def is_host_port(self, dpid, port_no):
        """
        True only for a port a real host is directly attached to — False
        for an inter-switch link AND for the router's own interface.
        Mitigation scoping for a distributed/spoofed attack (which has no
        ARP-learnable identity to fall back on, unlike a single real
        attacker) must use this instead of just "not inter-switch", or it
        would happily scope a block to whichever switch+port a spoofed
        packet happened to arrive on last — which, for any cross-subnet
        attack, is the VICTIM's own router-facing port, not the
        attacker's.
        """
        if self._is_interswitch_port and self._is_interswitch_port(dpid, port_no):
            return False
        return (dpid, port_no) not in self._router_ports

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        buffer_id=None,
        idle_timeout=0,
        hard_timeout=0):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        )

        datapath.send_msg(mod)

    def switch_features_handler(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )

        self._logger.info(
            log_line("enterprise", "FORWARDING", "TABLE_MISS_INSTALLED", f"switch={datapath.id}")
        )

    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # ---------------------------------
        # EXTRAER IPv4
        # ---------------------------------

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        # ---------------------------------
        # UBICACION REAL DEL HOST (para escopar mitigacion)
        # ---------------------------------

        # ip -> mac is learned ONLY from ARP, never from an arbitrary IP
        # packet's Ethernet header. ARP never crosses a router — it's
        # strictly local to one subnet/link — so it always reflects a
        # host's real mac. A routed IP packet's eth.src, by contrast,
        # changes at every hop (the router re-frames it with its own
        # outgoing-interface mac), so trusting that would associate the
        # ORIGINAL source's IP with the ROUTER's mac at the hop closest to
        # the destination — scoping a block to the wrong end of the path.
        if arp_pkt:
            self._ip_to_mac[arp_pkt.src_ip] = src

        is_interswitch = bool(
            self._is_interswitch_port and self._is_interswitch_port(dpid, in_port)
        )
        if not is_interswitch:
            # This mac just arrived on a genuine edge port — it's truly
            # attached here, not just passing through. An entry learned
            # this way is never overwritten by an interswitch hop's view
            # of the same mac later. Tracked for every mac seen (hosts AND
            # routers), independent of ip_to_mac above.
            self._host_location[src] = (dpid, in_port)

            # Gateway-IP convention (x.x.x.1) used elsewhere in this
            # codebase to identify the router — its ARP traffic on this
            # port marks (dpid, in_port) as the router's own interface,
            # never a real host's.
            if arp_pkt and arp_pkt.src_ip.endswith(".1"):
                self._router_ports.add((dpid, in_port))

        # ---------------------------------
        # DESTINO BAJO BLOQUEO DISTRIBUIDO
        # ---------------------------------

        if ip_pkt and self._is_blocked:

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:
                proto, dst_port = "TCP", tcp_pkt.dst_port
            elif udp_pkt:
                proto, dst_port = "UDP", udp_pkt.dst_port
            elif ip_pkt.proto == 1:
                proto, dst_port = "ICMP", 0
            else:
                proto, dst_port = "IP", 0

            if self._is_blocked(ip_pkt.src, ip_pkt.dst, dst_port, proto):
                # Drop silently — no forwarding rule, no packet-out. This
                # exact flow (or its whole destination, for a network-
                # wide block) is already blocked; caching a forwarding
                # rule here would just be a flow table entry that can
                # never deliver traffic.
                return

        # ---------------------------------
        # INSTALAR FLOW
        # ---------------------------------

        if out_port != ofproto.OFPP_FLOOD:

            if ip_pkt:

                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )

                if self._is_validated is None or self._is_validated(ip_pkt.src, ip_pkt.dst):

                    # hard_timeout forces this rule to expire — and the
                    # next packet to trigger a fresh packet-in — even
                    # under continuous traffic that would otherwise keep
                    # resetting idle_timeout forever. Without it, a flow
                    # cached from e.g. a ping could absorb a completely
                    # different protocol's traffic between the same two
                    # hosts later, and OpenFlowAdapter's protocol/port
                    # metadata for that pair would never get refreshed.
                    self.add_flow(
                        datapath,
                        priority=settings.FORWARDING_PRIORITY,
                        match=match,
                        actions=actions,
                        idle_timeout=60,
                        hard_timeout=settings.VALIDATED_FLOW_HARD_TIMEOUT
                    )

                    if settings.SYN_TWIN_ENABLED:
                        # Same output and lifetime as the rule above, one
                        # priority higher, matching only bare SYNs: its
                        # counters are this pair's exact SYN rate, which the
                        # L3 rule's can't tell apart from its other traffic
                        # (config/settings.py's SYN_TWIN_PRIORITY). Only for
                        # validated (long-lived) rules: a provisional rule
                        # lives 2s and keeps sending packets to the
                        # controller, where each one is tagged individually.
                        self.add_flow(
                            datapath,
                            priority=settings.SYN_TWIN_PRIORITY,
                            match=syn_twin_match(parser, ip_pkt.src, ip_pkt.dst),
                            actions=actions,
                            idle_timeout=60,
                            hard_timeout=settings.VALIDATED_FLOW_HARD_TIMEOUT
                        )

                else:

                    # Not validated yet — install a short-lived provisional
                    # rule instead of caching nothing. It expires on its
                    # own well before the next detection cycle runs, so it
                    # never becomes a standing permit; it just offloads the
                    # switch so a flood doesn't starve the controller.
                    self.add_flow(
                        datapath,
                        priority=settings.FORWARDING_PRIORITY,
                        match=match,
                        actions=actions,
                        idle_timeout=0,
                        hard_timeout=self.PROVISIONAL_TIMEOUT
                    )

            else:

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst,
                    eth_type=eth.ethertype
                )

                self.add_flow(
                    datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    idle_timeout=60,
                    hard_timeout=0
                )

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)