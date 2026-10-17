from time import time

from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class DDoSCollector:
    """
    Aggregates packet-in traffic per destination (dst_ip, dst_port, protocol)
    rather than per full (src, dst, port, protocol) flow.

    Keying by destination only — instead of including src_ip in the key —
    matters for spoofed-source / distributed floods: a single-source flood
    repeats the same key across packets, so a per-flow key works fine, but a
    spoofed attack uses a different source on (almost) every packet, so a
    src-inclusive key would never see the same key twice and could never
    compute a rate. Aggregating by destination, with a per-source packet
    breakdown inside that window, captures both cases: a dominant single
    source (low entropy) or many evenly-spread sources (high entropy).
    """

    def __init__(self):
        self.stats = {}

    def process_packet(self, msg):

        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return None

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt and (tcp_pkt.bits & tcp.TCP_RST):
            # A victim sends RST in plain response to an unwanted/closed-
            # port SYN — that's it defending itself, not a second attack.
            # hping3 (and similar floods) vary the source port per probe,
            # so each reply burst lands on a different ephemeral dst_port
            # and gets misread as its own short-lived SYN_FLOOD otherwise.
            return None

        protocol = "IP"
        dst_port = 0

        if tcp_pkt:
            # Bare SYN (no ACK) is a connection attempt — the actual
            # signature of a SYN flood. Once the handshake completes,
            # later packets carry ACK and are just normal traffic on an
            # established connection, not worth tripping SYN_FLOOD on
            # every cycle just because it's TCP.
            is_bare_syn = (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK)
            protocol = "TCP_SYN" if is_bare_syn else "TCP"
            dst_port = tcp_pkt.dst_port

        elif udp_pkt:
            protocol = "UDP"
            dst_port = udp_pkt.dst_port

        elif ip_pkt.proto == 1:
            protocol = "ICMP"

        key = (
            ip_pkt.dst,
            dst_port,
            protocol
        )

        now = time()

        entry = self.stats.get(key)

        if entry is None:
            entry = {
                "src_packets": {},
                "bytes": 0,
                "packets": 0,
                "timestamp": now
            }
            self.stats[key] = entry

        entry["src_packets"][ip_pkt.src] = entry["src_packets"].get(ip_pkt.src, 0) + 1
        entry["packets"] += 1
        entry["bytes"] += len(msg.data)

        delta = now - entry["timestamp"]

        if delta < 1:
            return None

        result = {
            "dst_ip": key[0],
            "dst_port": key[1],
            "protocol": key[2],
            "pps": entry["packets"] / delta,
            "bps": entry["bytes"] / delta,
            "src_pps": {
                src: count / delta
                for src, count in entry["src_packets"].items()
            },
        }

        entry["src_packets"] = {}
        entry["packets"] = 0
        entry["bytes"] = 0
        entry["timestamp"] = now

        return result
