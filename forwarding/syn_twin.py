"""Match for the SYN twin rule (see config/settings.py's SYN_TWIN_PRIORITY).

A bare SYN is SYN set and ACK clear: value 0x02 under mask 0x12. OpenFlow 1.3
has no standard TCP-flags match; Open vSwitch accepts the ONF experimenter
OXM `tcp_flags`, which Ryu 4.34 encodes (verified against Open vSwitch 3.7.1:
`ovs-ofctl ofp-parse` decodes it as `tcp,nw_src=...,nw_dst=...,
tcp_flags=+syn-ack`). The Nicira `tcp_flags_nxm` variant is rejected with
OFPBMC_BAD_PREREQ, so it is not used.
"""

TCP_SYN_BIT = 0x02
TCP_ACK_BIT = 0x10
BARE_SYN_FLAGS = (TCP_SYN_BIT, TCP_SYN_BIT | TCP_ACK_BIT)  # (value, mask)


def syn_twin_match(parser, ipv4_src: str, ipv4_dst: str):
    """OFPMatch for the twin of the L3 rule between these two hosts."""
    return parser.OFPMatch(
        eth_type=0x0800,
        ipv4_src=ipv4_src,
        ipv4_dst=ipv4_dst,
        ip_proto=6,
        tcp_flags=BARE_SYN_FLAGS,
    )
