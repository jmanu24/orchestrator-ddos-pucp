"""
bng_flood.py — kernel-native TCP-SYN / UDP flood generator for the
Broadband domain's IPoE subscriber sessions (macvlanN interfaces),
spawned by bng_subscriber_agent.py's Subscriber.start_attack() in place
of hping3.

Why not hping3: confirmed on real runs that hping3 cannot reliably
deliver traffic here at all, under EITHER access mode this project has
used. Under an earlier PPPoE-based design (ppp-subN interfaces), with
no -I it auto-selected the wrong egress interface via its own naive
heuristic (observed picking the VM's other, unrelated NIC, ignoring the
`ip rule from <subscriber-ip>` policy route a REAL kernel route lookup
does honor); with -I ppp-subN it correctly identified the interface
(its own banner reported it) but TX counters never moved past the PPP
LCP/IPCP handshake baseline -- hping3 injects packets via a raw-socket
path that assumes Ethernet L2 framing, which a PPP netdevice
(ARPHRD_PPP) doesn't have. Under the current IPoE design (a plain
Ethernet-type macvlanN interface, no such framing mismatch), hping3
STILL failed with -I bound to the right interface -- its own banner and
transmit-count claims looked normal, but the destination's BNG-side
session interface counter never moved at all, most likely an ARP
resolution failure in hping3's own raw-socket send path.

This script sidesteps the problem entirely by using ordinary kernel
sockets bound to the subscriber's own IP instead of any raw-socket L2
trick. The kernel's real FIB lookup (ip_route_output_flow) considers
the bound source address, correctly matches the per-subscriber `ip
rule` that bng_subscriber_agent.py's Subscriber._add_source_route()
already sets up, and the kernel's own network stack performs ARP
resolution and framing itself -- exactly the same mechanism that
already made `ping` work correctly throughout this project's
debugging, on every interface type it's been tried on.

TCP_SYN mode does not complete the handshake: every iteration opens a
fresh non-blocking socket, binds it to the subscriber's IP, fires one
connect() (the kernel emits exactly one real SYN for this), and closes
the socket immediately -- a real half-open-connection flood, kernel-
emitted rather than hand-crafted, functionally equivalent input for
DDoSDetectionEngine's own pps-based classification.

UDP mode opens a single UDP socket bound to the subscriber's IP and
loops sendto() at the target rate.

ICMP is NOT handled here -- bng_subscriber_agent.py shells out to the
system `ping` binary for that instead (already confirmed working
in-kernel over these interfaces since early in the PPP debugging).

Usage:
  python3 bng_flood.py --protocol tcp_syn --src-ip 10.20.0.40 \\
      --dst-ip 10.10.0.100 --dst-port 443 [--pps 5.0]
Omit --pps for an uncontrolled, fastest-possible flood.
"""

import argparse
import socket
import sys
import time

_UDP_PAYLOAD = b"\x00" * 32


def _sleep_for_rate(pps: float) -> None:
    if pps is not None and pps > 0:
        time.sleep(1.0 / pps)


def tcp_syn_flood(src_ip: str, dst_ip: str, dst_port: int, pps: float) -> None:
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((src_ip, 0))
            # Non-blocking connect() always raises EINPROGRESS/EWOULDBLOCK
            # here -- that's expected and fine: the kernel has already
            # emitted the real SYN packet by this point, which is all
            # this scenario needs. We deliberately never wait for/
            # complete the handshake.
            sock.connect_ex((dst_ip, dst_port))
        except OSError:
            pass
        finally:
            sock.close()
        _sleep_for_rate(pps)


def udp_flood(src_ip: str, dst_ip: str, dst_port: int, pps: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((src_ip, 0))
    # Unlike tcp_syn_flood's own except OSError (EINPROGRESS/EWOULDBLOCK
    # on every non-blocking connect(), genuinely expected there), a
    # sendto() failure here is NOT expected in the normal case -- print
    # it, once, rather than swallow it silently forever. Confirmed on a
    # real run: dst_port=0 makes EVERY sendto() call here fail with
    # `OSError: [Errno 22] Invalid argument` (a UDP sendto() DESTINATION
    # port of 0 is invalid on Linux, unlike bind()'s own port 0 meaning
    # "pick one"), and a bare `except OSError: pass` here previously made
    # that indistinguishable from a working flood in every signal this
    # project had -- process alive, high CPU (an all-out retry loop with
    # nothing ever slowing it down), no exception anywhere. Only prints
    # once (not per-packet) to stay usable at flood rate; the caller
    # (bng_subscriber_agent.py) no longer discards this process's
    # stderr, see its own comment.
    _warned = False
    while True:
        try:
            sock.sendto(_UDP_PAYLOAD, (dst_ip, dst_port))
        except OSError as exc:
            if not _warned:
                print(f"[bng_flood] sendto({dst_ip}:{dst_port}) failing: {exc}", file=sys.stderr, flush=True)
                _warned = True
        _sleep_for_rate(pps)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--protocol", required=True, choices=["tcp_syn", "udp"])
    p.add_argument("--src-ip", required=True)
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--dst-port", type=int, required=True)
    p.add_argument("--pps", type=float, default=None, help="omit for an unbounded flood")
    args = p.parse_args()

    if sys.platform != "linux":
        print("ERROR: needs Linux (kernel routing/PPP specifics assumed).", file=sys.stderr)
        sys.exit(1)

    if args.protocol == "tcp_syn":
        tcp_syn_flood(args.src_ip, args.dst_ip, args.dst_port, args.pps)
    else:
        udp_flood(args.src_ip, args.dst_ip, args.dst_port, args.pps)


if __name__ == "__main__":
    main()
