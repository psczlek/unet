import struct
import socket
from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet6 import (ICMPv6DestUnreach, ICMPv6EchoReply,
                                    ICMPv6EchoRequest, ICMPv6PacketTooBig,
                                    ICMPv6ParamProblem, ICMPv6TimeExceeded,
                                    ICMPv6Unknown, checksum)
    from scapy.packet import Raw, raw
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, rand
from unet.modules.ping.ip6 import ip6_send

__all__ = [
    "ICMP6_FLAGS",
    "icmp6_send",
    "register_send_routine",
    "create_method",
]


ICMP6_FLAGS: Final = {
    "ICMPv6": Group(
        arguments={
            # Echo
            "icmp6_id": OptionFlag(
                long="--icmp6-id",
                help="set ICMPv6 identifier",
                type=int,
                default=None,
                required=False,
                metavar="<id>",
            ),
            "icmp6_seq": OptionFlag(
                long="--icmp6-seq",
                help="set ICMPv6 sequence number",
                type=int,
                default=None,
                required=False,
                metavar="<seq>",
            ),

            # Destination Unreachable, Time Exceeded
            "icmp6_unused": OptionFlag(
                long="--icmp6-unused",
                help="set ICMPv6 unused field",
                type=int,
                default=None,
                required=False,
                metavar="<x>",
            ),

            # Packet Too Big
            "icmp6_mtu": OptionFlag(
                long="--icmp6-mtu",
                help="set ICMPv6 MTU",
                type=int,
                default=None,
                required=False,
                metavar="<mtu>",
            ),

            # Parameter Problem
            "icmp6_ptr": OptionFlag(
                long="--icmp6-ptr",
                help="set ICMPv6 pointer",
                type=int,
                default=None,
                required=False,
                metavar="<ptr>",
            ),
        },
    ),
}


def icmp6_send(opt: PingOptions, data: bytes | None) -> None:
    # Build packet
    icmp_pool = {
        1: ICMPv6DestUnreach(),
        2: ICMPv6PacketTooBig(),
        3: ICMPv6TimeExceeded(),
        4: ICMPv6ParamProblem(),
        128: ICMPv6EchoRequest(),
        129: ICMPv6EchoReply(),
    }
    try:
        icmp = icmp_pool[opt.icmp_type]
    except KeyError:
        icmp = ICMPv6EchoRequest()

    icmp.type = opt.icmp_type if opt.icmp_type is not None else 128
    icmp.code = opt.icmp_code if opt.icmp_code is not None else 0
    icmp.cksum = opt.icmp_sum if opt.icmp_sum is not None else 0

    if icmp.type in {1, 3}:
        icmp.unused = opt.icmp6_unused if opt.icmp6_unused is not None else 0

    if icmp.type == 2:
        icmp.mtu = opt.icmp6_mtu if opt.icmp6_mtu is not None else (opt.mtu - 40)

    if icmp.type == 4:
        icmp.ptr = opt.icmp6_ptr if opt.icmp6_ptr is not None else 0

    if icmp.type in {128, 129}:
        if opt.icmp6_id is None:
            opt.icmp6_id = rand(16)

        if opt.icmp6_seq is None:
            opt.icmp6_seq = 0

        icmp.id = opt.icmp6_id
        icmp.seq = opt.icmp6_seq

        opt.icmp6_seq += 1

    # Add data
    if data is not None:
        icmp = icmp / Raw(data)

    if opt.icmp_sum is None:
        ph = struct.pack(
            "!16s16sI3xB",
            socket.inet_pton(socket.AF_INET6, opt.ip_src),
            socket.inet_pton(socket.AF_INET6, opt.ip_dst),
            len(raw(icmp)),
            58,
        )

        chksum = checksum(ph + raw(icmp))
        icmp.cksum = chksum

    # Send packet
    if opt.ip_nh is None:
        opt.ip_nh = 58

    icmp = raw(icmp)
    ip6_send(opt, icmp)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "icmp6", icmp6_send


def create_method() -> str:
    return "icmp6"
