from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import ICMP, checksum
    from scapy.packet import Raw, raw
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, rand
from unet.modules.ping.ip import get_random_ipv4, ip_send

__all__ = ["ICMP_FLAGS", "icmp_send", "register_send_routine", "create_method"]


ICMP_FLAGS: Final = {
    "ICMPv4": Group(
        arguments={
            # Echo
            "icmp_seq": OptionFlag(
                long="--icmp-seq",
                help="set ICMP sequence number",
                type=int,
                default=None,
                required=False,
                metavar="<seq>"
            ),
            "icmp_id": OptionFlag(
                long="--icmp-id",
                help="set ICMP identifier",
                type=int,
                default=None,
                required=False,
                metavar="<seq>"
            ),
            # Destination Unreachable, Time Exceeded, Parameter Problem,
            # Source Quench
            "icmp_unused": OptionFlag(
                long="--icmp-unused",
                help="set ICMP unused field",
                type=int,
                default=None,
                metavar="<x>",
            ),
            # Parameter Problem
            "icmp_ptr": OptionFlag(
                long="--icmp-ptr",
                help="set ICMP parameter problem pointer",
                type=int,
                default=None,
                metavar="<ptr>",
            ),
            # Redirect
            "icmp_gateway_addr": OptionFlag(
                long="--icmp-gw-addr",
                help="set ICMP redirect gateway address",
                type=str,
                default=None,
                metavar="<addr>",
            ),
            # Timestamp
            "icmp_ots": OptionFlag(
                long="--icmp-ots",
                help="set ICMP originate timestamp",
                type=int,
                default=None,
                metavar="<ts>",
            ),
            "icmp_rts": OptionFlag(
                long="--icmp-rts",
                help="set ICMP receive timestamp",
                type=int,
                default=None,
                metavar="<ts>",
            ),
            "icmp_tts": OptionFlag(
                long="--icmp-tts",
                help="set ICMP transmit timestamp",
                type=int,
                default=None,
                metavar="<ts>",
            ),
        }
    ),
}


def icmp_send(opt: PingOptions, data: bytes | None = None) -> None:
    # Build packet
    icmp = ICMP()

    icmp.type = opt.icmp_type if opt.icmp_type is not None else 8
    icmp.code = opt.icmp_code if opt.icmp_code is not None else 0
    icmp.chksum = opt.icmp_sum if opt.icmp_sum is not None else 0

    if icmp.type in {0, 8, 13, 14, 15, 16}:
        if opt.icmp_seq is None:
            opt.icmp_seq = 0

        if opt.icmp_id is None:
            opt.icmp_id = rand(16)

        icmp.seq = opt.icmp_seq
        icmp.id = opt.icmp_id

        if icmp.type in {13, 14}:
            icmp.ts_ori = opt.icmp_ots if opt.icmp_ots is not None else rand(32)
            icmp.ts_rx = opt.icmp_rts if opt.icmp_rts is not None else 0
            icmp.ts_tx = opt.icmp_tts if opt.icmp_tts is not None else rand(32)

        # Update the sequence number after each sent packet
        opt.icmp_seq += 1

    if icmp.type in {3, 11, 12, 4}:
        icmp.reserved = opt.icmp_unused if opt.icmp_unused is not None else 0

        if icmp.type == 12:
            icmp.ptr = opt.icmp_ptr if opt.icmp_ptr is not None else 0

    if icmp.type == 5:
        icmp.gw = opt.icmp_gateway_addr if opt.icmp_gateway_addr is not None else get_random_ipv4()

    # Add data
    if data is not None:
        icmp = icmp / Raw(data)

    # Calculate checksum if wasn't set
    if opt.icmp_sum is None:
        chksum = checksum(raw(icmp))
        icmp.chksum = chksum

    # Send packet

    # Set the IP protocol to ICMP
    if opt.ip_proto is None:
        opt.ip_proto = 1

    icmp = raw(icmp)
    ip_send(opt, icmp)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "icmp", icmp_send


def create_method() -> str:
    return "icmp"
