import socket
import struct
from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import UDP, checksum
    from scapy.packet import Raw, raw
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, rand
from unet.modules.ping.ip import ip_send
from unet.modules.ping.ip6 import ip6_send

__all__ = ["UDP_FLAGS", "udp_send", "register_send_routine", "create_method"]


UDP_FLAGS: Final = {
    "UDP": Group(
        arguments={
            "udp_len": OptionFlag(
                long="--udp-len",
                help="set UDP length",
                type=int,
                default=None,
                required=False,
                metavar="<len>"
            ),
            "udp_sum": OptionFlag(
                long="--udp-sum",
                help="set UDP checksum",
                type=lambda flag: int(flag, 16),
                default=None,
                required=False,
                metavar="<sum>"
            ),
        }
    ),
}


def udp_send(opt: PingOptions, data: bytes | None = None) -> None:
    # Build packet
    udp = UDP()

    udp.sport = opt.sport if opt.sport is not None else rand(16)
    udp.dport = opt.dport if opt.dport is not None else rand(16)
    udp.len = opt.udp_len if opt.udp_len is not None else 0
    udp.chksum = opt.udp_sum if opt.udp_sum is not None else 0

    # Add data
    if data is not None:
        udp = udp / Raw(data)

    if opt.udp_len is None:
        udp.len = len(udp)

    if opt.udp_sum is None:
        if not opt.ip6:
            ph = struct.pack(
                "!4s4sBBH",
                socket.inet_pton(socket.AF_INET, opt.ip_src),
                socket.inet_pton(socket.AF_INET, opt.ip_dst),
                0,
                17,
                len(raw(udp)),
            )
        else:
            ph = struct.pack(
                "!16s16sI3xB",
                socket.inet_pton(socket.AF_INET6, opt.ip_src),
                socket.inet_pton(socket.AF_INET6, opt.ip_dst),
                len(raw(udp)),
                17,
            )

        chksum = checksum(ph + raw(udp))
        udp.chksum = chksum

    # Send packet
    if not opt.ip6:
        if opt.ip_proto is None:
            opt.ip_proto = 17
    else:
        if opt.ip_nh is None:
            opt.ip_nh = 17

    udp = raw(udp)

    if not opt.ip6:
        ip_send(opt, udp)
    else:
        ip6_send(opt, udp)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "udp", udp_send


def create_method() -> str:
    return "udp"
