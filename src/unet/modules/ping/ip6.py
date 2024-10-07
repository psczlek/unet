import time
from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet6 import IPv6, fragment6
    from scapy.packet import Raw, raw
    from scapy.sendrecv import send
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, if_addr

__all__ = ["IP6_FLAGS", "ip6_send", "register_send_routine", "create_method"]


IP6_FLAGS: Final = {
    "IPv6": Group(
        arguments={
            "ip_tcls": OptionFlag(
                long="--ip-tcls",
                help="set IP traffic class",
                type=lambda flag: int(flag, 16),
                required=False,
                default=None,
                metavar="<class>",
            ),
            "ip_flbl": OptionFlag(
                long="--ip-flbl",
                help="set IP flow label",
                type=lambda flag: int(flag, 16),
                required=False,
                default=None,
                metavar="<label>",
            ),
            "ip_plen": OptionFlag(
                long="--ip-plen",
                help="set IP payload length",
                type=int,
                required=False,
                default=None,
                metavar="<len>",
            ),
            "ip_nh": OptionFlag(
                long="--ip-nh",
                help="set IP next header",
                type=int,
                required=False,
                default=None,
                metavar="<nh>",
            ),
            "ip_hop": OptionFlag(
                long="--ip-hop",
                help="set IP hop limit",
                type=int,
                required=False,
                default=None,
                metavar="<hop>",
            ),
        }
    ),
}


def ip6_send(opt: PingOptions, data: bytes | None = None) -> None:
    # Build packet
    ip = IPv6()

    ip.version = opt.ip_ver if opt.ip_ver is not None else 6
    ip.tc = opt.ip_tcls if opt.ip_tcls is not None else 0
    ip.fl = opt.ip_flbl if opt.ip_flbl is not None else 0
    ip.plen = opt.ip_plen if opt.ip_plen is not None else len(data) if data is not None else 0
    ip.nh = opt.ip_nh if opt.ip_nh is not None else 255
    ip.hlim = opt.ip_hop if opt.ip_hop is not None else 255
    ip.src = opt.ip_src if opt.ip_src is not None else if_addr(opt.interface, "inet6")
    ip.dst = opt.ip_dst

    # Add data
    if data is not None:
        ip = ip / Raw(data)

    # Fragment if needed
    if len(ip) > opt.mtu:
        fragsize = opt.mtu - (len(ip) - (len(data) if data is not None else 0))
        fragments = fragment6(ip, fragsize)
    else:
        fragments = ip

    # Send packet
    send(fragments, count=1, inter=0, verbose=False)
    time.sleep(opt.delay)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "raw-ip6", ip6_send


def create_method() -> str:
    return "raw-ip6"
