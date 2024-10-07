from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet6 import (ICMPv6DestUnreach, ICMPv6EchoReply,
                                    ICMPv6EchoRequest, ICMPv6PacketTooBig,
                                    ICMPv6ParamProblem, ICMPv6TimeExceeded,
                                    checksum)
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

        },
    ),
}


def icmp6_send(opt: PingOptions, data: bytes | None) -> None:
    pass


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "icmp6", icmp6_send


def create_method() -> str:
    return "icmp6"
