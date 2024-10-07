from typing import Final

from unet.flag import Group, OptionFlag

__all__ = ["TCP_UDP_COMMON_FLAGS"]


TCP_UDP_COMMON_FLAGS: Final = {
    "TCP/UDP Common": Group(
        description="TCP/UDP",
        arguments={
            "sport": OptionFlag(
                short="-s",
                long="--sport",
                help="set source port",
                type=int,
                default=None,
                required=False,
                metavar="<port number>",
            ),
            "dport": OptionFlag(
                short="-p",
                long="--dport",
                help="set destination port",
                type=int,
                default=None,
                required=False,
                metavar="<port number>",
            ),
        }
    ),
}
