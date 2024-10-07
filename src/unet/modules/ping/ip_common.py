from typing import Final

from unet.flag import Group, OptionFlag

IP_COMMON_FLAGS: Final = {
    "IP Common": Group(
        description="IPv4/IPv6",
        arguments={
            "ip_ver": OptionFlag(
                long="--ip-ver",
                help="set IP version",
                type=int,
                default=None,
                required=False,
                metavar="<version>",
            ),
            "ip_src": OptionFlag(
                long="--ip-src",
                help="set IP source address",
                type=str,
                default=None,
                required=False,
                metavar="<address>",
            ),
            "ip_dst": OptionFlag(
                long="--ip-dst",
                help="set IP destination address. Can be used instead of 'target'",
                type=lambda flag: flag.strip().split(","),
                default=None,
                required=False,
                metavar="<address>",
            ),
        }
    )
}
