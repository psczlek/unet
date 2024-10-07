from typing import Final

from unet.flag import Group, OptionFlag

__all__ = ["ICMP_COMMON_FLAGS"]


ICMP_COMMON_FLAGS: Final = {
    "ICMP Common": Group(
        description="ICMP/ICMPv6",
        arguments={
            "icmp_type": OptionFlag(
                long="--icmp-type",
                help="set ICMP type",
                type=int,
                default=None,
                required=False,
                metavar="<type>"
            ),
            "icmp_code": OptionFlag(
                long="--icmp-code",
                help="set ICMP code",
                type=int,
                default=None,
                required=False,
                metavar="<code>",
            ),
            "icmp_sum": OptionFlag(
                long="--icmp-sum",
                help="set ICMP checksum",
                type=lambda flag: int(flag, 16),
                default=None,
                required=False,
                metavar="<sum>",
            ),
        }
    )
}
