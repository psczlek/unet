import socket
import struct
from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import TCP, checksum
    from scapy.packet import Raw, raw
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, rand
from unet.modules.ping.ip import ip_send
from unet.modules.ping.ip6 import ip6_send

__all__ = ["TCP_FLAGS", "tcp_send", "register_send_routine", "create_method"]


TCP_FLAGS: Final = {
    "TCP": Group(
        arguments={
            "tcp_seq": OptionFlag(
                long="--tcp-seq",
                help="set TCP sequence number",
                type=int,
                default=None,
                required=False,
                metavar="<seq>",
            ),
            "tcp_ack": OptionFlag(
                long="--tcp-ack",
                help="set TCP acknowledgement number",
                type=int,
                default=None,
                required=False,
                metavar="<ack>",
            ),
            "tcp_hlen": OptionFlag(
                long="--tcp-hlen",
                help="set TCP header length",
                type=int,
                default=None,
                required=False,
                metavar="<hlen>",
            ),
            "tcp_rsvrd": OptionFlag(
                long="--tcp-rsvd",
                help="set TCP reserved bits",
                type=int,
                default=None,
                required=False,
                metavar="<val>",
            ),
            "tcp_flags": OptionFlag(
                long="--tcp-flags",
                help="set TCP flags",
                default=None,
                required=False,
                metavar="<fin,syn,...>",
            ),
            "tcp_win": OptionFlag(
                long="--tcp-win",
                help="set TCP window size",
                type=int,
                default=None,
                required=False,
                metavar="<win>",
            ),
            "tcp_sum": OptionFlag(
                long="--tcp-sum",
                help="set TCP checksum",
                type=lambda flag: int(flag, 16),
                default=None,
                required=False,
                metavar="<checksum>",
            ),
            "tcp_uptr": OptionFlag(
                long="--tcp-uptr",
                help="set TCP urgent pointer",
                type=int,
                default=None,
                required=False,
                metavar="<ptr>",
            ),
            "tcp_opt": OptionFlag(
                long="--tcp-opt",
                help="set TCP options: [nop, eol, mss, ws, ts, sackp, sack]",
                type=lambda flag: flag.strip().split(","),
                default=None,
                required=False,
                metavar="<opts>",
            ),
            "tcp_opt_mss_mss": OptionFlag(
                long="--tcp-opt-mss-mss",
                help="set maximum segment size for the TCP's MSS option",
                type=int,
                default=-1,
                required=False,
                metavar="<mss>",
            ),
            "tcp_opt_ws_ws": OptionFlag(
                long="--tcp-opt-ws-ws",
                help="set window scale for the TCP's Window Scale option",
                type=int,
                default=4,
                required=False,
                metavar="<ws>"
            ),
            "tcp_opt_ts_val": OptionFlag(
                long="--tcp-opt-ts-val",
                help="set timestamp value for the TCP's timestamp option",
                type=int,
                default=rand(32),
                required=False,
                metavar="<val>"
            ),
            "tcp_opt_ts_ecr": OptionFlag(
                long="--tcp-opt-ts-ecr",
                help="set echo reply for the TCP's timestamp option",
                type=int,
                default=0,
                required=False,
                metavar="<ecr>"
            ),
            "tcp_opt_sack_right": OptionFlag(
                long="--tcp-opt-sack-right",
                help="set SACK right edges",
                type=lambda flag: [int(e) for e in flag.strip().split(",")],
                default=[rand(32) for _ in range(2)],
                required=False,
                metavar="<r1,r2,...>",
            ),
            "tcp_opt_sack_left": OptionFlag(
                long="--tcp-opt-sack-left",
                help="set SACK left edges",
                type=lambda flag: [int(e) for e in flag.strip().split(",")],
                default=[rand(32) for _ in range(2)],
                required=False,
                metavar="<l1,l2,...>",
            ),
        }
    )
}


def tcp_send(opt: PingOptions, data: bytes | None = None) -> None:
    # Build packet
    tcp = TCP()

    tcp.sport = opt.sport if opt.sport is not None else rand(16)
    tcp.dport = opt.dport if opt.dport is not None else rand(16)
    tcp.seq = opt.tcp_seq if opt.tcp_seq is not None else rand(32)
    tcp.ack = opt.tcp_ack if opt.tcp_ack is not None else 0
    tcp.dataofs = opt.tcp_hlen if opt.tcp_hlen is not None else 5
    tcp.reserved = opt.tcp_rsvrd if opt.tcp_rsvrd is not None else 0
    if opt.tcp_flags is not None:
        try:
            flags = int(opt.tcp_flags, 16)
        except ValueError:
            flags = 0
            if not isinstance(opt.tcp_flags, list):
                flag_list = opt.tcp_flags.strip().split(",")
            else:
                flag_list = opt.tcp_flags
            tcp_flags_map = {
                0x1: {"f", "fin"},
                0x2: {"s", "syn"},
                0x4: {"r", "rst"},
                0x8: {"p", "psh"},
                0x10: {"a", "ack"},
                0x20: {"u", "urg"},
                0x40: {"e", "ece"},
                0x80: {"c", "cwr"},
                0x100: {"n", "aecn"},
            }

            for flag in flag_list:
                flag = flag.lower()
                for v, s in tcp_flags_map.items():
                    if flag in s:
                        flags |= v

        tcp.flags = flags
    else:
        tcp.flags = 0x2
    tcp.window = opt.tcp_win if opt.tcp_win is not None else rand(16)
    tcp.chksum = opt.tcp_sum if opt.tcp_sum is not None else 0
    tcp.urgptr = opt.tcp_uptr if opt.tcp_uptr is not None else 0

    # Add options
    if opt.tcp_opt is not None:
        tcp_opts = []
        tcp_opt_map = {
            "eol": ("EOL", None),
            "nop": ("NOP", None),
            "mss": ("MSS", opt.tcp_opt_mss_mss if opt.tcp_opt_mss_mss != -1 else opt.mtu - 20 - (20 if not opt.ip6 else 40)),
            "ws": ("WScale", opt.tcp_opt_ws_ws),
            "ts": ("Timestamp", (opt.tcp_opt_ts_val, opt.tcp_opt_ts_ecr)),
            "sackp": ("SAckOK", ""),
            "sack": ("SAck", tuple(edge for pair in zip(opt.tcp_opt_sack_left, opt.tcp_opt_sack_right) for edge in pair)),
        }

        for name in opt.tcp_opt:
            name = name.lower()

            if name not in tcp_opt_map:
                continue

            tcp_opt = tcp_opt_map[name]
            tcp_opts.append(tcp_opt)

        tcp.options = tcp_opts

        if opt.tcp_hlen is None:
            tcp.dataofs = len(raw(tcp)) >> 2

    # Add data
    if data is not None:
        tcp = tcp / Raw(data)

    if opt.tcp_sum is None:
        if not opt.ip6:
            ph = struct.pack(
                "!4s4sBBH",
                socket.inet_pton(socket.AF_INET, opt.ip_src),
                socket.inet_pton(socket.AF_INET, opt.ip_dst),
                0,
                6,
                len(raw(tcp)),
            )
        else:
            ph = struct.pack(
                "!16s16sI3xB",
                socket.inet_pton(socket.AF_INET6, opt.ip_src),
                socket.inet_pton(socket.AF_INET6, opt.ip_dst),
                len(raw(tcp)),
                6
            )

        chksum = checksum(ph + raw(tcp))
        tcp.chksum = chksum

    # Send packet
    if not opt.ip6:
        if opt.ip_proto is None:
            opt.ip_proto = 6
    else:
        if opt.ip_nh is None:
            opt.ip_nh = 6

    tcp = raw(tcp)

    if not opt.ip6:
        ip_send(opt, tcp)
    else:
        ip6_send(opt, tcp)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "tcp", tcp_send


def create_method() -> str:
    return "tcp"
