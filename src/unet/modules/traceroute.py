"""
Record the path packets take through the network to reach the destination host
"""


import secrets
import signal
import socket
import sys
import time
from argparse import Namespace
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from types import FrameType
from typing import Final

from unet.coloring import RGB, Color, Hex, supports_colors, supports_true_color
from unet.flag import FlagParser, OptionFlag, PositionalFlag
from unet.printing import eprint


def error(message: str, code: int = 1) -> None:
    precedence = (f"{Color.color('error', 'red bold')}: "
                  f"{Color.color('traceroute', 'red bold')}")
    eprint(message, exit_code=code, precedence=precedence)


try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.packet import Packet, Raw
    from scapy.sendrecv import sr1
except ModuleNotFoundError:
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

__all__ = ["main", "TracerouteResultsPerHop", "Traceroute"]


@dataclass
class TracerouteResultsPerHop:
    addrver: int
    proto: str
    packet: int = 0
    hop: int = 0
    host: str | None = None
    hostname: str | None = None
    rtt: float = 0.0
    timeout_hit: bool = False
    count: int = 0


class Traceroute:
    """
    An object that mimics the traceroute tool.
    """

    def __init__(
            self,
            dst: str,
            method: str = "icmp",
            ip6: bool = False,
    ) -> None:
        self.dst = dst
        self.method = method if method in {"icmp", "tcp", "udp"} else "icmp"
        self.ip6 = ip6

        if not self.ip6:
            self._proto_map = {"icmp": 1, "tcp": 6, "udp": 17}
        else:
            self._proto_map = {"tcp": 6, "udp": 17, "icmp": 58}
        self.dst = socket.getaddrinfo(
            self.dst,
            None,
            socket.AF_INET if not self.ip6 else socket.AF_INET6,
            proto=self._proto_map[self.method]
        )[0][4][0]

        self._tr_results: list[TracerouteResultsPerHop] = []

    def _build_packet(
            self,
            id: int,
            seq: int,
            ds: int = 0,
            ttl: int = 1,
            df: bool = False,
            src: str | None = None,
            sport: int = 39181,
            dport: int = 33435,
            rand_sport: bool = False,
            static_dport: bool = False,
            data: bytes | None = None,
    ) -> Packet:
        # Build IP
        if not self.ip6:
            ip = IP(
                tos=ds,
                id=secrets.randbelow(0xffff),
                flags=0x2 if df else 0x0,
                ttl=ttl,
                src=src,
                dst=self.dst,
            )
        else:
            ip = IPv6(
                tc=ds,
                hlim=ttl,
                src=src,
                dst=self.dst,
            )

        # Build upper layer
        upl_proto_map = {
            "icmp": (ICMP(type=8, code=0, id=id, seq=seq) if not self.ip6
                     else ICMPv6EchoRequest(id=id, seq=seq)),
            "udp": UDP(
                sport=sport if not rand_sport else secrets.randbelow(0xffff),
                dport=dport + (seq if not static_dport else 0),
            ),
            "tcp": TCP(
                sport=sport if not rand_sport else secrets.randbelow(0xffff),
                dport=dport + (seq if not static_dport else 0),
                seq=secrets.randbelow(0xffffffff),
                ack=0,
                flags=0x2,
                window=secrets.randbelow(0xffff),
                options=[
                    ("MSS", secrets.choice(tuple(range(1220, 1520, 20)))),
                    ("WScale", secrets.choice(tuple(range(2, 9)))),
                    ("SAckOK", ""),
                    ("NOP", None),
                    ("NOP", None),
                    ("EOL", None),
                ]
            ),
        }

        pkt = ip / upl_proto_map[self.method]

        # Add data
        if data is None and self.method != "tcp":
            data = b"\x00" * (40 - len(pkt))
            pkt = pkt / Raw(data)
        elif data is not None:
            pkt = pkt / Raw(data)

        return pkt

    def trace_icmp(
            self,
            first_hop: int = 1,
            max_hops: int = 64,
            count: int = 3,
            wait_threshold: float = 5.0,
            ds: int = 0,
            df: bool = False,
            src: str | None = None,
            data: bytes | None = None,
            callback: Callable[[TracerouteResultsPerHop], None] | None = None,
    ) -> None:
        if not self.ip6:
            fexpr = "ip proto 1 and (icmp[0]=0 or icmp[0]=3 or icmp[0]=11)"
        else:
            fexpr = "ip proto 58 and (icmp6[0]=1 or icmp6[0]=3 or icmp6[0]=129)"

        for hop in range(first_hop, (max_hops + 1)):
            done = False

            for p in range(0, count):
                res = TracerouteResultsPerHop(
                    socket.AF_INET if not self.ip6 else socket.AF_INET6, "icmp",
                    hop, hop, count=count)
                pkt = self._build_packet(secrets.randbelow(0xffff + p), p, ds,
                                         hop, df, src, data=data)
                sent_time = time.time()
                rec = sr1(pkt, timeout=wait_threshold, verbose=False,
                          filter=fexpr)

                if rec:
                    recv_time = time.time()
                    host = rec[IP if not self.ip6 else IPv6].src
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except socket.herror:
                        hostname = host
                    rtt = (recv_time - sent_time) * 1000

                    res.host = host
                    res.hostname = hostname
                    res.rtt = rtt

                    if res.host == self.dst:
                        done = True
                else:
                    res.timeout_hit = True

                if callback:
                    callback(res)

                self._tr_results.append(res)

            if done:
                break

    def trace_udp(
            self,
            first_hop: int = 1,
            max_hops: int = 64,
            count: int = 3,
            wait_threshold: float = 5.0,
            ds: int = 0,
            df: bool = False,
            src: str | None = None,
            sport: int = 39181,
            dport: int = 33435,
            rand_sport: bool = False,
            static_dport: bool = False,
            data: bytes | None = None,
            callback: Callable[[TracerouteResultsPerHop], None] | None = None,
    ) -> None:
        if not self.ip6:
            fexpr = "ip proto 1 and (icmp[0]=3 or icmp[0]=11)"
        else:
            fexpr = "ip proto 58 and (icmp6[0]=1 or icmp6[0]=3)"

        for hop in range(first_hop, (max_hops + 1)):
            done = False

            for p in range(0, count):
                res = TracerouteResultsPerHop(
                    socket.AF_INET if not self.ip6 else socket.AF_INET6, "icmp",
                    hop, hop, count=count)
                pkt = self._build_packet(secrets.randbelow(0xffff + p), p, ds,
                                         hop, df, src, sport, dport, rand_sport,
                                         static_dport, data)
                sent_time = time.time()
                rec = sr1(pkt, timeout=wait_threshold, verbose=False,
                          filter=fexpr)

                if rec:
                    recv_time = time.time()
                    host = rec[IP if not self.ip6 else IPv6].src
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except socket.herror:
                        hostname = host
                    rtt = (recv_time - sent_time) * 1000

                    res.host = host
                    res.hostname = hostname
                    res.rtt = rtt

                    if res.host == self.dst:
                        done = True
                else:
                    res.timeout_hit = True

                if callback:
                    callback(res)

                self._tr_results.append(res)

            if done:
                break

    def trace_tcp(
            self,
            first_hop: int = 1,
            max_hops: int = 64,
            count: int = 3,
            wait_threshold: float = 5.0,
            ds: int = 0,
            df: bool = False,
            src: str | None = None,
            sport: int = 39181,
            dport: int = 33435,
            rand_sport: bool = False,
            static_dport: bool = False,
            data: bytes | None = None,
            callback: Callable[[TracerouteResultsPerHop], None] | None = None,
    ) -> None:
        if not self.ip6:
            fexpr = ("(ip proto 1 and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or "
                     "icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))")
        else:
            fexpr = ("(ip proto 58 and (icmp6[0]=1 or icmp6[0]=2 or icmp6[0]=3 or "
                     "icmp6[0]=4)) or (tcp and (tcp[13] & 0x16 > 0x10))")

        for hop in range(first_hop, (max_hops + 1)):
            done = False

            for p in range(0, count):
                res = TracerouteResultsPerHop(
                    socket.AF_INET if not self.ip6 else socket.AF_INET6, "icmp",
                    hop, hop, count=count)
                pkt = self._build_packet(secrets.randbelow(0xffff + p), p, ds,
                                         hop, df, src, sport, dport, rand_sport,
                                         static_dport, data)
                sent_time = time.time()
                rec = sr1(pkt, timeout=wait_threshold, verbose=False,
                          filter=fexpr)

                if rec:
                    recv_time = time.time()
                    host = rec[IP if not self.ip6 else IPv6].src
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except socket.herror:
                        hostname = host
                    rtt = (recv_time - sent_time) * 1000

                    res.host = host
                    res.hostname = hostname
                    res.rtt = rtt

                    if res.host == self.dst:
                        done = True
                else:
                    res.timeout_hit = True

                if callback:
                    callback(res)

                self._tr_results.append(res)

            if done:
                break

    def trace(
            self,
            first_hop: int = 1,
            max_hops: int = 64,
            count: int = 3,
            wait_threshold: float = 5.0,
            ds: int = 0,
            df: bool = False,
            src: str | None = None,
            sport: int = 39181,
            dport: int = 33435,
            rand_sport: bool = False,
            static_dport: bool = False,
            data: bytes | None = None,
            callback: Callable[[TracerouteResultsPerHop], None] | None = None,
    ) -> None:
        if self.method == "icmp":
            self.trace_icmp(first_hop, max_hops, count, wait_threshold, ds, df,
                            src, data, callback)
        elif self.method == "udp":
            self.trace_udp(first_hop, max_hops, count, wait_threshold, ds, df,
                           src, sport, dport, rand_sport, static_dport, data,
                           callback)
        elif self.method == "tcp":
            self.trace_tcp(first_hop, max_hops, count, wait_threshold, ds, df,
                           src, sport, dport, rand_sport, static_dport, data,
                           callback)

    @property
    def results(self) -> list[TracerouteResultsPerHop]:
        return self._tr_results


def _get_default_color(k: str) -> str | RGB | Hex | None:
    default_colors: dict[str, tuple[str | None, str | RGB | Hex | None]] = {
        "red": ("red", None),
        "light_red": ("light_red", None),
        "green": ("green", RGB(239, 205, 110)),
        "light_green": ("light_green", None),
        "yellow": ("yellow", RGB(130, 225, 223)),
        "light_yellow": ("light_yellow", None),
        "blue": ("blue", None),
        "light_blue": ("light_blue", None),
        "pink": ("pink", RGB(48, 213, 200)),
        "light_pink": ("light_pink", RGB(232, 213, 242)),
        "cyan": ("cyan", RGB(153, 237, 195)),
        "light_cyan": ("light_cyan", None),
        "gray": ("gray", RGB(160, 160, 160)),
        "light_gray": ("light_gray", RGB(190, 190, 190)),
    }
    try:
        if supports_true_color():
            color = default_colors[k][1]
        elif supports_colors():
            color = default_colors[k][0]
        else:
            color = None
        return color
    except KeyError:
        return None


@dataclass(frozen=True)
class _Colors:
    red: str | RGB | Hex | None = _get_default_color("red")
    light_red: str | RGB | Hex | None = _get_default_color("light_red")
    green: str | RGB | Hex | None = _get_default_color("green")
    light_green: str | RGB | Hex | None = _get_default_color("light_green")
    yellow: str | RGB | Hex | None = _get_default_color("yellow")
    light_yellow: str | RGB | Hex | None = _get_default_color("light_yellow")
    blue: str | RGB | Hex | None = _get_default_color("blue")
    light_blue: str | RGB | Hex | None = _get_default_color("light_blue")
    pink: str | RGB | Hex | None = _get_default_color("pink")
    light_pink: str | RGB | Hex | None = _get_default_color("light_pink")
    cyan: str | RGB | Hex | None = _get_default_color("cyan")
    light_cyan: str | RGB | Hex | None = _get_default_color("light_cyan")
    gray: str | RGB | Hex | None = _get_default_color("gray")
    light_gray: str | RGB | Hex | None = _get_default_color("light_gray")


_colors: Final = _Colors()


def _signal_handler(signum: int, frame: FrameType | None) -> None:
    if signum == signal.SIGINT:
        sys.exit(0)


def _startup_info(flags: Namespace) -> str:
    prelude_data = {
        "unet": ("traceroute", _colors.pink),
        "destination host": (flags.host, _colors.pink),
        "ip": (
            socket.getaddrinfo(
                flags.host,
                None,
                socket.AF_INET6 if flags.ip6 else socket.AF_INET,
            )[0][4][0],
            _colors.pink,
        ),
        "method": (flags.method, _colors.pink),
        "first hop": (str(flags.first_hop), _colors.pink),
        "max hops": (str(flags.max_hops), _colors.pink),
        "packets per hop": (str(flags.count), _colors.pink),
        "wait threshold": (f"{flags.wait_threshold}s", _colors.pink),
    }
    if flags.method in {"tcp", "udp"}:
        prelude_data.update({
            "source port": ((str(flags.sport), _colors.pink)
                            if not flags.rand_sport else ("random", _colors.pink)),
            "destination port": (str(flags.dport), _colors.pink),
            "fixed destination port": (str(flags.static_dport).lower(), _colors.pink)
        })

    max_key_length = max(len(key) for key in prelude_data.keys())
    prelude_parts = []

    for key, (value, color) in prelude_data.items():
        if key == "unet":
            prelude_parts.append(
                f"{Color.color(key, color)}: {Color.color(value, color)}:")
            continue
        elif key == "ip":
            prelude_parts[-1] += f" ({Color.color(value, color)})"
            continue
        else:
            formatted_key = f"{Color.color(key, _colors.green)}"
            formatted_value = f"{Color.color(value, color)}"

        padding = " " * (max_key_length - len(key) + 2)
        prelude_parts.append(f"{formatted_key}:{padding}{formatted_value}")

    return "\n  ".join(prelude_parts)


def _summary(res: list[TracerouteResultsPerHop]) -> str:
    return ""


TRACEROUTE_FLAGS: Final = {
    "host": PositionalFlag(
        help="destination address or hostname for which to trace the path packets "
             "take to reach this target",
        type=str
    ),
    "ip6": OptionFlag(
        short="-6",
        long="--ip6",
        help="use IPv6",
        action="store_true",
        required=False,
        default=False,
    ),
    "method": OptionFlag(
        short="-m",
        long="--method",
        help="tell which protocol to use: [icmp, udp, tcp]",
        type=str,
        required=False,
        default="icmp",
        metavar="<icmp|udp|tcp>"
    ),
    "first_hop": OptionFlag(
        short="-f",
        help="set the initial ttl or hop limit value",
        type=int,
        required=False,
        default=1,
        metavar="<n>"
    ),
    "max_hops": OptionFlag(
        short="-M",
        help="set the maximum number ttl can reach",
        type=int,
        required=False,
        default=64,
        metavar="<n>"
    ),
    "count": OptionFlag(
        short="-c",
        long="--count",
        help="set the number of packets per ttl",
        type=int,
        required=False,
        default=3,
        metavar="<n>"
    ),
    "saddr": OptionFlag(
        short="-s",
        help="use <addr> as the source address",
        type=str,
        required=False,
        default=None,
        metavar="<addr>",
    ),
    "ds": OptionFlag(
        short="-q",
        help="set differentiated services (as hex) (formerly 'tos' for IP and "
             "'traffic class' for IPv6)",
        type=lambda arg: int(arg, base=16),
        required=False,
        default=0,
        metavar="<diffserv>",
    ),
    "df": OptionFlag(
        short="-D",
        help="set the 'Don't Fragment' flag",
        action="store_true",
        required=False,
        default=False,
    ),
    "sport": OptionFlag(
        short="-e",
        help="set TCP/UDP source port",
        type=int,
        required=False,
        default=39181,
        metavar="<port>",
    ),
    "dport": OptionFlag(
        short="-p",
        help="set TCP/UDP destination port",
        type=int,
        required=False,
        default=33435,
        metavar="<port>",
    ),
    "rand_sport": OptionFlag(
        short="-R",
        help="randomize source port number",
        action="store_true",
        required=False,
        default=False,
    ),
    "static_dport": OptionFlag(
        short="-F",
        help="use fixed destination port for TCP and UDP methods",
        action="store_true",
        required=False,
        default=False,
    ),
    "wait_threshold": OptionFlag(
        short="-d",
        help="set the time (in seconds) to wait for a response",
        type=float,
        required=False,
        default=5.0,
        metavar="<n>",
    ),
    "summary": OptionFlag(
        short="-S",
        long="--summary",
        help="",
        action="store_true",
        required=False,
        default=False,
    ),
}


def main(args: list[str]) -> None:
    # Parser args
    parser = FlagParser(
        prog="traceroute",
        description="record the path packets take through the network to reach "
                    "the destination host",
    )
    parser.add_arguments(TRACEROUTE_FLAGS)
    flags = parser.parse_args(args)

    # Print startup info
    startup_info = _startup_info(flags)
    print(startup_info, end="\n\n")

    # Run
    try:
        # We use signals directly  because suddenly scapy just decided to don't
        # react to keyboard interrupts
        signal.signal(signal.SIGINT, _signal_handler)

        prev_host = None
        current_packet_num = 0
        packets_left = 0

        def _pretty_print_results(res: TracerouteResultsPerHop) -> None:
            nonlocal prev_host, current_packet_num, packets_left

            current_packet_num = res.packet
            if not packets_left:
                packets_left = res.count

            if packets_left == res.count:
                packet = Color.color(str(res.packet), _colors.yellow)
                print(f"{packet}. ", end="", flush=True)

            if res.timeout_hit:
                no_res = Color.color("-", _colors.light_gray)
                print(no_res + " ", end="", flush=True)
            else:
                if ((res.host != prev_host) and (prev_host is not None)
                        and (packets_left != res.count)):
                    print()
                    print(" " * len(f"{res.packet}. "), end="")

                if res.hostname != res.host:
                    if packets_left == res.count or res.host != prev_host:
                        hostname = Color.color(res.hostname, _colors.green)
                        host = Color.color(res.host, _colors.cyan)
                        print(f"{hostname} ({host}): ", end="", flush=True)
                    else:
                        print("", end="")
                else:
                    if packets_left == res.count or res.host != prev_host:
                        host = Color.color(res.host, _colors.green)
                        print(f"{host}: ", end="", flush=True)
                    else:
                        print("", end="")

                rtt = (Color.color(f"{res.rtt:.3f}", _colors.pink)
                       + Color.color("ms", _colors.light_pink))
                print(rtt + " ", end="", flush=True)

            prev_host = res.host
            packets_left -= 1

            if not packets_left:
                print()

        # Start the trace loop
        tr = Traceroute(flags.host, flags.method, flags.ip6)
        tr.trace(flags.first_hop, flags.max_hops, flags.count,
                 flags.wait_threshold, flags.ds, flags.df, flags.saddr,
                 flags.sport, flags.dport, flags.rand_sport, flags.static_dport,
                 callback=partial(_pretty_print_results))

        # Print summary if said so
        if flags.summary:
            res = tr.results
            summary = _summary(res)
            print("\n" + summary)
    except Exception as err:
        error(str(err))
