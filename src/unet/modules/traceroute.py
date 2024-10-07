"""
Record the path packets take through the network to reach the destination host
"""


import ipaddress
import secrets
import signal
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from types import FrameType
from typing import Final, Literal

from unet.coloring import RGB, Color, Hex, supports_colors, supports_true_color
from unet.flag import FlagParser, OptionFlag, PositionalFlag
from unet.printing import Assets, eprint


def error(message: str, code: int = 1) -> None:
    precedence = (f"{Color.color('error', 'red bold')}: "
                  f"{Color.color('traceroute', 'red bold')}")
    eprint(message, exit_code=code, precedence=precedence)


try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
    from scapy.packet import Packet, Raw, raw
    from scapy.sendrecv import sr1
except ModuleNotFoundError:
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

__all__ = ["main", "TracerouteResultsPerHop", "Traceroute"]


@dataclass
class TracerouteResultsPerHop:
    probe_num: int = 0
    host: str | None = None
    rtt: float = 0.0
    timeout_hit: bool = False
    probes_sent: int = 0
    retry_count: int = 0
    timeouts_hit: int = 0
    current_hop: int = 0


class Traceroute:
    """
    An object that mimics the traceroute tool.
    """

    def __init__(
            self,
            to: str,
            method: Literal["icmp", "tcp", "udp"] = "icmp",
            interface: str | None = None,
            resolve: bool = True,
            ip6: bool = False,
    ) -> None:
        self.to = to
        self.method = method
        self.interface = interface
        self.resolve = resolve
        self.ip6 = ip6
        try:
            if self.resolve:
                self.to = socket.getaddrinfo(
                    self.to,
                    None,
                    socket.AF_INET6 if self.ip6 else socket.AF_INET,
                )[0][4][0]
            else:
                ipaddress.ip_address(self.to)
        except (ValueError, socket.herror):
            pass
        _supported_methods = {"icmp", "tcp", "udp"}
        if self.method not in _supported_methods:
            raise ValueError(f"unknown method: {self.method}. "
                             f"supported methods: {_supported_methods}")

    def trace(
        self,
        first_hop: int = 1,
        max_hops: int = 64,
        retry_count: int = 3,
        delay: float = 0.2,
        wait_limit: int = 2,
        df: bool = False,
        sport: int = 39181,
        dport: int = 33435,
        callback: Callable[[TracerouteResultsPerHop], None] | None = None,
    ) -> None:
        bpf = self._get_bpf_filter()
        for hop in range(first_hop, max_hops + 1):
            tr_results = TracerouteResultsPerHop(hop, retry_count=retry_count,
                                                 current_hop=hop)
            done = False
            for _ in range(retry_count):
                pkt = self._build_packet(hop, df, sport, dport)
                sent_time = time.time()
                res = sr1(pkt, timeout=wait_limit, inter=delay, filter=bpf,
                          verbose=False, threaded=False)
                if res:
                    recv_time = time.time()
                    if self._check_packet(res):
                        tr_results.host = res[IP if not self.ip6 else IPv6].src
                        tr_results.rtt = (recv_time - sent_time) * 1000
                        if tr_results.host == self.to:
                            done = True
                else:
                    tr_results.timeout_hit = True
                    tr_results.timeouts_hit += 1
                if callback:
                    callback(tr_results)
                tr_results.probes_sent += 1
            if done:
                return
            dport += 1

    def _get_bpf_filter(self) -> str:
        if not self.ip6:
            return ("(ip proto 1 and (icmp[0]=0 or icmp[0]=3 or icmp[0]=11)) "
                    "or (ip proto 6 and (tcp[13] & 0x16 > 0x10))")
        else:
            return ("(ip6 proto 58 and (icmp6[0]=1 or icmp6[0]=3 or icmp6[0]=129)) "
                    "or (ip6 proto 6 and (tcp[13] & 0x16 > 0x10))")

    def _check_packet(self, pkt: Packet) -> bool:
        return True

    def _build_packet(
            self,
            ttl: int,
            df: bool,
            sport: int,
            dport: int,
    ) -> Packet:
        if not self.ip6:
            ip = IP(
                id=secrets.randbelow(0xffff),
                flags="DF" if df else None,
                ttl=ttl,
                dst=self.to,
            )
        else:
            ip = IPv6(hlim=ttl, dst=self.to)
        if self.method == "icmp":
            np = ICMP() if not self.ip6 else ICMPv6EchoRequest()
        elif self.method == "udp":
            np = UDP(sport=sport, dport=dport)
        else:
            np = TCP(
                sport=sport,
                dport=dport,
                seq=secrets.randbelow(0xffffffff),
                flags="S",
            )
        pkt = ip / np
        return pkt


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


def _pretty_print_results(results: TracerouteResultsPerHop) -> None:
    if results.probes_sent == 0:
        probe_num = Color.color(str(results.probe_num), _colors.yellow)
        print(f"{probe_num}. ", end="", flush=True)
    if results.timeout_hit:
        no_res = Color.color("- ", _colors.light_gray)
        print(f"{no_res} ", end="", flush=True)
    else:
        if results.probes_sent == 0:
            try:
                hostname = socket.gethostbyaddr(results.host)[0]
                hostname = Color.color(hostname, _colors.green)
                host = Color.color(results.host, _colors.cyan)
                print(f"{hostname} ({host}): ", end="", flush=True)
            except socket.herror:
                host = Color.color(results.host, _colors.green)
                print(f"{host}: ", end="", flush=True)
        rtt = Color.color(f"{results.rtt:.3f}", _colors.pink)
        unit = Color.color("ms", _colors.light_pink)
        print(f"{rtt}{unit} ", end="", flush=True)
    if results.probes_sent == (results.retry_count - 1):
        hop = Color.color(str(results.current_hop), _colors.yellow)
        print(f"{Assets.LEFTWARDS_ARROW} (ttl={hop})", flush=True)


TRACEROUTE_FLAGS: Final = {
    "host": PositionalFlag(
        help="destination address or hostname for which to trace the path packets "
             "take to reach this target",
        type=str
    ),
    "method": OptionFlag(
        short="-m",
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
        metavar="<first_ttl>"
    ),
    "max_hops": OptionFlag(
        short="-M",
        help="set the maximum number ttl can reach",
        type=int,
        required=False,
        default=64,
        metavar="<max_ttl>"
    ),
    "retry_count": OptionFlag(
        short="-r",
        help="set the number of packets per ttl",
        type=int,
        required=False,
        default=3,
        metavar="<n>"
    ),
    "wait_limit": OptionFlag(
        short="-w",
        help="set the time to wait for a response",
        type=float,
        required=False,
        default=3.0,
        metavar="<n>",
    ),
    "df_bit": OptionFlag(
        short="-D",
        help="set the 'Don't Fragment' flag",
        action="store_true",
        required=False,
        default=False,
    ),
    "sport": OptionFlag(
        short="-s",
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
    "ip6": OptionFlag(
        short="-6",
        help="use IPv6",
        action="store_true",
        required=False,
        default=False,
    ),
}


def _signal_handler(signum: int, frame: FrameType | None) -> None:
    if signum == signal.SIGINT:
        sys.exit(0)


def main(args: list[str]) -> None:
    parser = FlagParser(
        prog="traceroute",
        description="record the path packets take through the network to reach "
                    "the destination host",
    )
    parser.add_arguments(TRACEROUTE_FLAGS)
    flags = parser.parse_args(args)
    header_parts = [
        f"{Color.color('destination host', _colors.green)}: {Color.color(flags.host, _colors.pink)}",
        f"{Color.color('method', _colors.green)}: {Color.color(flags.method, _colors.pink)}",
        f"{Color.color('first hop', _colors.green)}: {Color.color(str(flags.first_hop), _colors.pink)}",
        f"{Color.color('max hops', _colors.green)}: {Color.color(str(flags.max_hops), _colors.pink)}",
        f"{Color.color('packets per hop', _colors.green)}: {Color.color(str(flags.retry_count), _colors.pink)}",
        f"{Color.color('wait limit', _colors.green)}: {Color.color(str(flags.wait_limit), _colors.pink)}s"
    ]
    if flags.method in {"tcp", "udp"}:
        header_parts.extend([
            f"source port: {flags.sport}",
            f"destination port: {flags.dport}"
        ])
    header = ", ".join(header_parts)
    print("unet: traceroute: " + header, end="\n\n")
    try:
        signal.signal(signal.SIGINT, _signal_handler)
        tracer = Traceroute(flags.host, flags.method)
        tracer.trace(flags.first_hop, flags.max_hops, flags.retry_count, 0,
                     flags.wait_limit, flags.df_bit, flags.sport, flags.dport,
                     callback=_pretty_print_results)
    except Exception as err:
        error(str(err))
