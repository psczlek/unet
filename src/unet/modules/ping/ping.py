"""
Arbitrary packet manipulation.
"""


import ipaddress
import platform
import secrets
import shutil
import socket
import subprocess
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final, Literal

from unet.coloring import Color
from unet.flag import FlagParser, Group, OptionFlag, PositionalFlag
from unet.modloader import load_module, lookup_symbol
from unet.modules.dissect import Dissect, PacketOptions
from unet.modules.dissect.dl import *
from unet.modules.dissect.platform import LINUX
from unet.printing import Assets, eprint


def error(message: str, code: int = 1) -> None:
    precedence = (f"{Color.red(Color.bold('error'))}: "
                  f"{Color.red(Color.bold('ping'))}")
    eprint(message, exit_code=code, precedence=precedence)


try:
    import psutil
except ModuleNotFoundError:
    error_message = "\n".join([
        "psutil is not installed, install scapy and try again.\n",
        "%*spip install psutil" % (7, ""),
        "%*spip3 install psutil" % (7, ""),
    ])
    error(error_message)

__all__ = [
    "error",
    "rand",
    "if_addr",
    "if_mtu",
    "if_is_active",
    "if_default_routing_interface",
    "is_valid_addr",
    "addr_version",
    "addr_is_v4",
    "addr_is_v6",
    "PingOptions",
]


# =================
# utility functions
# =================


def rand(width: Literal[8, 16, 32, 64], /) -> int:
    """
    Obtain a random number.

    Attributes
    ----------
    width : Literal[8, 16, 32, 64]
        Width of the number to return in bits (8, 16, 32 or 64).

    Returns
    -------
    int
        A random number from range [0, 2^width)
    """
    bounds = {
        8: 0xff,
        16: 0xffff,
        32: 0xffffffff,
        64: 0xffffffffffffffff,
    }
    return secrets.randbelow(bounds[width])


def _if_link_addr(name: str) -> str | None:
    addrs = psutil.net_if_addrs()[name]
    for addr in addrs:
        if addr.family == socket.AF_LINK:
            return str(addr.address)
    return None


def _if_inet_addr(name: str) -> str | None:
    addrs = psutil.net_if_addrs()[name]
    for addr in addrs:
        if addr.family == socket.AF_INET:
            return str(addr.address)
    return None


def _if_inet6_addr(name: str) -> str | None:
    addrs = psutil.net_if_addrs()[name]
    for addr in addrs:
        if addr.family == socket.AF_INET6:
            return str(addr.address)
    return None


def if_addr(
        ifname: str,
        family: Literal["link", "inet", "inet6"] = "inet",
        /,
) -> str | None:
    """
    Retrieve an IP address from a network interface.

    Attributes
    ----------
    ifname : str
        Name of the network interface for which to retrieve IP address.

    family : Literal["link", "inet", "inet6"]
        Address version to retrieve. (default: inet)

    Returns
    -------
    str | None
        The address for the supplied interface on success. Otherwise `None`.
    """
    if len(ifname) > 15:
        return None
    fn_map = {
        "link": _if_link_addr,
        "inet": _if_inet_addr,
        "inet6": _if_inet6_addr,
    }
    return fn_map[family](ifname)


def if_mtu(ifname: str, /) -> int:
    """
    Retrieve MTU for an interface.

    Attributes
    ----------
    ifname : str
        Interface name for which to retrieve MTU.

    Returns
    -------
    int
        The MTU value for the supplied interface.
    """
    return int(psutil.net_if_stats()[ifname].mtu)


def _get_local_ip(ver: int, daddr: str) -> str | None:
    try:
        sock = socket.socket(ver, socket.SOCK_DGRAM, 0)
        sock.connect((daddr, rand(16)))
        laddr = str(sock.getsockname()[0])
    except (TimeoutError, InterruptedError):
        return None
    finally:
        sock.close()
    return laddr


def if_default_routing_interface(addr: str, /) -> str | None:
    """
    Retrieve default routing interface for the supplied address.

    Attributes
    ----------
    addr : str
        Destination address for which the lookup will be performed.

    Returns
    -------
    str | None
        The interface name that would be used to route data to the supplied host.
        In case of failure `None` is returned.
    """
    if not is_valid_addr(addr):
        return None
    ver = addr_version(addr)
    if ver is None:
        return None
    laddr = _get_local_ip(ver, addr)
    if platform.system() == "Linux":
        try:
            result = subprocess.run(["ip", "addr"], capture_output=True,
                                    text=True, check=True)
            output = result.stdout
            iface = None
            for line in output.split("\n"):
                if line.startswith(" "):
                    if laddr in line:
                        return iface
                else:
                    if ":" in line:
                        iface = line.split(":")[1].strip()
        except subprocess.CalledProcessError:
            return None
    elif platform.system() == "Darwin":
        try:
            result = subprocess.run(["ifconfig"], capture_output=True,
                                    text=True, check=True)
            output = result.stdout
            iface = None
            for line in output.split("\n"):
                if "flags=" in line:
                    iface = line.split(":")[0]
                if laddr in line:
                    return iface
        except subprocess.CalledProcessError:
            return None
    return None


def if_is_active(ifname: str, /) -> bool:
    """
    Check if an interface is active.

    Attributes
    ----------
    ifname : str
        Name of the interface to check.

    Returns
    -------
    bool
        True if interface is active.
    """
    return bool(psutil.net_if_stats()[ifname].isup)


def is_valid_addr(addr: str, /) -> bool:
    """
    Check if an internet address is valid.

    Attributes
    ----------
    addr : str
        Internet address to check.

    Returns
    -------
    bool
        True if the supplied address is a valid IP address.
    """
    try:
        if "/" in addr:
            ipaddress.ip_network(addr)
        else:
            ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def addr_version(addr: str, /) -> int | None:
    """
    Tell what version the supplied ip address is.

    Attributes
    ----------
    addr : str
        Address to check.

    Returns
    -------
    int | None
        AF_INET* value or None.
    """
    if not is_valid_addr(addr):
        return None
    if "/" in addr:
        if isinstance(ipaddress.ip_network(addr), ipaddress.IPv4Network):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
    else:
        if isinstance(ipaddress.ip_address(addr), ipaddress.IPv4Address):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
    return family


def addr_is_v4(addr: str, /) -> bool | None:
    """
    Whether the supplied ip address is IPv4 address.

    Attributes
    ----------
    addr : str
        Address to check.

    Returns
    -------
    bool | None
        `True` if `addr` is IPv4 address. Otherwise `False`. In case when the
        address version could not be determined returns `None`.
    """
    ver = addr_version(addr)
    if ver is not None:
        return ver == socket.AF_INET
    return None


def addr_is_v6(addr: str, /) -> bool | None:
    """
    Whether the supplied ip address is IPv6 address.

    Attributes
    ----------
    addr : str
        Address to check.

    Returns
    -------
    bool | None
        `True` if `addr` is IPv6 address. Otherwise, `False`. In case when the
        address version could not be determined returns `None`.
    """
    ver = addr_version(addr)
    if ver is not None:
        return ver == socket.AF_INET6
    return None


def _load_ping_modules(external: str | None = None) -> dict[str, ModuleType]:
    handles = {}
    built_in_path = Path(__file__.strip("ping.py")).resolve()
    exclude = {"__init__.py", "ping.py", "__pycache__"}

    # Helper function to recursively process a directory
    def process_directory(path: Path) -> None:
        for item in path.rglob("*.py"):
            name = item.name
            stem = item.stem

            if name in exclude:
                continue

            handle = load_module(str(item), stem)
            if handle is None:
                continue

            handles[stem] = handle

    process_directory(built_in_path)

    if external is not None:
        external_path = Path(external).expanduser().resolve()

        if external_path.is_dir():
            process_directory(external_path)
        elif external_path.is_file() and external_path.suffix == ".py":
            handle = load_module(str(external_path), external_path.stem)
            if handle is not None:
                handles[external_path.stem] = handle

    return handles


def _build_ping_flags(external: str | None = None) -> dict[Any, Any]:
    ping_modules = _load_ping_modules(external)
    ping_flags = {}

    for name, handle in ping_modules.items():
        if not lookup_symbol(handle, f"{name.upper()}_FLAGS"):
            continue

        flags = getattr(handle, f"{name.upper()}_FLAGS")
        ping_flags |= flags

    return ping_flags


type PingOptions = Namespace


@dataclass
class StartupInfo:
    targets: list[str]
    interface: str
    mtu: int
    count: int
    method: str
    delay: int
    payload: int


@dataclass
class Statistics:
    targets: list[str] | None = None
    sent: int = 0
    recv: int = 0
    lost: float = 0.0
    rtt_max: float = 0.0
    rtt_min: float = 0.0
    rtt_avg: float = 0.0


def packet_send(opt: PingOptions) -> None:
    ping_modules = _load_ping_modules()
    send_table = {}

    for name, handle in ping_modules.items():
        if (not lookup_symbol(handle, f"{name}_send")
                and not lookup_symbol(handle, "register_send_routine")
                and not lookup_symbol(handle, "create_method")):
            continue

        if lookup_symbol(handle, "create_method"):
            create_method = getattr(handle, "create_method")
            method = create_method()
            send_table[method] = None

        if lookup_symbol(handle, "register_send_routine"):
            register_send_routine = getattr(handle, "register_send_routine")
            method, send_routine = register_send_routine()

            send_table[method] = send_routine

    if opt.method not in send_table:
        raise ValueError(f"method '{opt.method}' does not exist. Create "
                         "the method first and then try to register the "
                         "send routine")

    send = send_table[opt.method]

    if opt.flood:
        opt.delay = 0

        while True:
            send(opt, opt.payload)

    targets = opt.ip_dst
    if opt.count > 0:
        for target in opt.ip_dst:
            opt.ip_dst = target

            for _ in range(opt.count):
                send(opt, opt.payload)

                if opt.no_sent:
                    opt.stat.sent += 1
    else:
        next_target = 0

        while True:
            try:
                opt.ip_dst = targets[next_target]
            except IndexError:
                next_target = 0

            send(opt, opt.payload)

            next_target += 1


def list_methods() -> dict[str, tuple[str, Any]]:
    ping_modules = _load_ping_modules()
    methods = {}

    for name, handle in ping_modules.items():
        if (not lookup_symbol(handle, f"{name}_send")
                and not lookup_symbol(handle, "register_send_routine")
                and not lookup_symbol(handle, "create_method")):
            continue

        if lookup_symbol(handle, "register_send_routine"):
            register_send_routine = getattr(handle, "register_send_routine")
            method, send_routine = register_send_routine()

            methods[method] = (handle.__file__, send_routine.__name__)

    return methods


def startup_info(si: StartupInfo, opt: PingOptions) -> str:
    from unet.modules.dissect import FieldFormatterColor

    lines = []
    colors = FieldFormatterColor()

    # Create top and bottom separators
    terminal_width = shutil.get_terminal_size().columns - 2
    top_sep = Assets.HORIZONTAL_LINE * terminal_width
    top_sep = f"{top_sep[:2]}{Assets.TOP_T_INTERSECTION}{top_sep[2:]}"

    bottom_sep = Assets.HORIZONTAL_LINE * terminal_width
    bottom_sep = f"{bottom_sep[:2]}{Assets.BOTTOM_T_INTERSECTION}{bottom_sep[2:]}"

    # Color the separators
    top_sep = Color.color(top_sep, colors.sep)
    bottom_sep = Color.color(bottom_sep, colors.sep)

    # Prepare content information
    targets = ", ".join([
        f"{addr} ({socket.getaddrinfo(addr, None, socket.AF_INET if not opt.ip6 else socket.AF_INET6)[0][4][0]})"
        for addr in si.targets
    ])

    interface = f"{si.interface} ({if_addr(si.interface, 'inet6' if opt.ip6 else 'inet')})"
    payload_size = si.payload

    contents = {
        "targets": targets,
        "interface": interface,
        "mtu": str(si.mtu),
        "count": str(si.count),
        "method": si.method,
        "delay": f"{si.delay} s",
        "payload": f"{payload_size} byte(s)",
    }

    # Find the longest key for alignment
    max_key_len = max(len(k) for k in contents)

    # Format each line with proper indentation and colors
    for key, value in contents.items():
        indent = (max_key_len - len(key)) + 1
        key_colored = Color.color(key, colors.name)
        value_colored = Color.color(value, colors.value)
        sep_colored = Color.color(Assets.VERTICAL_LINE, colors.sep)

        lines.append(f"  {sep_colored} {key_colored}:{' ' * indent}{value_colored}")

    # Format the full output
    formatted_lines = "\n".join(lines)
    return f"{top_sep}\n{formatted_lines}\n{bottom_sep}"


def summary(stat: Statistics, opt: PingOptions) -> str:
    from unet.modules.dissect import FieldFormatterColor

    # Initialize lines and colors
    lines = []
    colors = FieldFormatterColor()

    # Generate top and bottom separators
    terminal_width = shutil.get_terminal_size().columns - 2
    top_sep = Assets.HORIZONTAL_LINE * terminal_width
    top_sep = f"{top_sep[:2]}{Assets.TOP_T_INTERSECTION}{top_sep[2:]}"

    bottom_sep = Assets.HORIZONTAL_LINE * terminal_width
    bottom_sep = f"{bottom_sep[:2]}{Assets.BOTTOM_T_INTERSECTION}{bottom_sep[2:]}"

    # Color the separators
    top_sep = Color.color(top_sep, colors.sep)
    bottom_sep = Color.color(bottom_sep, colors.sep)

    # Prepare summary contents
    targets = ", ".join([
        f"{addr} ({socket.getaddrinfo(addr, None, socket.AF_INET if not opt.ip6 else socket.AF_INET6)[0][4][0]})"
        for addr in stat.targets
    ])

    contents = {
        "targets": targets,
        "transmitted": str(stat.sent) if stat.sent > 0 else "-",
        "received": str(stat.recv) if stat.recv > 0 else "-",
    }

    # Calculate packet loss rate
    if stat.sent == 0:
        loss_rate = 0
    elif stat.recv == 0:
        loss_rate = 100
    else:
        if stat.sent > opt.count and not len(stat.targets) > 1:
            contents["transmitted by kernel"] = str((stat.sent - opt.count))
            stat.sent = stat.sent - opt.count
            contents["transmitted"] = str(stat.sent)
        loss_rate = 100 * (stat.sent - stat.recv) / stat.sent

    # Packet loss information
    if "transmitted by kernel" not in contents:
        contents["lost"] = "-" if stat.sent == -1 and stat.recv == -1 else f"{int(stat.lost)} ({loss_rate:.2f} %)"
    else:
        contents["lost"] = "-" if not loss_rate else f"{int(stat.lost)} ({loss_rate:.2f} %)"

    # RTT information
    contents["rtt max"] = f"{stat.rtt_max:.6f} ms" if stat.rtt_max else "n/a"
    contents["rtt min"] = f"{stat.rtt_min:.6f} ms" if stat.rtt_min else "n/a"
    contents["rtt avg"] = f"{stat.rtt_avg:.6f} ms" if stat.rtt_avg else "n/a"

    # Format each line of the summary
    max_key_len = max(len(k) for k in contents)
    for key, value in contents.items():
        indent = (max_key_len - len(key)) + 1
        key_colored = Color.color(key, colors.name)
        value_colored = Color.color(value, colors.value)
        sep_colored = Color.color(Assets.VERTICAL_LINE, colors.sep)

        lines.append(f"  {sep_colored} {key_colored}:{' ' * indent}{value_colored}")

    # Format the full output
    formatted_lines = "\n".join(lines)
    return f"{top_sep}\n{formatted_lines}\n{bottom_sep}"


PING_FLAGS: Final = {
    "target": PositionalFlag(
        help="destination host for sending packets (e.g., 192.168.1.1)",
        nargs="?",
        type=lambda flag: flag.strip().split(","),
    ),
    "no_target_resolve": OptionFlag(
        short="-r",
        help="do not try to resolve the target address",
        required=False,
        action="store_true",
        default=False,
    ),
    "interface": OptionFlag(
        short="-i",
        long="--interface",
        help="specify the network interface to use (e.g., eth0)",
        type=str,
        required=False,
        default=None,
        metavar="<name>",
    ),
    "count": OptionFlag(
        short="-c",
        long="--count",
        help="total number of packets to send (default: 4)",
        type=int,
        required=False,
        default=4,
        metavar="<count>",
    ),
    "delay": OptionFlag(
        short="-d",
        long="--delay",
        help="delay between packets in seconds (default: 1)",
        type=float,
        required=False,
        default=1,
        metavar="<delay>",
    ),
    "method": OptionFlag(
        short="-m",
        long="--method",
        help="protocol to use for sending packets (default: icmp, e.g., tcp)",
        type=str,
        required=False,
        default="icmp",
        metavar="<method>",
    ),
    "ip6": OptionFlag(
        short="-6",
        long="--ip6",
        help="use IPv6",
        action="store_true",
        default=False,
    ),
    "payload": OptionFlag(
        short="-P",
        long="--payload",
        help="append specified data to the end of each packet",
        type=str,
        required=False,
        default=None,
        metavar="<data>",
    ),
    "payload_as_hex": OptionFlag(
        short="-X",
        long="--payload-as-hex",
        help="interpret the supplied payload string as though it is already "
             "encoded in bytes",
        action="store_true",
        required=False,
        default=False,
    ),
    "payload_len": OptionFlag(
        short="-L",
        long="--payload-len",
        help="specify the number of bytes to append from the `-p` flag. "
             "Data will be adjusted to fit this length.",
        type=int,
        required=False,
        default=-1,
        metavar="<n>",
    ),
    "payload_rand": OptionFlag(
        short="-R",
        long="--payload-rand",
        help="append <n> random bytes to the end of each packet",
        type=int,
        required=False,
        default=-1,
        metavar="<n>",
    ),
    "mtu": OptionFlag(
        short="-M",
        long="--mtu",
        help="set the mtu size to use",
        type=int,
        required=False,
        default=-1,
        metavar="<mtu>",
    ),
    "flood": OptionFlag(
        short="-F",
        long="--flood",
        help="send packets as fast as ping can",
        action="store_true",
        default=False,
    ),
    "list_methods": OptionFlag(
        long="--list-methods",
        help="display a list of available packet sending methods and exit",
        action="store_true",
        default=False,
    ),
}


_EXAMPLES_OF_USAGE: Final = {
    "examples": Group(
        arguments={},
        description="\n".join([
            f"{Color.blue('unet')} {Color.cyan('ping')} facebook.com",

            f"{Color.blue('unet')} {Color.cyan('ping')} google.com "
            f"{Color.yellow('-m')} tcp {Color.yellow('-p')} 443 "
            f"{Color.yellow('--tcp-flags')} syn {Color.yellow('--tcp-opt')} "
            f"mss,ws,sackp,nop,nop,eol {Color.yellow('--num --timestamp')} "
            f"{Color.yellow('-c')} 2",

            f"{Color.blue('unet')} {Color.cyan('ping')} {Color.yellow('-m')} udp "
            f"microsoft.com {Color.yellow('-p')} 53 {Color.yellow('-c')} 3 "
            f"{Color.yellow('--num --timestamp --verbose --sum-ok')}",

            f"{Color.blue('unet')} {Color.cyan('ping')} 192.168.0.1 "
            f"{Color.yellow('-m')} tcp {Color.yellow('--tcp-flags')} rst "
            f"{Color.yellow('-p')} 80 {Color.yellow('--num --timestamp')}",
        ]),
    ),
}


def main(args: list[str]) -> None:
    parser = FlagParser(prog="ping", description="almost arbitrary packet manipulation")
    ping_flags: dict[str, Group | PositionalFlag | OptionFlag] = PING_FLAGS | _build_ping_flags(None) | _EXAMPLES_OF_USAGE
    parser.add_arguments(ping_flags)
    flags = parser.parse_args(args)

    if flags.list_methods:
        from unet.modules.dissect import FieldFormatterColor

        colors = FieldFormatterColor()
        methods = list_methods()

        for method, spec in methods.items():
            output = "%s: (%s) from %s %s" % (
                Color.color(method, colors.alt_name),
                Color.color(spec[1], colors.value),
                Color.color(Assets.RIGHTWARDS_ARROW, colors.sep),
                Color.color(spec[0], colors.alt_unit),
            )
            print(output)

        return

    stat = Statistics()
    setattr(flags, "stat", stat)

    # Adjust target(s)
    if flags.target is None and flags.ip_dst is None:
        error("destination host is required but was not supplied. "
              "Use '--ip-dst' or positional 'target' to set the destination host")
    elif flags.target is not None and flags.ip_dst is None:
        flags.ip_dst = flags.target

    unresolved_targets = flags.ip_dst
    resolved_targets = []
    if not flags.no_target_resolve:
        for target in flags.ip_dst:
            try:
                addr = socket.getaddrinfo(
                    target,
                    None,
                    socket.AF_INET if not flags.ip6 else socket.AF_INET6,
                )
                addr = addr[0][4][0]
                resolved_targets.append(addr)
            except socket.gaierror as e:
                error(f"failed to resolve target address {Assets.RIGHTWARDS_ARROW} "
                      f"'{target}'\n{' ' * 13}{e}")
    else:
        for target in flags.ip_dst:
            resolved_targets.append(target)

    flags.ip_dst = resolved_targets

    for target in flags.ip_dst:
        if not is_valid_addr(target):
            error(f"invalid target address: {target}")

        if flags.ip6 and addr_is_v4(target):
            error(f"expected IPv6 targets, however IPv4 was supplied: {target}")
        elif not flags.ip6 and addr_is_v6(target):
            error(f"expected IPv4 targets, however IPv6 was supplied: {target}")

    # Setup interface
    if flags.interface is None:
        flags.interface = if_default_routing_interface(flags.ip_dst[0])
        if flags.interface is None:
            error(f"could not determine which interface to use to send data to "
                  f"host: '{flags.ip_dst[0]}'. Please specify it manually and "
                  f"try again")

    # At this point interface shouldn't be None
    assert flags.interface is not None

    ip_src_ver = "inet" if not flags.ip6 else "inet6"
    flags.ip_src = if_addr(flags.interface, ip_src_ver) if flags.ip_src is None else flags.ip_src

    # Set MTU
    if flags.mtu == -1:
        flags.mtu = if_mtu(flags.interface)

    # Adjust payload
    if flags.payload is not None:
        # If a specific payload length is given, adjust the payload to fit
        if flags.payload_len > -1:
            # Truncate or pad the payload to fit the length
            flags.payload = flags.payload[:flags.payload_len].ljust(flags.payload_len, flags.payload[0])

        if not flags.payload_as_hex:
            flags.payload = flags.payload.encode()
        else:
            try:
                flags.payload = bytes.fromhex(flags.payload)
            except ValueError as e:
                error(str(e))

    # Append random bytes if requested
    if flags.payload_rand > 0:
        if flags.payload is None:
            flags.payload = bytes(secrets.randbits(8) for _ in range(flags.payload_rand))
        else:
            flags.payload += bytes(secrets.randbits(8) for _ in range(flags.payload_rand))

    # Print the startup info
    si = StartupInfo(
        unresolved_targets,
        flags.interface,
        flags.mtu,
        flags.count,
        flags.method,
        flags.delay,
        len(flags.payload) if flags.payload else 0,
    )
    prelude = startup_info(si, flags)
    print(prelude, end="\n" * 2)

    # Start the send loop
    if not flags.no_capture:
        if flags.bpf is not None:
            bpf = flags.bpf
        else:
            bpf_ip_ver = "ip" if not flags.ip6 else "ip6"

            bpf_parts = []

            if not flags.no_sent:
                for target in flags.ip_dst:
                    bpf_parts.append(f"({bpf_ip_ver} src {flags.ip_src} "
                                     f"and {bpf_ip_ver} dst {target}) or "
                                     f"({bpf_ip_ver} src {target} and {bpf_ip_ver} "
                                     f"dst {flags.ip_src})")
            else:
                for target in flags.ip_dst:
                    bpf_parts.append(f"({bpf_ip_ver} src {target} and {bpf_ip_ver} "
                                     f"dst {flags.ip_src})")

            bpf = " or ".join(bpf_parts)

            if flags.bpf_append is not None:
                bpf += f" and ({flags.bpf_append})"

        target_list = flags.ip_dst

        if flags.save is not None:
            flags.save = str(Path(flags.save).expanduser().resolve())

        dissect = Dissect("live", interface=flags.interface, wfile=flags.save,
                          filter=bpf)
        pkto = PacketOptions(flags.verbose, False, flags.num, flags.hexdump,
                             flags.dumpchunk, flags.no_mac_resolve,
                             flags.no_ip_resolve, flags.no_port_resolve,
                             flags.sum_ok, False, flags.timestamp, flags.l2,
                             flags.unknown)

        dissect.packet_print_loop(pkto, threaded=True)

        try:
            packet_send(flags)
        except KeyboardInterrupt:
            pass
        except ValueError as e:
            error(str(e))

        dissect.live_stop()

        linkhdrlen_map = {
            DLT_NULL: 4,
            DLT_EN10MB: 14,
            DLT_EN3MB: 14,
            DLT_AX25: 17,
            DLT_PRONET: 6,
            DLT_CHAOS: 4,
            DLT_IEEE802: 14,
            DLT_ARCNET: 10 if not LINUX else 8,
            DLT_SLIP: 16,
            DLT_PPP: 4,
            DLT_FDDI: 13,
            DLT_RAW: 0,
            DLT_ATM_CLIP: 8,
            DLT_PPP_SERIAL: 4,
            DLT_PPP_ETHER: 6,
            DLT_C_HDLC: 4,
            DLT_IEEE802_11: 14,
            DLT_FRELAY: 4,
            DLT_IPV4: 0,
            DLT_IPV6: 0,
            DLT_LOOP: 4,
            DLT_ENC: 12,
            DLT_LINUX_SLL: 16,
            DLT_LINUX_SLL2: 20,
        }
        linkhdrlen = linkhdrlen_map[dissect.live_linktype]

        cph = dissect.live_get()
        ts_sent = 0.0
        ts_recv = 0.0
        rtt_pool: list[float] = []
        while cph is not None:
            if flags.ip6:
                ip = cph.buf[linkhdrlen:]
            else:
                ip = cph.buf[linkhdrlen:]
                ip_ihl = ip[0] & 0xf
                ip = ip[:ip_ihl << 2]

            try:
                if flags.ip6:
                    src = str(ipaddress.ip_address(ip[8:24]))
                    dst = str(ipaddress.ip_address(ip[24:40]))
                else:
                    src = str(ipaddress.ip_address(ip[12:16]))
                    dst = str(ipaddress.ip_address(ip[16:20]))
            except ValueError as e:
                error(str(e))

            pkt_ts = round(cph.timestamp[0] + cph.timestamp[1] / 1000.0, 6)

            if src == flags.ip_src and dst == flags.ip_src:
                flags.stat.sent = -1
                flags.stat.recv = -1
            elif src == flags.ip_src and dst in target_list:
                flags.stat.sent += 1
                ts_sent = pkt_ts
            elif src in target_list and dst == flags.ip_src:
                flags.stat.recv += 1
                ts_recv = pkt_ts

                if ts_sent > 0 and ts_recv >= ts_sent:
                    rtt = ts_recv - ts_sent
                    rtt_pool.append(rtt)
                    ts_sent = 0.0

            cph = dissect.live_get()

        flags.stat.lost = flags.stat.sent - flags.stat.recv

        if rtt_pool:
            flags.stat.rtt_max = max(rtt_pool)
            flags.stat.rtt_min = min(rtt_pool)
            flags.stat.rtt_avg = sum(rtt_pool) / len(rtt_pool)
        else:
            flags.stat.rtt_max = flags.stat.rtt_min = flags.stat.rtt_avg = 0.0

        stat.targets = unresolved_targets

        epilog = summary(stat, flags)
        print("\n" + epilog)
    else:
        try:
            packet_send(flags)
        except KeyboardInterrupt:
            pass
