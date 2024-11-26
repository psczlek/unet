import secrets
import time
from collections.abc import Callable
from typing import Final

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.layers.inet import (IP, IPOption_Address_Extension,
                                   IPOption_EOL, IPOption_LSRR,
                                   IPOption_MTU_Probe, IPOption_NOP,
                                   IPOption_Router_Alert, IPOption_RR,
                                   IPOption_SDBM, IPOption_Security,
                                   IPOption_SSRR, IPOption_Stream_Id,
                                   IPOption_Timestamp, IPOption_Traceroute,
                                   checksum, fragment)
    from scapy.packet import Raw, raw
    from scapy.sendrecv import send
except ModuleNotFoundError:
    from unet.modules.ping import error
    error("scapy is not installed. Install scapy and try again: "
          "'python3 -m pip install scapy'")

from unet.flag import Group, OptionFlag
from unet.modules.ping import PingOptions, if_addr, rand

__all__ = [
    "IP_FLAGS",
    "get_random_ipv4",
    "ip_send",
    "register_send_routine",
    "create_method",
]


def get_random_ipv4() -> str:
    # Class A, public range: 1.0.0.0 - 126.255.255.255
    def random_class_a() -> str:
        return (f"{secrets.randbelow(127)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}")

    # Class B, public range: 128.0.0.0 - 191.255.255.255
    def random_class_b() -> str:
        return (f"{secrets.randbelow(192)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}")

    # Class C, public range: 192.0.0.0 - 223.255.255.255
    def random_class_c() -> str:
        return (f"{secrets.randbelow(224)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}"
                f".{secrets.randbelow(256)}")

    class_a = random_class_a()
    class_b = random_class_b()
    class_c = random_class_c()

    ip_list = [class_a, class_b, class_c]

    return secrets.choice(ip_list)


IP_FLAGS: Final = {
    "IPv4": Group(
        arguments={
            "ip_ihl": OptionFlag(
                long="--ip-ihl",
                help="set IP header length",
                type=int,
                required=False,
                default=None,
                metavar="<ihl>",
            ),
            "ip_tos": OptionFlag(
                long="--ip-tos",
                help="set IP type of service",
                type=lambda flag: int(flag, 16),
                required=False,
                default=None,
                metavar="<tos>",
            ),
            "ip_len": OptionFlag(
                long="--ip-len",
                help="set IP total length",
                type=int,
                required=False,
                default=None,
                metavar="<len>",
            ),
            "ip_id": OptionFlag(
                long="--ip-id",
                help="set IP identification",
                type=lambda flag: int(flag, 16),
                required=False,
                default=None,
                metavar="<id>",
            ),
            "ip_flags": OptionFlag(
                long="--ip-flags",
                help="set IP flags",
                type=str,
                required=False,
                default=None,
                metavar="<flags>",
            ),
            "ip_off": OptionFlag(
                long="--ip-off",
                help="set IP fragment offset",
                type=int,
                required=False,
                default=None,
                metavar="<off>",
            ),
            "ip_ttl": OptionFlag(
                long="--ip-ttl",
                help="set IP time to live",
                type=int,
                required=False,
                default=None,
                metavar="<ttl>",
            ),
            "ip_proto": OptionFlag(
                long="--ip-proto",
                help="set IP protocol",
                type=int,
                required=False,
                default=None,
                metavar="<proto>",
            ),
            "ip_sum": OptionFlag(
                long="--ip-sum",
                help="set IP checksum",
                type=lambda flag: int(flag, 16),
                required=False,
                default=None,
                metavar="<checksum>",
            ),
            "ip_opt": OptionFlag(
                long="--ip-opt",
                help="set IP options: [eol, nop, sec, lsrr, ts, rr, sid, ssrr, "
                     "tr, sdb, mtu, ra, aext]",
                type=lambda flag: flag.strip().split(","),
                required=False,
                default=None,
                metavar="<options>",
            ),
            "ip_opt_sec_sss": OptionFlag(
                long="--ip-opt-sec-sss",
                help="set 'security' for the IP's security option",
                type=int,
                required=False,
                default=0,
                metavar="<sss>",
            ),
            "ip_opt_sec_ccc": OptionFlag(
                long="--ip-opt-sec-c",
                help="set 'compartment' for the IP's security option",
                type=int,
                required=False,
                default=0,
                metavar="<ccc>",
            ),
            "ip_opt_sec_hhh": OptionFlag(
                long="--ip-opt-sec-hhh",
                help="set 'handling restrictions' for the IP's security "
                     "option",
                type=int,
                required=False,
                default=0,
                metavar="<hhh>",
            ),
            "ip_opt_sec_tcc": OptionFlag(
                long="--ip-opt-sec-tcc",
                help="set 'transmission control code' for the IP's "
                     "security option",
                type=str,
                required=False,
                default="AAA",
                metavar="<hhh>",
            ),
            "ip_opt_rr_ptr": OptionFlag(
                long="--ip-opt-rr-ptr",
                help="set pointer for the IP's [lsrr, ssrr, rr] options",
                type=int,
                default=4,
                required=False,
                metavar="<ptr>",
            ),
            "ip_opt_rr_data": OptionFlag(
                long="--ip-opt-rr-data",
                help="set route data for the IP's [lsrr, ssrr, rr] options. "
                     "Comma separated list of IP addresses",
                type=lambda flag: flag.strip().split(","),
                default=[get_random_ipv4() for _ in range(3)],
                required=False,
                metavar="<data>",
            ),
            "ip_opt_ts_ptr": OptionFlag(
                long="--ip-opt-ts-ptr",
                help="set pointer for the IP's timestamp option",
                type=int,
                default=9,
                required=False,
                metavar="<ptr>",
            ),
            "ip_opt_ts_oflw": OptionFlag(
                long="--ip-opt-ts-oflw",
                help="set overflow for the IP's timestamp option",
                type=int,
                default=0,
                required=False,
                metavar="<oflw>",
            ),
            "ip_opt_ts_flg": OptionFlag(
                long="--ip-opt-ts-flg",
                help="set the flag for the IP's timestamp option",
                type=int,
                default=1,
                required=False,
                metavar="<flg>",
            ),
            "ip_opt_ts_addr": OptionFlag(
                long="--ip-opt-ts-addr",
                help="set internet address for the IP's timestamp option",
                type=str,
                default=get_random_ipv4(),
                required=False,
                metavar="<addr>",
            ),
            "ip_opt_ts_ts": OptionFlag(
                long="--ip-opt-ts-ts",
                help="set timestamp for the IP's timestamp option",
                type=int,
                default=0,
                required=False,
                metavar="<ts>",
            ),
            "ip_opt_sid_id": OptionFlag(
                long="--ip-opt-sid-id",
                help="set stream id for the IP's stream identifier option",
                type=int,
                default=0,
                required=False,
                metavar="<sid>",
            ),
            "ip_opt_tr_id": OptionFlag(
                long="--ip-opt-tr-id",
                help="set identification for the IP's traceroute option",
                type=int,
                default=rand(16),
                required=False,
                metavar="<id>",
            ),
            "ip_opt_tr_ohops": OptionFlag(
                long="--ip-opt-tr-ohops",
                help="set outbound hops for the IP's traceroute option",
                type=int,
                default=0,
                required=False,
                metavar="<n>",
            ),
            "ip_opt_tr_rhops": OptionFlag(
                long="--ip-opt-tr-rhops",
                help="set return hops for the IP's traceroute option",
                type=int,
                default=0,
                required=False,
                metavar="<n>",
            ),
            "ip_opt_tr_ip": OptionFlag(
                long="--ip-opt-tr-ip",
                help="set originator address for the IP's traceroute option",
                type=str,
                default=get_random_ipv4(),
                required=False,
                metavar="<addr>",
            ),
            "ip_opt_sdb_data": OptionFlag(
                long="--ip-opt-sdb-data",
                help="set addresses for the IP's SDB option",
                type=lambda flag: flag.strip().split(","),
                default=[get_random_ipv4() for _ in range(3)],
                required=False,
                metavar="<addr1,addr2,...>",
            ),
            "ip_opt_mtu_type": OptionFlag(
                long="--ip-opt-mtu-type",
                help="set MTU option type: [probe, reply]",
                type=str,
                default="probe",
                required=False,
                metavar="<probe|reply>",
                choices={"probe", "reply"},
            ),
            "ip_opt_mtu_mtu": OptionFlag(
                long="--ip-opt-mtu-mtu",
                help="set MTU for the IP's MTU option",
                type=int,
                default=rand(16),
                required=False,
                metavar="<mtu>",
            ),
            "ip_opt_ra_alert": OptionFlag(
                long="--ip-opt-ra-alert",
                help="set alert for the IP's router alert option",
                type=int,
                default=rand(16),
                required=False,
                metavar="<alert>",
            ),
            "ip_opt_aext_src": OptionFlag(
                long="--ip-opt-aext-src",
                help="set source for the IP's address extension option",
                type=str,
                default=get_random_ipv4(),
                required=False,
                metavar="<addr>",
            ),
            "ip_opt_aext_dst": OptionFlag(
                long="--ip-opt-aext-dst",
                help="set destination for the IP's address extension option",
                type=str,
                default=get_random_ipv4(),
                required=False,
                metavar="<addr>",
            ),
        }
    )
}


def ip_send(opt: PingOptions, data: bytes | None = None) -> None:
    # Build packet
    ip = IP()

    ip.version = opt.ip_ver if opt.ip_ver is not None else 4
    ip.ihl = opt.ip_ihl if opt.ip_ihl is not None else 5
    ip.tos = opt.ip_tos if opt.ip_tos is not None else 0
    ip.len = opt.ip_len if opt.ip_len is not None else 20 + (len(data) if data is not None else 0)
    ip.id = opt.ip_id if opt.ip_id is not None else rand(16)
    ip.flags = opt.ip_flags.upper() if opt.ip_flags is not None else "DF"
    ip.frag = opt.ip_off if opt.ip_off is not None else 0
    ip.ttl = opt.ip_ttl if opt.ip_ttl is not None else 64
    ip.proto = opt.ip_proto if opt.ip_proto is not None else 255
    ip.chksum = opt.ip_sum if opt.ip_sum is not None else 0
    ip.src = opt.ip_src if opt.ip_src is not None else if_addr(opt.interface, "inet")
    ip.dst = opt.ip_dst

    # Add options
    if opt.ip_opt is not None:
        ip_opt_map = {
            "eol": IPOption_EOL(),
            "nop": IPOption_NOP(),
            "sec": IPOption_Security(
                security=opt.ip_opt_sec_sss,
                compartment=opt.ip_opt_sec_ccc,
                handling_restrictions=opt.ip_opt_sec_hhh,
                transmission_control_code=opt.ip_opt_sec_tcc,
            ),
            "lsrr": IPOption_LSRR(
                pointer=opt.ip_opt_rr_ptr,
                routers=opt.ip_opt_rr_data,
            ),
            "ts": IPOption_Timestamp(
                pointer=opt.ip_opt_ts_ptr,
                oflw=opt.ip_opt_ts_oflw,
                flg=opt.ip_opt_ts_flg,
                internet_address=opt.ip_opt_ts_addr,
                timestamp=opt.ip_opt_ts_ts,
            ),
            "rr": IPOption_RR(
                pointer=opt.ip_opt_rr_ptr,
                routers=opt.ip_opt_rr_data,
            ),
            "sid": IPOption_Stream_Id(
                security=opt.ip_opt_sid_id,
            ),
            "ssrr": IPOption_SSRR(
                pointer=opt.ip_opt_rr_ptr,
                routers=opt.ip_opt_rr_data,
            ),
            "tr": IPOption_Traceroute(
                copy_flag=0,
                optclass=2,
                option=18,
                id=opt.ip_opt_tr_id,
                outbound_hops=opt.ip_opt_tr_ohops,
                return_hops=opt.ip_opt_tr_ohops,
                originator_ip=opt.ip_opt_tr_ip,
            ),
            "sdb": IPOption_SDBM(
                addresses=opt.ip_opt_sdb_data,
            ),
            "mtu": IPOption_MTU_Probe(
                option=11 if opt.ip_opt_mtu_type == "probe" else 12,
                mtu=opt.ip_opt_mtu_mtu,
            ),
            "ra": IPOption_Router_Alert(
                alert=opt.ip_opt_ra_alert,
            ),
            "aext": IPOption_Address_Extension(
                src_ext=opt.ip_opt_aext_src,
                dst_ext=opt.ip_opt_aext_dst,
            ),
        }

        data_len = len(data) if data is not None else 0
        ip_len_without_data = ip.len - data_len

        for name in opt.ip_opt:
            name = name.lower()

            if name not in ip_opt_map:
                continue

            ip_opt = ip_opt_map[name]
            next_len = ip_len_without_data + len(ip_opt)

            if next_len >= 60:
                break

            ip = ip / ip_opt
            ip_len_without_data += len(ip_opt)

        if (ip_len_without_data & 3) != 0:
            while (ip_len_without_data & 3) != 0:
                next_len = ip_len_without_data + 1
                if (next_len & 3) == 0:
                    ip = ip / ip_opt_map["eol"]
                    ip_len_without_data += 1
                    break

                ip = ip / ip_opt_map["nop"]
                ip_len_without_data += 1

        if opt.ip_ihl is None:
            ip.ihl = ip_len_without_data >> 2
        if opt.ip_len is None:
            ip.len = ip_len_without_data + data_len

    if opt.ip_sum is None:
        chksum = checksum(raw(ip))
        ip.chksum = chksum

    # Add data
    if data is not None:
        # Upper layer packet or payload
        ip = ip / Raw(data)

    # Fragment if needed
    if len(ip) > opt.mtu:
        if opt.ip_flags is None:
            ip.flags = 0

        fragsize = opt.mtu - (len(ip) - (len(data) if data is not None else 0))
        fragments = fragment(ip, fragsize)
    else:
        fragments = ip

    # Send packet
    send(fragments, count=1, inter=0, verbose=False)
    time.sleep(opt.delay)


def register_send_routine() -> tuple[str, Callable[[PingOptions, bytes | None], None]]:
    return "raw-ip", ip_send


def create_method() -> str:
    return "raw-ip"
