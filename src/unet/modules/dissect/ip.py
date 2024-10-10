from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, addr_to_name, as_bin, as_hex,
                                  hexdump, indent_lines)
from unet.modules.dissect.dl import DLT_EN10MB, DLT_IPV4, DLT_NULL, DLT_RAW
from unet.modules.dissect.eth import EtherType
from unet.modules.dissect.null import NullType
from unet.printing import Assets

__all__ = [
    "IP_HDRLEN",
    "IP",
    "IPDiffServDSCP",
    "IPDiffServECN",
    "IPDS_DSCP_MAP",
    "IPDS_ECN_MAP",
    "IPFlag",
    "IP_FLAGS_MAP",
    "IPProto",
    "IP_PROTO_MAP",
    "IPOpt",
    "IP_OPT_MAP",
    "ip_opt_dissect",
    "ip_opt_eol_or_nop_dissect",
    "ip_dissect",
]


# Plain IP header with no options added
IP_HDRLEN: Final = 20


class IP:
    def __init__(self, buf: bytes) -> None:
        if len(buf) > IP_HDRLEN:
            buf = buf[:IP_HDRLEN]

        ip = struct.unpack("!BBHHHBBH4s4s", buf)
        self.ver = ip[0] >> 4
        self.ihl = ip[0] & 0xf
        self.tos = ip[1]
        self.tlen = ip[2]
        self.id = ip[3]
        self.flags = (ip[4] & 0xe000) >> 13
        self.off = ip[4] & 0x1fff
        self.ttl = ip[5]
        self.proto = ip[6]
        self.chksum = ip[7]
        self.src = str(ipaddress.ip_address(ip[8]))
        self.dst = str(ipaddress.ip_address(ip[9]))


# =======================
# Differentiated Services
# =======================


class IPDiffServDSCP(IntEnum):
    NONE = 0x00
    LE = 0x01
    CS1 = 0x08
    AF11 = 0x0a
    AF12 = 0x0c
    AF13 = 0x0e
    CS2 = 0x10
    AF21 = 0x12
    AF22 = 0x14
    AF23 = 0x16
    CS3 = 0x18
    AF31 = 0x1a
    AF32 = 0x1c
    AF33 = 0x1e
    CS4 = 0x20
    AF41 = 0x22
    AF42 = 0x24
    AF43 = 0x26
    CS5 = 0x28
    VOICE_ADMIT = 0x2c
    EF = 0x2e
    CS6 = 0x30
    CS7 = 0x38


class IPDiffServECN(IntEnum):
    ECT_NOT = 0x00
    ECT_1 = 0x01
    ECT_0 = 0x02
    CE = 0x03


IPDS_DSCP_MAP: Final[dict[int, tuple[str, str]]] = {
    IPDiffServDSCP.NONE: ("none", "none"),
    IPDiffServDSCP.LE: ("le", "low effort"),
    IPDiffServDSCP.CS1: ("cs1", "class selector 1"),
    IPDiffServDSCP.AF11: ("af11", "assure forwarding 11"),
    IPDiffServDSCP.AF12: ("af12", "assure forwarding 12"),
    IPDiffServDSCP.AF13: ("af13", "assure forwarding 13"),
    IPDiffServDSCP.CS2: ("cs2", "class selector 2"),
    IPDiffServDSCP.AF21: ("af21", "assure forwarding 21"),
    IPDiffServDSCP.AF22: ("af22", "assure forwarding 22"),
    IPDiffServDSCP.AF23: ("af23", "assure forwarding 23"),
    IPDiffServDSCP.CS3: ("cs3", "class selector 3"),
    IPDiffServDSCP.AF31: ("af31", "assure forwarding 31"),
    IPDiffServDSCP.AF32: ("af32", "assure forwarding 32"),
    IPDiffServDSCP.AF33: ("af33", "assure forwarding 33"),
    IPDiffServDSCP.CS4: ("cs4", "class selector 4"),
    IPDiffServDSCP.AF41: ("af41", "assure forwarding 41"),
    IPDiffServDSCP.AF42: ("af42", "assure forwarding 42"),
    IPDiffServDSCP.AF43: ("af43", "assure forwarding 43"),
    IPDiffServDSCP.CS5: ("cs5", "class selector 5"),
    IPDiffServDSCP.VOICE_ADMIT: ("vc", "voice-admit"),
    IPDiffServDSCP.EF: ("ef-phb", "expedited forwarding"),
    IPDiffServDSCP.CS6: ("cs6", "class selector 6"),
    IPDiffServDSCP.CS7: ("cs7", "class selector 7"),
}


IPDS_ECN_MAP: Final[dict[int, tuple[str, str]]] = {
    IPDiffServECN.ECT_NOT: ("not-ect", "non-ect"),
    IPDiffServECN.ECT_1: ("ect(1)", "ecn-capable transport codepoint 01"),
    IPDiffServECN.ECT_0: ("ect(0)", "ecn-capable transport codepoint 10"),
    IPDiffServECN.CE: ("ce", "congestion experienced 11"),
}


# =====
# Flags
# =====


class IPFlag(IntEnum):
    MF = 0x1
    DF = 0x2
    EF = 0x4


IP_FLAGS_MAP: Final[dict[int, tuple[str, str]]] = {
    IPFlag.MF: ("mf", "more fragments"),
    IPFlag.DF: ("df", "don't fragment"),
    IPFlag.EF: ("ef", "evil bit"),
}


# =========
# Protocols
# =========


# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
class IPProto(IntEnum):
    HOPOPTS = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPV4 = 4
    ST = 5
    TCP = 6
    CBT = 7
    EGP = 8
    IGP = 9
    BBN_RCC_MON = 10
    NVP_II = 11
    PUP = 12
    EMCON = 14
    XNET = 15
    CHAOS = 16
    UDP = 17
    MUX = 18
    DCN_MEAS = 19
    HMP = 20
    PRM = 21
    XNS_IDP = 22
    TRUNK_1 = 23
    TRUNK_2 = 24
    LEAF_1 = 25
    LEAF_2 = 26
    RDP = 27
    IRTP = 28
    ISO_TP4 = 29
    NETBLT = 30
    MFE_NSP = 31
    MERIT_INP = 32
    DCCP = 33
    PC3 = 34
    IDPR = 35
    XTP = 36
    DDP = 37
    IDPR_CMTP = 38
    TP_PP = 39
    IL = 40
    IPV6 = 41
    SDRP = 42
    IPV6_ROUTE = 43
    IPV6_FRAG = 44
    IDRP = 45
    RSVP = 46
    GRE = 47
    DSR = 48
    BNA = 49
    ESP = 50
    AH = 51
    I_NLSP = 52
    NARP = 54
    MIN_IPV4 = 55
    TLSP = 56
    SKIP = 57
    ICMPV6 = 58
    IPV6_NONXT = 59
    IPV6_OPTS = 60
    CFTP = 61
    SAT_EXPAK = 64
    KRYPTOLAN = 65
    RVD = 66
    IPPC = 67
    SAT_MON = 69
    VISA = 70
    IPCV = 71
    CPNX = 72
    CPHB = 73
    WSN = 74
    PVP = 75
    BR_SAT_MON = 76
    SUN_ND = 77
    WB_MON = 78
    WB_EXPAK = 79
    ISO_IP = 80
    VMTP = 81
    SECURE_VMTP = 82
    VINES = 83
    IPTMP = 84
    NSFNET_IGP = 85
    DGP = 86
    TCF = 87
    EIGRP = 88
    OSPFIGP = 89
    SPRITE_RPC = 90
    LARP = 91
    MTP = 92
    AX_25 = 93
    IPIP = 94
    SSC_SP = 96
    ETHERIP = 97
    ENCAP = 98
    GMTP = 100
    IFMP = 101
    PNNI = 102
    PIM = 103
    ARIS = 104
    SCPS = 105
    QNX = 106
    IPCOMP = 108
    SNP = 109
    COMPAQ_PEER = 110
    IPX_IN_IP = 111
    VRRP = 112
    PGM = 113
    L2TP = 115
    DDX = 116
    IATP = 117
    STP = 118
    SRP = 119
    UTI = 120
    SMP = 121
    PTP = 123
    ISIS_OVER_IPV4 = 124
    FIRE = 125
    CRTP = 126
    CRUDP = 127
    SSCOPMCE = 128
    IPLT = 129
    SPS = 130
    PIPE = 131
    SCTP = 132
    FC = 133
    RSVP_E2E_IGNORE = 134
    MOBILITY = 135
    UDP_LITE = 136
    MPLS_IN_IP = 137
    MANET = 138
    HIP = 139
    SHIM6 = 140
    WESP = 141
    ROHC = 142
    ETHERNET = 143
    AGGFRAG = 144
    NSH = 145


IP_PROTO_MAP: Final[dict[int, str]] = {
    0: "IPv6-HopOpts",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISP-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "ICMPv6",
    59: "IPv6-NoNext",
    60: "IPv6-DestOpts",
    61: "Any Host Internal Protocol",
    62: "CFTP",
    63: "Any Local Network",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "Any Distributed File System",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "Any private encryption scheme",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "Any 0-hop protocol",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "IPv6-Mobility",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
} | {
    num: "Unassigned" for num in range(146, 253)
} | {
    253: "Use for experimentation and testing",
    254: "Use for experimentation and testing",
    255: "Reserved",
}


# =======
# Options
# =======


# https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
class IPOpt(IntEnum):
    EOOL = 0
    NOP = 1
    SEC = 130
    LSR = 131
    TS = 68
    ESEC = 133
    CIPSO = 134
    RR = 7
    SID = 136       # Deprecated
    SSR = 137
    ZSU = 10
    MTUP = 11       # Deprecated
    MTUR = 12       # Deprecated
    FINN = 205      # Deprecated
    VISA = 142      # Deprecated
    ENCODE = 15     # Deprecated
    IMITD = 144
    EIP = 145       # Deprecated
    TR = 82         # Deprecated
    ADDEXT = 147    # Deprecated
    RTRALT = 148
    SDB = 149       # Deprecated
    DPS = 151       # Deprecated
    UMP = 152       # Deprecated
    QS = 25
    # 30, 94, 158, 222 - Experimental


IP_OPT_MAP: Final[dict[int, tuple[str, str]]] = {
    IPOpt.EOOL: ("EOOL", "end of options list"),
    IPOpt.NOP: ("NOP", "no operation"),
    IPOpt.SEC: ("SEC", "security"),
    IPOpt.LSR: ("LSR", "loose source route"),
    IPOpt.TS: ("TS", "time stamp"),
    IPOpt.ESEC: ("E-SEC", "extended security"),
    IPOpt.CIPSO: ("CIPSO", "commercial security"),
    IPOpt.RR: ("RR", "record route"),
    IPOpt.SID: ("SID", "stream identifier"),                # Deprecated
    IPOpt.SSR: ("SSR", "strict source route"),
    IPOpt.ZSU: ("ZSU", "experimental measurement"),
    IPOpt.MTUP: ("MTUP", "mtu probe"),                      # Deprecated
    IPOpt.MTUR: ("MTUR", "mtu reply"),                      # Deprecated
    IPOpt.FINN: ("FINN", "experimental flow control"),
    IPOpt.VISA: ("VISA", "experimental access control"),    # Deprecated
    IPOpt.ENCODE: ("ENCODE", "ENCODE"),                     # Deprecated
    IPOpt.IMITD: ("IMITD", "imi traffic descriptor"),
    IPOpt.EIP: ("EIP", "extended internet protocol"),       # Deprecated
    IPOpt.TR: ("TR", "traceroute"),                         # Deprecated
    IPOpt.ADDEXT: ("ADDEXT", "address extension"),          # Deprecated
    IPOpt.RTRALT: ("RTRALT", "router alert"),
    IPOpt.SDB: ("SDB", "selective directed broadcast"),     # Deprecated
    IPOpt.DPS: ("DPS", "dynamic packet state"),             # Deprecated
    IPOpt.UMP: ("UMP", "upstream multicast packet"),        # Deprecated
    IPOpt.QS: ("QS", "quick-start"),
}


_IP_OPT_TYPE_FLAG_MAP: Final = {
    0: "not copied",
    1: "copied"
}


_IP_OPT_TYPE_CLASS_MAP: Final = {
    0: "control",
    1: "reserved",
    2: "debugging and measurement",
    3: "reserved",
}


def _add_ip_opt_type_field(f: FieldFormatter, opt_type: int) -> None:
    try:
        name = f"{IP_OPT_MAP[opt_type][1]} ({IP_OPT_MAP[opt_type][0]})"
    except KeyError:
        name = "unknown"
    copy_flag = (opt_type & 0x80) >> 7
    opt_class = (opt_type & 0x60) >> 5
    opt_num = opt_type & 0x1f

    type_field = f.add_field("type", opt_type, alt_value=name)
    type_field.add_field("copy flag", as_bin(copy_flag, 8, 0, 1), bin_field=True,
                         alt_value=f"{_IP_OPT_TYPE_FLAG_MAP[copy_flag]} ({copy_flag})")
    type_field.add_field("class", as_bin(opt_class, 8, 1, 2), bin_field=True,
                         alt_value=f"{_IP_OPT_TYPE_CLASS_MAP[opt_class]} ({opt_class})")
    type_field.add_field("number", as_bin(opt_num, 8, 3, 5), bin_field=True,
                         alt_value=opt_num)
    type_field.add_field("type", as_bin(opt_type, 8, 0, 8), bin_field=True,
                         sep=" = ")


def ip_opt_eol_or_nop_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]

    if len(buf) != 1:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {len(buf)}, MUST BE 1"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", len(buf))

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_sec_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 11:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 11"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", len(buf))

    # Security
    sss = struct.unpack('!H', buf[2:4])[0]
    sss_field = f.add_field("sss", sss, alt_value=as_bin(sss, 16, 0, 16))

    # Compartments
    ccc = struct.unpack('!H', buf[4:6])[0]
    ccc_field = f.add_field("ccc", ccc)
    if not ccc:
        ccc_field.add_note("not compartmented")

    # Handling Restrictions
    hhh = struct.unpack('!H', buf[6:8])[0]
    hhh_field = f.add_field("hhh", hhh)

    # Transmission Control Code
    tcc = struct.unpack('!3s', buf[8:11])[0]
    tcc_field = f.add_field("tcc", as_hex(int.from_bytes(tcc, 'big'), 6),
                            alt_value=tcc.decode())

    sss_field.name = "security"
    ccc_field.name = "compartments"
    hhh_field.name = "handling restrictions"
    tcc_field.name = "transmission control code"

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# LSR, RR, SSR
def ip_opt_route_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != len(buf):
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len} != {len(buf)}"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    ptr = buf[2]
    route_data = buf[3:]
    route_data_len = opt_len - 3

    # Length
    if opt_len < 3:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = (f"IP ROUTE OPTION INVALID LENGTH: {opt_len}, "
                            "MUST BE MINIMUM 3 BYTES")
        return ""

    len_field = f.add_field("len", opt_len)

    # Pointer
    ptr_field = f.add_field("ptr", ptr)
    if opt_len > 3 and ptr < 4:
        ptr_field.add_note("")

    # Route data
    data_field = f.add_field("data", route_data_len, unit="bytes")
    resolved_data = []

    if opt_len > 3:
        for off in range(0, route_data_len, 4):
            addr = socket.inet_ntoa(route_data[off:off + 4])
            resolved_data.append(addr)

    if pkto.verbose:
        for addr in resolved_data:
            data_field.add_field("address", addr)

    len_field.name = "length"
    ptr_field.name = "pointer"
    data_field.name = "route data"

    dump = f.line("len", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


_IP_OPT_TS_FLG_MAP = {
    0: "time stamps only",
    1: "timestamp preceded with internet address",
    3: "prespecified addresses",
}


def ip_opt_ts_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != len(buf):
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len} != {len(buf)}"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    ptr = buf[2]
    oflw = (buf[3] & 0xf0) >> 4
    flg = buf[3] & 0x0f
    data = buf[4:]

    # Length
    f.add_field("length", opt_len)

    # Pointer
    ptr_field = f.add_field("ptr", ptr)
    if ptr > opt_len:
        ptr_field.add_note("timestamp data area full, no timestamp will be inserted")

    # Overflow
    oflw_field = f.add_field("oflw", as_bin(oflw, 8, 0, 4), bin_field=True,
                             alt_value=oflw)

    # Flag
    flg_field = f.add_field("flg", as_bin(flg, 8, 4, 4), bin_field=True,
                            alt_value=f"{flg} ({_IP_OPT_TS_FLG_MAP[flg]})")

    # Data
    data_field = f.add_field("tsdata", len(data), unit="bytes")
    resolved_data = []

    if flg == 0:
        for off in range(0, len(data), 4):
            ts = struct.unpack("!L", data[off:off + 4])
            resolved_data.append(ts)
    elif flg in {1, 3}:
        ts_next = False

        for off in range(0, len(data), 4):
            if not ts_next:
                elem = socket.inet_ntoa(data[off:off + 4])
                ts_next = True
            else:
                elem = struct.unpack("!L", data[off:off + 4])[0]
                ts_next = False

            resolved_data.append(elem)
    else:
        data_field.add_note(f"invalid flag value: {flg}")

    if pkto.verbose:
        for elem in resolved_data:
            name = "address" if isinstance(elem, str) else "timestamp"
            data_field.add_field(name, elem)

    ptr_field.name = "pointer"
    oflw_field.name = "overflow"
    flg_field.name = "flag"
    data_field.name = "timestamp data"

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_sid_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 4:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 4"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    sid = struct.unpack("!H", buf[2:])[0]
    f.add_field("stream id", as_hex(sid, 4), alt_value=sid, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_rtralt_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 4:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 4"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    alert = struct.unpack("!H", buf[2:])[0]
    alert_str = "router shall examine packet" if alert == 0 else "reserved"
    f.add_field("value", alert_str, alt_value=alert, alt_value_brackets=("(", ")"),
                alt_sep=" ")

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_mtu_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 4:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 4"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    mtu = struct.unpack("!H", buf[2:])[0]
    f.add_field("mtu", mtu)

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_traceroute_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 12:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 12"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    # ID
    id_value = struct.unpack("!H", buf[2:4])[0]
    f.add_field("id", id_value)

    # Outbound Hop Count
    outbound_hop_count = struct.unpack("!H", buf[4:6])[0]
    f.add_field("outbound hop count", outbound_hop_count)

    # Return Hop Count
    return_hop_count = struct.unpack("!H", buf[6:8])[0]
    f.add_field("return hop count", return_hop_count)

    # Originator IP Address
    originator_ip = socket.inet_ntoa(buf[8:12])
    f.add_field("originator ip address", originator_ip)

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_cipso_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len < 6:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE AT LEAST 6"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    # DOI (Domain of Interpretation)
    doi = struct.unpack("!L", buf[2:6])[0]
    f.add_field("doi", doi)

    # Process tags
    offset = 6
    while offset < opt_len:
        tag_type = buf[offset]
        tag_len = buf[offset + 1] if offset + 1 < opt_len else 0

        if offset + tag_len > opt_len:
            pkti.invalid = True
            pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
            pkti.invalid_msg = f"TAG LENGTH {tag_len} EXCEEDS OPTION LENGTH"
            break

        tag_field = f.add_field("tag type", tag_type)
        tag_field.add_field("length", tag_len)

        if tag_type == 1:  # Sensitivity Level
            if tag_len >= 3:
                sens_level = buf[offset + 2]
                tag_field.add_field("sensitivity level", sens_level)
        elif tag_type == 2:  # Category
            categories = buf[offset + 2:offset + tag_len]
            cat_field = tag_field.add_field("categories", len(categories), unit="bytes")
            if pkto.verbose:
                for i, category in enumerate(categories):
                    cat_field.add_field(f"category {i + 1}", category)
        elif tag_type == 5:  # Enumerated Categories
            if tag_len >= 4:
                enum_cat = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
                tag_field.add_field("enumerated categories", enum_cat)
        elif tag_type == 6:  # Range of Categories
            if tag_len >= 5:
                low_cat = buf[offset + 2]
                high_cat = buf[offset + 3]
                tag_field.add_field("low category", low_cat)
                tag_field.add_field("high category", high_cat)
        elif tag_type == 7:  # Bit Map for Categories
            bitmap = buf[offset + 2:offset + tag_len]
            bitmap_field = tag_field.add_field("category bitmap", len(bitmap), unit="bytes")
            if pkto.verbose:
                for i, byte in enumerate(bitmap):
                    bitmap_field.add_field(f"byte {i + 1}",
                                           as_bin(byte, 8, 0, 8), bin_field=True)

        offset += tag_len

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_esec_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len < 9:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE AT LEAST 9"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    # Format Identifier
    format_id = buf[2]
    f.add_field("format identifier", format_id)

    # Security Level
    sec_level = struct.unpack('!H', buf[3:5])[0]
    f.add_field("security level", sec_level)

    # Compartment Bitmap
    compartment_bitmap = struct.unpack('!L', buf[5:9])[0]
    bitmap_field = f.add_field("compartment bitmap",
                               as_bin(compartment_bitmap, 32, 0, 32),
                               bin_field=True)

    # Handling Restrictions
    if opt_len >= 11:
        handling_restrictions = struct.unpack('!H', buf[9:11])[0]
        f.add_field("handling restrictions", as_hex(handling_restrictions, 4))

    # Release Markings
    if opt_len > 11:
        release_markings = buf[11:opt_len]
        release_field = f.add_field("release markings", len(release_markings),
                                    unit="bytes")
        if pkto.verbose:
            for i, byte in enumerate(release_markings):
                release_field.add_field(f"byte {i + 1}", as_hex(byte, 2))

    # Additional fields based on Format Identifier
    if format_id == 0:
        bitmap_field.add_note("GENSER format")
    elif format_id == 1:
        bitmap_field.add_note("SIOP-ESI format")
    else:
        bitmap_field.add_note(f"Unknown format: {format_id}")

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_qs_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len != 8:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE 8"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    # Func field (1 byte)
    func = buf[2]
    func_field = f.add_field("func", as_bin(func, 8, 0, 8), bin_field=True)

    # Rate field (30 bits)
    rate = struct.unpack("!I", buf[3:7])[0] >> 2
    rate_field = f.add_field("rate", as_bin(rate, 30, 0, 30), bin_field=True)

    # TTL field (6 bits)
    ttl = ((buf[6] & 0x03) << 4) | (buf[7] >> 4)
    ttl_field = f.add_field("ttl", as_bin(ttl, 6, 0, 6), bin_field=True)

    # Parsing Func field
    func_type = (func & 0xf0) >> 4
    func_type_field = func_field.add_field("type", func_type)
    if func_type == 0:
        func_type_field.add_note("Rate Request")
    elif func_type == 8:
        func_type_field.add_note("Rate Report")
    else:
        func_type_field.add_note("Unknown")

    func_field.add_field("reserved", as_bin(func & 0x0f, 8, 4, 4), bin_field=True)

    # Parsing Rate field
    rate_kbps = rate * 40
    rate_field.add_field("rate", f"{rate_kbps} kbps")

    # Parsing TTL field
    ttl_field.add_field("ttl", ttl)

    # Check for QS Nonce
    qs_nonce = ((buf[6] & 0x03) << 14) | (buf[7] & 0x0f)
    f.add_field("qs nonce", as_bin(qs_nonce, 16, 0, 16), bin_field=True)

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_sdb_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    if opt_len < 2:
        pkti.invalid = True
        pkti.invalid_proto_name = f"IP Option {IP_OPT_MAP[opt_type][1]}"
        pkti.invalid_msg = f"BOGUS LENGTH: {opt_len}, MUST BE AT LEAST 2"
        return ""

    f = FieldFormatter(IP_OPT_MAP[opt_type][0])
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len)

    addresses = []
    data = buf[2:]
    for off in range(0, len(data), 4):
        addr = socket.inet_ntoa(data[off:off + 4])
        addresses.append(addr)

    if pkto.verbose:
        data_field = f.add_field("data", len(addresses) * 4, unit="bytes")
        for addr in addresses:
            data_field.add_field("address", addr)

    dump = f.line("length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip_opt_unk_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    opt_type = buf[0]
    opt_len = buf[1]

    f = FieldFormatter("Unknown IP option")
    _add_ip_opt_type_field(f, opt_type)

    f.add_field("length", opt_len, unit="bytes" if len(buf) > 1 else "byte")

    dump = f.line("length", "bytes" if len(buf) > 1 else "byte")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


_IP_OPT_DISSECTOR_MAP: Final[dict[int, Callable[[PacketOptions, PacketInfo, bytes], str]]] = {
    IPOpt.EOOL: ip_opt_eol_or_nop_dissect,
    IPOpt.NOP: ip_opt_eol_or_nop_dissect,
    IPOpt.SEC: ip_opt_sec_dissect,
    IPOpt.LSR: ip_opt_route_dissect,
    IPOpt.TS: ip_opt_ts_dissect,
    IPOpt.ESEC: ip_opt_esec_dissect,
    IPOpt.CIPSO: ip_opt_cipso_dissect,
    IPOpt.RR: ip_opt_route_dissect,
    IPOpt.SID: ip_opt_sid_dissect,
    IPOpt.SSR: ip_opt_route_dissect,
    IPOpt.MTUP: ip_opt_mtu_dissect,
    IPOpt.MTUR: ip_opt_mtu_dissect,
    IPOpt.TR: ip_opt_traceroute_dissect,
    IPOpt.RTRALT: ip_opt_rtralt_dissect,
    IPOpt.SDB: ip_opt_sdb_dissect,
    IPOpt.QS: ip_opt_qs_dissect,
}


_IP_OPT_MIN_LEN_MAP: Final[dict[int, int]] = {
    IPOpt.EOOL: 1,
    IPOpt.NOP: 1,
    IPOpt.SEC: 11,
    IPOpt.LSR: 3,
    IPOpt.TS: 4,
    IPOpt.ESEC: 3,
    IPOpt.CIPSO: 10,
    IPOpt.RR: 3,
    IPOpt.SID: 4,
    IPOpt.SSR: 3,
    IPOpt.MTUP: 4,
    IPOpt.MTUR: 4,
    IPOpt.TR: 12,
    IPOpt.RTRALT: 4,
    IPOpt.SDB: 6,
    IPOpt.QS: 8,
}


def ip_opt_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> list[str]:
    results = []
    off = 0

    while off < len(buf):
        opt_type = buf[off]

        if opt_type not in IPOpt:
            return [f"[IP unknown option type: {opt_type}]"]

        if opt_type == IPOpt.EOOL or opt_type == IPOpt.NOP:
            opt_len = 1
        else:
            opt_len = buf[off + 1]

        if opt_len < _IP_OPT_MIN_LEN_MAP[opt_type]:
            name = (IP_OPT_MAP[opt_type][0] if not pkto.verbose else
                    f"{IP_OPT_MAP[opt_type][1]} ({IP_OPT_MAP[opt_type][0]})")
            return [f"[IP option: {name} [length too short: {opt_len}]]"]

        current_opt = buf[off:off + opt_len]
        try:
            dissected_opt: str = _IP_OPT_DISSECTOR_MAP[opt_type](pkto, pkti, current_opt)
        except KeyError:
            dissected_opt = ip_opt_unk_dissect(pkto, pkti, buf)

        if pkti.invalid:
            return []

        results.append(dissected_opt)
        off += opt_len

    return results


def ip_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "IP"
    f = FieldFormatter(protocol)

    if len(buf) < IP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID IP PACKET"
        return ""

    ip = IP(buf[:IP_HDRLEN])

    ver = ip.ver
    ihl = ip.ihl
    hlen = ihl << 2

    if ver != 4:
        if ver == 6:
            from unet.modules.dissect.ip6 import ip6_dissect
            return ip6_dissect(pkto, pkti, buf)
        else:
            pkti.invalid = True
            pkti.invalid_proto_name = protocol
            pkti.invalid_msg = f"INVALID VERSION: {ver}"
            return ""

    if hlen < IP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"INVALID HEADER LENGTH: {hlen} ({ihl})"
        return ""

    # Version
    ver_field = f.add_field("ver", as_bin(ver, 8, 0, 4), bin_field=True,
                            sep=" = ", alt_value=ver, alt_sep=": ")

    # Header Length
    ihl_field = f.add_field("ihl", as_bin(ihl, 8, 4, 4), bin_field=True,
                            sep=" = ", alt_value=hlen, alt_unit="bytes",
                            alt_sep=": ")
    ihl_field.add_note(str(ihl))

    # Differentiated Services
    ds = ip.tos
    dscp = ds >> 2
    ecn = ds & 0x03

    ds_field = f.add_field("ds", as_hex(ds, 2))
    dscp_field = ds_field.add_field("differentiated services codepoint",
                                    as_bin(dscp, 8, 0, 6), bin_field=True, sep=" = ",
                                    alt_value=dscp, alt_sep=": ")

    set_dscp: list[str] = []
    for val, names in IPDS_DSCP_MAP.items():
        if val == dscp:
            set_dscp.append(names[1])
            break

    if dscp != 0 and not len(set_dscp):
        set_dscp.append(f"unknown ({dscp})")

    dscp_field.add_note(", ".join(set_dscp))
    ecn_field = ds_field.add_field("explicit congestion notification", as_bin(ecn, 8, 6, 2),
                                   bin_field=True, sep=" = ", alt_value=ecn, alt_sep=": ")

    set_ecn: list[str] = []
    for val, names in IPDS_ECN_MAP.items():
        if val == ecn:
            set_ecn.append(names[1])
            break

    ecn_field.add_note(", ".join(set_ecn))

    # Total Length
    tlen = ip.tlen
    tlen_field = f.add_field("tlen", tlen, unit="bytes")

    if tlen < hlen:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"INVALID TOTAL LENGTH: {tlen}, LESS THAN HEADER LENGTH: {hlen}"
        return ""

    # Identification
    id = ip.id
    id_field = f.add_field("id", f"{as_hex(id, 4)}", alt_value=id)

    # Flags
    flags = ip.flags
    set_flags: list[str] = []

    for val, names in IP_FLAGS_MAP.items():
        if flags & val:
            set_flags.append(f"{names[0]}")

    if not len(set_flags):
        set_flags.append("none")

    flags_field = f.add_field("flags", as_hex(flags, 1), alt_value=", ".join(set_flags),
                              alt_value_brackets=("[", "]"), alt_sep=" ")

    flag_bits = [
        (int(bool(flags & IPFlag.EF)), "evil bit", 0),
        (int(bool(flags & IPFlag.DF)), "don't fragment", 1),
        (int(bool(flags & IPFlag.MF)), "more fragments", 2),
    ]
    for has, name, off in flag_bits:
        flags_field.add_field(name, as_bin(has, 3, off, 1), bin_field=True,
                              sep=" = ", alt_value="set" if has else "not set",
                              alt_sep=": ")

    if flags > IPFlag.DF:
        flags_field.add_note("flags value exceeds usable bound, might be a "
                             "manually crafted packet")

    # Fragment offset
    off = ip.off
    off_field = f.add_field("off", as_bin(off, 16, 3, 13), bin_field=True,
                            sep=" = ", alt_value=(off << 3), alt_sep=": ")

    if (flags & 0x1) and (not pkti.fragmented):
        pkti.fragmented = True

    if pkti.fragmented:
        pkti.add_fragment(buf[hlen:tlen])
        off_field.add_note("fragmented IP datagram")

    if (off << 3) > 0 and not (flags & 0x1):
        pkti.fragmented = False
        pkti.defragment = True

    # Time to Tive
    ttl = ip.ttl
    ttl_field = f.add_field("ttl", ttl)
    if ttl < 5:
        ttl_field.add_note(f"ttl only {ttl}")

    # Protocol
    proto = ip.proto
    try:
        proto_str = IP_PROTO_MAP[proto]
    except KeyError:
        proto_str = "unknown"

    proto_field = f.add_field("proto", proto_str, alt_value=proto,
                              alt_value_brackets=("(", ")"), alt_sep=" ")

    # Checksum
    chksum = ip.chksum
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf[:hlen])
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

    # Source address
    src = ip.src
    if not pkto.numeric_ip:
        src_numeric = src
        src = addr_to_name(src)

    src_field = f.add_field("src", src)

    if not pkto.numeric_ip:
        src_field.add_field("numeric", src_numeric, sep=" = ")

    # Destination address
    dst = ip.dst
    if not pkto.numeric_ip:
        dst_numeric = dst
        dst = addr_to_name(ip.dst)

    dst_field = f.add_field("dst", dst)

    if not pkto.numeric_ip:
        dst_field.add_field("numeric", dst_numeric, sep=" = ")

    # Options
    opt_buf = buf[IP_HDRLEN:hlen]
    if len(opt_buf):
        if pkto.verbose:
            opt_field = f.add_field("options", len(opt_buf), unit="bytes")
            opts = ip_opt_dissect(pkto, pkti, opt_buf)

            if pkti.invalid:
                return ""

            for opt in opts:
                opt = indent_lines(opt, 6)
                opt_field.add_field("IP option", "\n" + opt)
        else:
            opts = ", ".join(ip_opt_dissect(pkto, pkti, opt_buf))
            opt_field = f.add_field("options", f"{len(opt_buf)} bytes, [{opts}]")
    else:
        f.add_field("options", "[not set]")

    # Hexdump
    if pkto.dump_chunk:
        ip_hexdump = hexdump(buf[:hlen], indent=4)
        f.add_field("hexdump", "\n" + ip_hexdump)

    # Update packet info
    pkti.remaining -= hlen if not pkti.fragmented else tlen
    pkti.dissected += hlen if not pkti.fragmented else tlen

    if pkti.remaining > 0:
        pkti.next_proto = proto
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    if pkti.prev_proto == DLT_EN10MB:
        pkti.current_proto = EtherType.IP
    elif pkti.prev_proto == DLT_NULL:
        pkti.current_proto = NullType.BSD_AF_INET
    elif pkti.prev_proto == DLT_RAW:
        pkti.current_proto = 0
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = protocol

    if pkto.numeric_ip:
        pkti.net_src = src
        pkti.net_dst = dst
    else:
        pkti.net_src = src_numeric
        pkti.net_dst = dst_numeric

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["ip"] = f
    pkti.proto_stack.append("ip")

    # Set more descriptive name for each field
    ver_field.name = "version"
    ihl_field.name = "header length"
    ds_field.name = "differentiated services"
    tlen_field.name = "total length"
    id_field.name = "identification"
    # Don't need to change the flags field name
    off_field.name = "fragment offset"
    ttl_field.name = "time to live"
    proto_field.name = "protocol"
    chksum_field.name = "checksum"
    src_field.name = "source address"
    dst_field.name = "destination address"

    if not pkti.fragmented:
        dump = f.line("src", Assets.RIGHTWARDS_ARROW, "dst", len="tlen",
                      proto="proto", options="options")
    else:
        dump = f.line("src", Assets.RIGHTWARDS_ARROW, "dst", "fragmented",
                      len="tlen", proto="proto", off=str((off << 3)), id="id")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_ip(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("ip", "Internet Protocol", "dl.type", DLT_IPV4, ip_dissect)
    register("ip", "Internet Protocol", "eth.type", 0x0800, ip_dissect)
    register("ip", "Internet Protocol", "null.proto_type", 2, ip_dissect)
    register("ip", "Internet Protocol", "ip.proto", 4, ip_dissect)
    register("ip", "Internet Protocol", "icmp.data", 0, ip_dissect)


def create_dissector_entry() -> str:
    return "ip.proto"
