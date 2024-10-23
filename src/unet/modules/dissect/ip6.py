from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, addr_to_name, as_bin, as_hex,
                                  hexdump, hexstr)
from unet.modules.dissect.dl import DLT_EN10MB, DLT_IPV6, DLT_NULL, DLT_RAW
from unet.modules.dissect.ip import (IP_PROTO_MAP, IPDS_DSCP_MAP, IPDS_ECN_MAP,
                                     IPProto)
from unet.modules.dissect.platform import DARWIN, FREEBSD, NETBSD, OPENBSD
from unet.printing import Assets

__all__ = [
    "IP6_HDRLEN",
    "IPv6",
    "IPv6ExtHeader",
    "IP6_EXT_HDR_MAP",
    "IPv6Opt",
    "IP6_OPT_MAP",
    "ip6_ext_hdr_hop_opts_dissect",
    "ip6_ext_hdr_route_dissect",
    "ip6_ext_hdr_fragment_dissect",
    "ip6_ext_hdr_dest_opts_dissect",
    "ip6_dissect",
    "register_dissector_ip6",
]


IP6_HDRLEN: Final = 40


class IPv6:
    def __init__(self, buf: bytes) -> None:
        if len(buf) > IP6_HDRLEN:
            buf = buf[:IP6_HDRLEN]

        ip6 = struct.unpack("!LHBB16s16s", buf)
        self.ver = (ip6[0] & 0xf0000000) >> 28
        self.tcls = (ip6[0] & 0x0ff00000) >> 20
        self.flow = (ip6[0] & 0x000fffff)
        self.plen = ip6[1]
        self.nh = ip6[2]
        self.hop = ip6[3]
        self.src = str(ipaddress.ip_address(ip6[4]))
        self.dst = str(ipaddress.ip_address(ip6[5]))


# https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml


# ======================
# Extension Header Types
# ======================


class IPv6ExtHeader(IntEnum):
    HOP_OPTS = 0            # Hop-by-Hop Option
    ROUTE = 43              # Routing Header
    FRAGMENT = 44           # Fragment Header
    ESP = 50                # Encapsulating Security Payload
    AUTH_HDR = 51           # Authentication Header
    DEST_OPTS = 60          # Destination Options
    MOBILITY = 135          # Mobility Header
    HOST_IDENTITY = 139     # Host Identity Protocol
    SHIM6 = 140             # Shim6 Protocol


IP6_EXT_HDR_MAP: Final = {
    IPv6ExtHeader.HOP_OPTS: ("HOP-OPTS", "hop-by-hop option"),
    IPv6ExtHeader.ROUTE: ("ROUTE", "routing header"),
    IPv6ExtHeader.FRAGMENT: ("FRAGMENT", "fragment header"),
    IPv6ExtHeader.ESP: ("ESP", "encapsulating security payload"),
    IPv6ExtHeader.AUTH_HDR: ("AUTH_HDR", "authentication header"),
    IPv6ExtHeader.DEST_OPTS: ("DEST-OPTS", "destination options"),
    IPv6ExtHeader.MOBILITY: ("MOBILITY", "mobility header"),
    IPv6ExtHeader.HOST_IDENTITY: ("HOST-IDENTITY", "host identity protocol"),
    IPv6ExtHeader.SHIM6: ("SHIM6", "shim6 protocol")
}


# ==================================
# Destination and Hop-by-Hop Options
# ==================================


class IPv6Opt(IntEnum):
    PAD1 = 0x00             # Pad1
    PADN = 0x01             # PadN
    JUMBO_PAYLOAD = 0xc2    # Jumbo Payload
    RPL = 0x23              # RPL Option
    TEL = 0x04              # Tunnel Encapsulation Limit
    ROUTER_ALERT = 0x05     # Router Alert
    QUICK_START = 0x26      # Quick-Start
    CALIPSO = 0x07          # CALIPSO
    SMF_DPD = 0x08          # SMF_DPD
    HOME_ADDR = 0xc9        # Home Address
    ILNP_NONCE = 0x8b       # ILNP Nonce
    LI = 0x8c               # Line-Identification
    MPL = 0x6d              # MPL
    IP_DFF = 0xee           # IP_DFF
    PDM = 0x0f              # Performance and Diagnostic Metrics
    MPMH = 0x30             # Minimum Path MTU Hop-by-Hop Option
    IOAM = 0x31             # IOAM Destination Option and IOAM Hop-by-Hop Option
    ALTMARK = 0x12          # AltMark
    # 10011-11101 - Unassigned


IP6_OPT_MAP: Final = {
    IPv6Opt.PAD1: ("pad1",) * 2,
    IPv6Opt.PADN: ("padn",) * 2,
    IPv6Opt.JUMBO_PAYLOAD: ("jumbo payload",) * 2,
    IPv6Opt.RPL: ("RPL", "rpl option"),
    IPv6Opt.TEL: ("TEL", "tunnel encapsulation limit"),
    IPv6Opt.ROUTER_ALERT: ("router alert",) * 2,
    IPv6Opt.QUICK_START: ("quick-start",) * 2,
    IPv6Opt.CALIPSO: ("calipso",) * 2,
    IPv6Opt.SMF_DPD: ("smf dpd",) * 2,
    IPv6Opt.HOME_ADDR: ("HOME-ADDR", "home address"),
    IPv6Opt.ILNP_NONCE: ("ilnp nonce",) * 2,
    IPv6Opt.LI: ("LI", "line-identifdication"),
    IPv6Opt.MPL: ("mpl",) * 2,
    IPv6Opt.IP_DFF: ("ip_dff",) * 2,
    IPv6Opt.PDM: ("PDM", "performance and diagnostic metrics"),
    IPv6Opt.MPMH: ("MPMH", "minimum path mtu hop-by-hop option"),
    IPv6Opt.IOAM: ("ioam",) * 2,
    IPv6Opt.ALTMARK: ("altmark",) * 2,
}


def ip6_ext_hdr_hop_opts_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    protocol = "IPv6 Hop-by-Hop Options Header"

    if len(buf) < 2:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE AT LEAST 2"
        return ""

    f = FieldFormatter(protocol)

    nh = buf[0]
    length = buf[1]
    length2 = (length + 1) * 8

    # Next Header
    nh_field = f.add_field("nh", IP_PROTO_MAP[nh], alt_value=nh,
                           alt_value_brackets=("(", ")"), alt_sep=" ")

    if pkti.current_proto != IPProto.IPV6:
        nh_field.add_note("wrong order, hop-by-hop options have to be preceded "
                          "with the IPv6 header")

    # Length
    len_field = f.add_field("len", length)
    len2_field = f.add_field("len2", length2, unit="bytes", virtual=True)

    if length2 > 0:
        data_field = f.add_field("data", (length2 - 2), unit="bytes")
        data_field.add_field("dump", hexstr(buf[2:length2], 40))

    # Update packet info
    pkti.remaining -= length2
    pkti.dissected += length2

    if pkti.remaining > 0:
        pkti.next_proto = nh
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = IPProto.HOPOPTS
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = protocol

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["hopopts6"] = f
    pkti.proto_stack.append("hopopts6")

    # Update names
    nh_field.name = "next header"
    len_field.name = "length"
    len2_field.name = "length"

    dump = f.line(len="len2")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip6_ext_hdr_route_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    protocol = "IPv6 Routing Header"

    if len(buf) < 4:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE AT LEAST 4"
        return ""

    f = FieldFormatter(protocol)

    nh = buf[0]
    length = buf[1]
    length2 = (length + 1) * 8
    routing_type = buf[2]
    segments_left = buf[3]

    # Next Header
    nh_field = f.add_field("nh", IP_PROTO_MAP[nh], alt_value=nh,
                           alt_value_brackets=("(", ")"), alt_sep=" ")
    # Length
    len_field = f.add_field("len", length)
    len2_field = f.add_field("len2", length2, unit="bytes", virtual=True)

    # Routing Type
    routing_type_map = {
        0: "source route (deprecated)",
        1: "nimrod (deprecated 2009-05-06)",
        2: "type 2 routing header",
        3: "rpl source route header",
        4: "segment routing header (srh)",
        5: "crh-16",
        6: "crh-32",
    }
    routing_type_map |= {num: "unassigned" for num in range(7, 253)}
    routing_type_map |= {
        253: "rfc3692-style experiment 1",
        254: "rfc3692-style experiment 2",
        255: "reserved",
    }

    rtype_field = f.add_field("rtype", routing_type_map[routing_type],
                              alt_value=routing_type,
                              alt_value_brackets=("(", ")"), alt_sep=" ")

    # Segments Left
    sleft_field = f.add_field("sleft", segments_left)

    # Update packet info
    pkti.remaining -= length2
    pkti.dissected += length2

    if pkti.remaining > 0:
        pkti.next_proto = nh
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = IPProto.IPV6_ROUTE
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = protocol

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["route6"] = f
    pkti.proto_stack.append("route6")

    # Update names
    nh_field.name = "next header"
    len_field.name = "length"
    len2_field.name = "length"
    rtype_field.name = "routing type"
    sleft_field.name = "segments left"

    dump = f.line(len="len2")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip6_ext_hdr_fragment_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    protocol = "IPv6 Fragment Header"

    if len(buf) < 8:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE 8"
        return ""

    f = FieldFormatter(protocol)

    nh = buf[0]
    rsvrd = buf[1]
    off = (struct.unpack("!H", buf[2:4])[0] & 0xfff8) >> 3
    off_rsvrd = (struct.unpack("!H", buf[2:4])[0] & 0x6) >> 1
    m = struct.unpack("!H", buf[2:4])[0] & 0x1
    id = struct.unpack("!I", buf[4:8])[0]

    # Next Header
    nh_field = f.add_field("nh", IP_PROTO_MAP[nh], alt_value=nh,
                           alt_value_brackets=("(", ")"), alt_sep=" ")

    # Reserved 8-bit
    f.add_field("reserved (8-bit)", rsvrd)

    # Fragment Offset
    off_field = f.add_field("off", as_bin(off, 16, 0, 13), alt_value=off,
                            alt_unit=f"({(off << 3)})", bin_field=True)

    # Reserved 2-bit
    f.add_field("reserved (2-bit)", as_bin(off_rsvrd, 16, 13, 2),
                alt_value=off_rsvrd, bin_field=True)

    # M
    m_flag_map = {0: "last fragment", 1: "more fragments"}
    m_field = f.add_field("m", as_bin(m, 16, 15, 1), alt_value=m,
                          alt_unit=m_flag_map[m], bin_field=True)

    if m:
        pkti.fragmented = True

    if pkti.fragmented:
        pkti.add_fragment(buf[8:len(buf[8:])])
        off_field.add_note("fragmented IPv6 datagram")

    if (off << 3) > 0 and not m:
        pkti.fragmented = False
        pkti.defragment = True

    # Identification
    id_field = f.add_field("id", id, alt_value=as_hex(id, 8),
                           alt_value_brackets=("(", ")"), alt_sep=" ")

    # Update packet info
    pkti.remaining -= 8 if not pkti.fragmented else len(buf)
    pkti.dissected += 8 if not pkti.fragmented else len(buf)

    if pkti.remaining > 0:
        pkti.next_proto = nh
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = IPProto.IPV6_FRAG
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = protocol

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["frag6"] = f
    pkti.proto_stack.append("frag6")

    # Update names
    nh_field.name = "next header"
    off_field.name = "fragment offset"
    m_field.name = "m flag"
    id_field.name = "identification"

    dump = f.line("fragmented", off=str((off << 3)), id="id", proto="nh")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip6_ext_hdr_dest_opts_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    protocol = "IPv6 Destination Options Header"

    if len(buf) < 2:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE AT LEAST 2"
        return ""

    f = FieldFormatter(protocol)

    nh = buf[0]
    length = buf[1]
    length2 = (length + 1) * 8

    # Next Header
    nh_field = f.add_field("nh", IP_PROTO_MAP[nh], alt_value=nh,
                           alt_value_brackets=("(", ")"), alt_sep=" ")

    # Length
    len_field = f.add_field("len", length)
    len2_field = f.add_field("len2", length2, unit="bytes", virtual=True)

    if length2 > 0:
        data_field = f.add_field("data", (length2 - 2), unit="bytes")
        data_field.add_field("dump", hexstr(buf[2:length2], 40))

    # Update packet info
    pkti.remaining -= length2
    pkti.dissected += length2

    if pkti.remaining > 0:
        pkti.next_proto = nh
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = IPProto.IPV6_OPTS
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = protocol

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["dstopts6"] = f
    pkti.proto_stack.append("dstopts6")

    # Update names
    nh_field.name = "next header"
    len_field.name = "length"
    len2_field.name = "length"

    dump = f.line(len="len2")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def ip6_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "IPv6"
    f = FieldFormatter(protocol)

    if len(buf) < IP6_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID IPv6 PACKET"
        return ""

    ip = IPv6(buf)
    ver = ip.ver

    if ver != 6:
        if ver == 4:
            from unet.modules.dissect.ip import ip_dissect

            return ip_dissect(pkto, pkti, buf)
        else:
            pkti.invalid = True
            pkti.invalid_proto_name = protocol
            pkti.invalid_msg = "invalid IP version: %d" % ver
            return ""

    # Version
    ver_field = f.add_field("ver", as_bin(ver, 32, 0, 4), bin_field=True,
                            sep=" = ", alt_value=ver, alt_sep=": ")

    # Differentiated Services
    ds = ip.tcls
    dscp = ds >> 2
    ecn = ds & 0x03

    ds_field = f.add_field("ds", as_bin(ds, 32, 4, 8), bin_field=True,
                           sep=" = ", alt_value=as_hex(ds, 2), alt_sep=": ")
    dscp_field = ds_field.add_field("differentiated services codepoint",
                                    as_bin(dscp, 8, 0, 6), bin_field=True,
                                    sep=" = ", alt_value=dscp, alt_sep=": ")

    set_dscp: list[str] = []
    for val, names in IPDS_DSCP_MAP.items():
        if val == dscp:
            set_dscp.append(names[1])
            break

    if dscp != 0 and not len(set_dscp):
        set_dscp.append(f"unknown ({dscp})")

    dscp_field.add_note(", ".join(set_dscp))
    ecn_field = ds_field.add_field("explicit congestion notification",
                                   as_bin(ecn, 8, 6, 2), bin_field=True,
                                   sep=" = ", alt_value=ecn, alt_sep=": ")

    set_ecn: list[str] = []
    for val, names in IPDS_ECN_MAP.items():
        if val == ecn:
            set_ecn.append(names[1])
            break

    ecn_field.add_note(", ".join(set_ecn))

    # Flow Label
    flow = ip.flow
    flow_field = f.add_field("flow", as_bin(flow, 32, 12, 20), bin_field=True,
                             sep=" = ", alt_value=as_hex(flow, 5), alt_sep=": ")

    # Payload Length
    plen = ip.plen
    plen_field = f.add_field("plen", plen, unit="bytes")

    # Next Header
    nh = ip.nh

    try:
        nh_str = IP_PROTO_MAP[nh]
    except KeyError:
        nh_str = "unknown"

    nh_field = f.add_field("nh", nh_str, alt_value=nh,
                           alt_value_brackets=("(", ")"), alt_sep=" ")

    # Hop Limit
    hop = ip.hop
    hop_field = f.add_field("hop", hop)

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

    # Hexdump
    if pkto.dump_chunk:
        ip_hexdump = hexdump(buf[:IP6_HDRLEN], indent=4)
        f.add_field("hexdump", "\n" + ip_hexdump)

    # Update packet info
    pkti.remaining -= IP6_HDRLEN
    pkti.dissected += IP6_HDRLEN

    if pkti.remaining > 0:
        pkti.next_proto = nh
        pkti.next_proto_lookup_entry = "ip.proto"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    if pkti.prev_proto == DLT_EN10MB:
        pkti.current_proto = 0x86dd
    elif pkti.prev_proto == DLT_NULL:
        if FREEBSD:
            pkti.current_proto = 28
        elif OPENBSD:
            pkti.current_proto = 24
        elif NETBSD:
            pkti.current_proto = 24
        elif DARWIN:
            pkti.current_proto = 30
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

    pkti.proto_map["ip6"] = f
    pkti.proto_stack.append("ip6")

    # Set more descriptive name for each field
    ver_field.name = "version"
    ds_field.name = "differentiated services"
    flow_field.name = "flow label"
    plen_field.name = "payload length"
    nh_field.name = "next header"
    hop_field.name = "hop limit"
    src_field.name = "source address"
    dst_field.name = "destination address"

    dump = f.line("src", Assets.RIGHTWARDS_ARROW, "dst", len="plen",
                  proto="nh")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_ip6(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    # Extension Headers
    register("hopopts", "Hop-by-Hop Option", "ip.proto", IPProto.HOPOPTS, ip6_ext_hdr_hop_opts_dissect)
    register("route", "Routing Header", "ip.proto", IPProto.IPV6_ROUTE, ip6_ext_hdr_route_dissect)
    register("fragment", "Fragment Header", "ip.proto", IPProto.IPV6_FRAG, ip6_ext_hdr_fragment_dissect)
    register("destopts", "Destination Options", "ip.proto", IPProto.IPV6_OPTS, ip6_ext_hdr_dest_opts_dissect)

    # IPv6
    register("ip6", "Internet Protocol Version 6", "dl.type", DLT_IPV6, ip6_dissect)
    register("ip6", "Internet Protocol Version 6", "eth.type", 0x86dd, ip6_dissect)
    register("ip6", "Internet Protocol Version 6", "ip.proto", 41, ip6_dissect)
    register("ip6", "Internet Protocol Version 6", "icmp.data", 1, ip6_dissect)
    register("ip6-bsd", "Internet Protocol Version 6", "null.proto_type", 24, ip6_dissect)
    register("ip6-darwin", "Internet Protocol Version 6", "null.proto_type", 30, ip6_dissect)
    register("ip6-freebsd", "Internet Protocol Version 6", "null.proto_type", 28, ip6_dissect)
