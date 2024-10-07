import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, as_hex, hexdump, hexstr)

__all__ = [
    "ICMPV6_HDRMINLEN",
    "ICMPv6Type",
    "ICMPV6_TYPE_MAP",
    "icmp6_common_dissect",
    "icmp6_unreach_dissect",
    "icmp6_pkt_too_big_dissect",
    "icmp6_timexceeded_dissect",
    "icmp6_param_prob_dissect",
    "icmp6_echo_dissect",
    "icmp6_unk_dissect",
    "icmp6_dissect",
]


ICMPV6_HDRMINLEN: Final = 8


# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
# Last Update: 2024-09-05
class ICMPv6Type(IntEnum):
    # 0                                     # Reserved
    # RFC 4443
    UNREACH = 1                             # Destination Unreachable
    # RFC 4443
    PKT_TOO_BIG = 2                         # Packet Too Big
    # RFC 4443
    TIMEXCEEDED = 3                         # Time Exceeded
    # RFC 4443
    PARAM_PROBLEM = 4                       # Parameter Problem
    # 5-99                                  # Unassigned
    # RFC 4443
    # 100, 101                              # Private experimentation
    # 102-126                               # Unassigned
    # RFC 4443
    # 127                                   # Reserved for expansion of ICMPv6 error messages
    # RFC 4443
    ECHO_REQ = 128                          # Echo Request
    # RFC 4443
    ECHO_REP = 129                          # Echo Reply
    # RFC 2710
    ML_QUERY = 130                          # Multicast Listener Query
    # RFC 2710
    ML_REPORT = 131                         # Multicast Listener Report
    # RFC 2710
    ML_DONE = 132                           # Multicast Listener Done
    # RFC 4861
    ROUTER_SOLICIT = 133                    # Router Solicitation
    # RFC 4861
    ROUTER_ADVERT = 134                     # Router Advertisement
    # RFC 4861
    NEIGHBOR_SOLICIT = 135                  # Neighbor Solicitation
    # RFC 4861
    NEIGHBOR_ADVERT = 136                   # Neighbor Advertisement
    # RFC 4861
    REDIRECT = 137                          # Redirect Message
    # RFC 2894
    ROUTER_RENUMBER = 138                   # Router Renumbering
    # RFC 4620
    ICMP_NODE_INFQ = 139                    # ICMP Node Information Query
    # RFC 4620
    ICMP_NODE_INFR = 140                    # ICMP Node Information Response
    # RFC 3122
    INEIGHBOR_DISCOVERY_SOLICIT = 141       # Inverse Neighbor Discovery Solicitation
    # RFC 3122
    INEIGHBOR_DISCOVERY_ADVERT = 142        # Inverse Neighbor Discovery Advertisement
    # https://datatracker.ietf.org/doc/draft-ietf-pim-3810bis/12/
    V2_ML_REPORT = 143                      # Version 2 Multicast Listener Report
    # RFC 6275
    HOME_AGENT_ADDR_DISCOVERY_REQ = 144     # Home Agent Address Discovery Request
    # RFC 6275
    HOME_AGENT_ADDR_DISCOVERY_REP = 145     # Home Agent Address Discovery Reply
    # RFC 6275
    MOBILE_PREFIX_SOLICIT = 146             # Mobile Prefix Solicitation
    # RFC 6275
    MOBILE_PREFIX_ADVERT = 147              # Mobile Prefix Advertisement
    # RFC 3971
    CERT_PATH_SOLICIT = 148                 # Certification Path Solicitation
    # RFC 3971
    CERT_PATH_ADVERT = 149                  # Certification Path Advertisement
    # RFC 4065
    # 150                                   # ICMP messages utilized by experimental mobility protocols
    # RFC 4286
    MULTICAST_ROUTER_ADVERT = 151           # Multicast Router Advertisement
    # RFC 4286
    MULTICAST_ROUTER_SOLICIT = 152          # Multicast Router Solicitation
    # RFC 4286
    MULTICAST_ROUTER_TERM = 153             # Multicast Router Termination
    # RFC 5568
    FMIPV6 = 154                            # FMIPv6 Messages
    # RFC 6550
    RPL_CONTROL = 155                       # RPL Control Message
    # RFC 6743
    ILNPV6_LOCATOR_UPDATE = 156             # ILNPv6 Locator Update Message
    # RFC 6775
    DUP_ADDR_REQ = 157                      # Duplicate Address Request
    # RFC 6775
    DUP_ADDR_CONF = 158                     # Duplicate Address Confirmation
    # RFC 7731
    MPL_CONTROL = 159                       # MPL Control Message
    # RFC 8335
    EXT_ECHO_REQ = 160                      # Extended Echo Request
    # RFC 8335
    EXT_ECHO_REP = 161                      # Extended Echo Reply
    # 162-199                               # Unassigned
    # RFC 4443
    # 200, 201                              # Private experimentation
    # 202-254                               # Unassigned
    # RFC 4443
    # 255                                   # Reserved for expansion of ICMPv6 informational messages


ICMPV6_TYPE_MAP: Final[dict[int, str]] = {
    0: "reserved",
    ICMPv6Type.UNREACH: "destination unreachable",
    ICMPv6Type.PKT_TOO_BIG: "packet too big",
    ICMPv6Type.TIMEXCEEDED: "time exceeded",
    ICMPv6Type.PARAM_PROBLEM: "parameter problem",
    ICMPv6Type.ECHO_REQ: "echo request",
    ICMPv6Type.ECHO_REP: "echo reply",
    ICMPv6Type.ML_QUERY: "multicast listener query",
    ICMPv6Type.ML_REPORT: "multicast listener repoer",
    ICMPv6Type.ML_DONE: "multicast listener done",
    ICMPv6Type.ROUTER_SOLICIT: "router solicitation",
    ICMPv6Type.ROUTER_ADVERT: "router advertisement",
    ICMPv6Type.REDIRECT: "redirect",
    ICMPv6Type.ROUTER_RENUMBER: "router renumbering",
    ICMPv6Type.ICMP_NODE_INFQ: "ICMP node information query",
    ICMPv6Type.ICMP_NODE_INFR: "ICMP node information response",
    ICMPv6Type.INEIGHBOR_DISCOVERY_SOLICIT: "inverse neighbor discovery solicitation",
    ICMPv6Type.INEIGHBOR_DISCOVERY_ADVERT: "inverse neighbor discovery advertisement",
    ICMPv6Type.V2_ML_REPORT: "version 2 multicast listener report",
    ICMPv6Type.HOME_AGENT_ADDR_DISCOVERY_REQ: "home agent address discovery request",
    ICMPv6Type.HOME_AGENT_ADDR_DISCOVERY_REP: "home agent address discovery reply",
    ICMPv6Type.MOBILE_PREFIX_SOLICIT: "mobile prefix solicitation",
    ICMPv6Type.MOBILE_PREFIX_ADVERT: "mobile prefix advertisement",
    ICMPv6Type.CERT_PATH_SOLICIT: "certification path solicitation",
    ICMPv6Type.CERT_PATH_ADVERT: "certification path advertisement",
    ICMPv6Type.MULTICAST_ROUTER_ADVERT: "multicast router advertisement",
    ICMPv6Type.MULTICAST_ROUTER_SOLICIT: "multicast router solicitation",
    ICMPv6Type.MULTICAST_ROUTER_TERM: "multicast router termination",
    ICMPv6Type.FMIPV6: "FMIPv6 messages",
    ICMPv6Type.RPL_CONTROL: "rpl control message",
    ICMPv6Type.ILNPV6_LOCATOR_UPDATE: "ILNPv6 locator update message",
    ICMPv6Type.DUP_ADDR_REQ: "duplicate address request",
    ICMPv6Type.DUP_ADDR_CONF: "duplicate address confirmation",
    ICMPv6Type.MPL_CONTROL: "MPL control message",
    ICMPv6Type.EXT_ECHO_REQ: "extended echo request",
    ICMPv6Type.EXT_ECHO_REP: "extended echo reply",
} | {
    num: "unassigned" for num in range(5, 96)
} | {
    num: "private experimentation" for num in range(100, 102)
} | {
    num: "unassigned" for num in range(102, 126)
} | {
    127: "reserved for expansion of ICMPv6 error messages",
    150: "experimental mobility",
} | {
    num: "unassigned" for num in range(162, 200)
} | {
    num: "private experimentation" for num in range(200, 202)
} | {
    num: "private experimentation" for num in range(200, 202)
} | {
    num: "unassigned" for num in range(202, 254)
} | {
    255: "reserved for expansion of ICMPv6 informational messages",
}


def icmp6_common_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
        code_map: dict[int, str] | None = None,
) -> None:
    icmp_type = buf[0]
    icmp_code = buf[1]
    icmp_chksum = struct.unpack("!H", buf[2:4])[0]

    # Type
    try:
        icmp_type_str = ICMPV6_TYPE_MAP[icmp_type]
    except KeyError:
        icmp_type_str = "unknown"
    f.add_field("type", icmp_type_str, alt_value=icmp_type,
                alt_value_brackets=("(", ")"), alt_sep=" ")

    # Code
    if code_map is not None:
        try:
            icmp_code_str = code_map[icmp_code]
        except KeyError:
            icmp_code_str = "unknown"
        f.add_field("code", icmp_code_str, alt_value=icmp_code,
                    alt_value_brackets=("(", ")"), alt_sep=" ")
    else:
        f.add_field("code", icmp_code)

    # Checksum
    chksum_field = f.add_field("checksum", as_hex(icmp_chksum, 4))
    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum_shouldbe,
                                                    ip6_proto_chksum)

        computed_chksum = ip6_proto_chksum(buf, pkti.net_src, pkti.net_dst, 58,
                                           len(buf))
        shouldbe = in_chksum_shouldbe(icmp_chksum, computed_chksum)
        is_ok = (shouldbe == icmp_chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")


def icmp6_unreach_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    code_map = {
        0: "no route to destination",
        1: "communication with destination administratively prohibited",
        2: "beyond scope of source address",
        3: "address unreachable",
        4: "port unreachable",
        5: "source address failed ingress/egress policy",
        6: "reject route to destination",
        7: "error in source routing header",
        8: "headers too long",
    }
    icmp6_common_dissect(pkto, pkti, buf, f, code_map)

    # Unused
    unused = struct.unpack("!I", buf[4:8])[0]
    f.add_field("unused", as_hex(unused, 8), alt_value=unused,
                alt_value_brackets=("(", ")"), alt_sep=" ")

    # Info
    info = f"{ICMPV6_TYPE_MAP[buf[0]]} ({code_map[buf[1]]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMPV6_HDRMINLEN
    if data_len > 0:
        f.add_field("data", data_len, unit="bytes", virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMPV6_HDRMINLEN
    pkti.dissected += ICMPV6_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 1
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMPV6_HDRMINLEN
        pkti.dissected += len(buf) - ICMPV6_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 58
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_pkt_too_big_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    icmp6_common_dissect(pkto, pkti, buf, f)

    # MTU
    mtu = struct.unpack("!I", buf[4:8])[0]
    f.add_field("mtu", mtu)

    # Info
    info = f"{ICMPV6_TYPE_MAP[buf[0]]} ({buf[1]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMPV6_HDRMINLEN
    if data_len > 0:
        f.add_field("data", data_len, unit="bytes", virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMPV6_HDRMINLEN
    pkti.dissected += ICMPV6_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 1
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMPV6_HDRMINLEN
        pkti.dissected += len(buf) - ICMPV6_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 58
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_timexceeded_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    code_map = {
        0: "hop limit exceeded in transit",
        1: "fragment reassembly time exceeded",
    }
    icmp6_common_dissect(pkto, pkti, buf, f, code_map)

    # Unused
    unused = struct.unpack("!I", buf[4:8])[0]
    f.add_field("unused", as_hex(unused, 8), alt_value=unused,
                alt_value_brackets=("(", ")"), alt_sep=" ")

    # Info
    info = f"{ICMPV6_TYPE_MAP[buf[0]]} ({buf[1]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMPV6_HDRMINLEN
    if data_len > 0:
        f.add_field("data", data_len, unit="bytes", virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMPV6_HDRMINLEN
    pkti.dissected += ICMPV6_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 1
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMPV6_HDRMINLEN
        pkti.dissected += len(buf) - ICMPV6_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 58
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_param_prob_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    code_map = {
        0: "erroneous header field encountered",
        1: "unrecognized next header type encountered",
        2: "unrecognized IPv6 option encountered",
        3: "IPv6 first fragment has incomplete IPv6 header chain",
        4: "SR upper-layer header error",
        5: "unrecognized next header type encountered by intermediate node",
        6: "extension header too big",
        7: "extension header chain too long",
        8: "too many extension headers",
        9: "too many options in extension header",
        10: "option too big",
    }
    icmp6_common_dissect(pkto, pkti, buf, f, code_map)

    # Pointer
    ptr = struct.unpack("!I", buf[4:8])[0]
    f.add_field("unused", ptr)

    # Info
    info = f"{ICMPV6_TYPE_MAP[buf[0]]} ({buf[1]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMPV6_HDRMINLEN
    if data_len > 0:
        f.add_field("data", data_len, unit="bytes", virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMPV6_HDRMINLEN
    pkti.dissected += ICMPV6_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 1
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMPV6_HDRMINLEN
        pkti.dissected += len(buf) - ICMPV6_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 58
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_echo_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    icmp6_common_dissect(pkto, pkti, buf, f)

    # Identifier
    id = struct.unpack("!H", buf[4:6])[0]
    id_field = f.add_field("id", id, alt_value=as_hex(id, 4), alt_sep=" ",
                           alt_value_brackets=("(", ")"))

    # Sequence number
    seq = struct.unpack("!H", buf[6:8])[0]
    seq_field = f.add_field("seq", seq, alt_value=as_hex(seq, 4), alt_sep=" ",
                            alt_value_brackets=("(", ")"))

    # Data
    data_len = len(buf) - ICMPV6_HDRMINLEN
    if data_len > 0:
        data_field = f.add_field("data", data_len, unit="bytes")
        data_field.add_field(
            "data", (hexstr(buf[ICMPV6_HDRMINLEN:], 40)
                     + ("..." if data_len > 40 else "")))

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    if pkto.dump_chunk:
        icmp_hexdump = hexdump(buf, indent=4)
        f.add_field("hexdump", "\n" + icmp_hexdump)

    # Update packet info
    pkti.remaining -= ICMPV6_HDRMINLEN + (len(buf) - ICMPV6_HDRMINLEN)
    pkti.dissected += ICMPV6_HDRMINLEN + (len(buf) - ICMPV6_HDRMINLEN)

    pkti.next_proto = -1
    pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 58
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    # Update field names
    id_field.name = "identifier"
    seq_field.name = "sequence number"

    dump_line_kwargs = {}
    if data_len > 0:
        dump_line_kwargs["data"] = "data"

    dump = f.line("type", id="id", seq="seq", **dump_line_kwargs)
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_unk_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    icmp6_common_dissect(pkto, pkti, buf, f)

    info = f"unknown ICMPv6 type: type={buf[0]}, code={buf[1]}"
    f.add_field("info", info, virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= len(buf)
    pkti.dissected += len(buf)

    pkti.next_proto = -1
    pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp6_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "ICMPv6"
    f = FieldFormatter(protocol)

    if len(buf) < ICMPV6_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"INVALID ICMPv6 PACKET: BAD LENGTH: {len(buf)}"
        return ""

    icmp6_dissect_map: dict[int, Callable[[PacketOptions, PacketInfo, bytes, FieldFormatter], str | None]] = {
        ICMPv6Type.UNREACH: icmp6_unreach_dissect,
        ICMPv6Type.PKT_TOO_BIG: icmp6_pkt_too_big_dissect,
        ICMPv6Type.TIMEXCEEDED: icmp6_timexceeded_dissect,
        ICMPv6Type.PARAM_PROBLEM: icmp6_param_prob_dissect,
        ICMPv6Type.ECHO_REQ: icmp6_echo_dissect,
        ICMPv6Type.ECHO_REP: icmp6_echo_dissect,
    }

    icmp_type = buf[0]
    try:
        dissector = icmp6_dissect_map[icmp_type]
    except KeyError:
        dissector = icmp6_unk_dissect

    assert pkti.proto_stack is not None
    assert pkti.proto_map is not None

    pkti.proto_stack.append("icmp6")
    pkti.proto_map["icmp6"] = f

    dump = dissector(pkto, pkti, buf, f)
    if dump is None:
        return ""

    return dump


def register_dissector_icmp6(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("icmpv6", "Internet Control Message Protocol Version 6",
             "ip.proto", 58, icmp6_dissect)
