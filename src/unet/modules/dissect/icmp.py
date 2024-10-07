import ipaddress
import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (Field, FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, as_hex, hexdump, hexstr)

__all__ = [
    "ICMP_HDRMINLEN",
    "ICMPType",
    "ICMP_TYPE_MAP",
    "icmp_echo_dissect",
    "icmp_unreach_dissect",
    "icmp_timexceeded_dissect",
    "icmp_redirect_dissect",
    "icmp_timestamp_dissect",
    "icmp_inf_dissect",
    "icmp_srcqnch_dissect",
    "icmp_param_problem_dissect",
    "icmp_unk_dissect",
    "icmp_dissect",
    "register_dissector_icmp",
    "create_dissector_entry"
]


ICMP_HDRMINLEN: Final = 8


class ICMPType(IntEnum):
    ECHO_REPLY = 0
    UNREACH = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO = 8
    ROUTER_ADVERT = 9
    ROUTER_SOLICIT = 10
    TIMEXCEED = 11
    PARAM_PROBLEM = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    INF_REQUEST = 15
    INF_REPLY = 16
    MASK_REQUEST = 17
    MASK_REPLY = 18
    EXT_ECHO_REQUEST = 42
    EXT_ECHO_REPLY = 43


ICMP_TYPE_MAP: Final[dict[int, tuple[str, str]]] = {
    ICMPType.ECHO_REPLY: ("echo-rep", "echo reply"),
    ICMPType.UNREACH: ("unreach", "destination unreachable"),
    ICMPType.SOURCE_QUENCH: ("srcqnch", "source quench"),
    ICMPType.REDIRECT: ("redirect", "redirect"),
    ICMPType.ECHO: ("echo", "echo request"),
    ICMPType.ROUTER_ADVERT: ("router-advert", "router advertisement"),
    ICMPType.ROUTER_SOLICIT: ("router-solicit", "router solicitation"),
    ICMPType.TIMEXCEED: ("timexceed", "time exceeded"),
    ICMPType.PARAM_PROBLEM: ("param-problem", "parameter problem"),
    ICMPType.TIMESTAMP: ("timestamp", "timestamp request"),
    ICMPType.TIMESTAMP_REPLY: ("timestamp-rep", "timestamp reply"),
    ICMPType.INF_REQUEST: ("inf-req", "information request"),
    ICMPType.INF_REPLY: ("inf-rep", "information reply"),
    ICMPType.MASK_REQUEST: ("mask-req", "mask request"),
    ICMPType.MASK_REPLY: ("mask-rep", "mask reply"),
    ICMPType.EXT_ECHO_REQUEST: ("ext-echo-req", "extended echo request"),
    ICMPType.EXT_ECHO_REPLY: ("ext-echo-reply", "extended echo reply"),
}


def _icmp_mark_as_deprecated(f: FieldFormatter, type_field: Field) -> None:
    type_field.add_note("this ICMP message is deprecated")
    f.add_field("deprecated", "[this ICMP message is deprecated]", virtual=True)


# ====
# Echo
# ====


def icmp_echo_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    f.add_field("code", code)

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Identifier
    id = struct.unpack("!H", buf[4:6])[0]
    id_field = f.add_field("id", id, alt_value=as_hex(id, 4), alt_sep=" ",
                           alt_value_brackets=("(", ")"))

    # Sequence number
    seq = struct.unpack("!H", buf[6:8])[0]
    seq_field = f.add_field("seq", seq, alt_value=as_hex(seq, 4), alt_sep=" ",
                            alt_value_brackets=("(", ")"))

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        data_field = f.add_field("data", data_len, unit="bytes")
        data_field.add_field(
            "data", (hexstr(buf[ICMP_HDRMINLEN:], 40)
                     + ("..." if data_len > 40 else "")))

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    if pkto.dump_chunk:
        icmp_hexdump = hexdump(buf, indent=4)
        f.add_field("hexdump", "\n" + icmp_hexdump)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN + (len(buf) - ICMP_HDRMINLEN)
    pkti.dissected += ICMP_HDRMINLEN + (len(buf) - ICMP_HDRMINLEN)

    pkti.next_proto = -1
    pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update field names
    chksum_field.name = "checksum"
    id_field.name = "identifier"
    seq_field.name = "sequence number"

    dump_line_kwargs = {}
    if data_len > 0:
        dump_line_kwargs["data"] = "data"

    dump = f.line("type", id="id", seq="seq", **dump_line_kwargs)
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# ===========
# Unreachable
# ===========


def icmp_unreach_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    code_map = {
        0: "net unreachable",
        1: "host unreachable",
        2: "protocol unreachable",
        3: "port unreachable",
        4: "fragmentation needed",
        5: "source route failed",
        6: "destination network unknown",
        7: "destination host unknown",
        8: "source host isolated",
        9: "communication with destination network prohibited",
        10: "communication with destination host prohibited",
        11: "destination network unreachable for type of service",
        12: "destination host unreachable for type of service",
        13: "communication prohibited",
        14: "host precedence violation",
        15: "precedence cutoff in effect",
    }

    try:
        code_str = code_map[code]
    except KeyError:
        code_str = "unknown"

    f.add_field("code", code_str, alt_value=code, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Unused
    if code != 4:
        unused = struct.unpack("!L", buf[4:8])[0]
        f.add_field("unused", as_hex(unused, 8), alt_value=unused, alt_sep=" ",
                    alt_value_brackets=("(", ")"))
    else:
        unused = struct.unpack("!H", buf[4:6])[0]
        f.add_field("unused", as_hex(unused, 4), alt_value=unused, alt_sep=" ",
                    alt_value_brackets=("(", ")"))

        mtu = struct.unpack("!H", buf[6:8])[0]
        f.add_field("mtu", mtu)

    # Info
    info = f"{ICMP_TYPE_MAP[type][1]} ({code_map[code]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        f.add_field("IP + original datagram", data_len, unit="bytes",
                    virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN
    pkti.dissected += ICMP_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 0
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMP_HDRMINLEN
        pkti.dissected += len(buf) - ICMP_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update names
    chksum_field.name = "checksum"

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# =============
# Time exceeded
# =============


def icmp_timexceeded_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    code_map = {
        0: "time to live exceeded in transit",
        1: "net unreachable",
    }

    try:
        code_str = code_map[code]
    except KeyError:
        code_str = "unknown"

    f.add_field("code", code_str, alt_value=code, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Unused
    unused = struct.unpack("!L", buf[4:8])[0]
    f.add_field("unused", as_hex(unused, 8), alt_value=unused, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Info
    info = f"{ICMP_TYPE_MAP[type][1]} ({code_map[code]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        f.add_field("IP + original datagram", data_len, unit="bytes",
                    virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN
    pkti.dissected += ICMP_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 0
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMP_HDRMINLEN
        pkti.dissected += len(buf) - ICMP_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update names
    chksum_field.name = "checksum"

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# =================
# Parameter problem
# =================


def icmp_param_problem_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    code_map = {
        0: "indicates the error",
        1: "missing a required option",
        2: "bad length"
    }

    try:
        code_str = code_map[code]
    except KeyError:
        code_str = "unknown"

    f.add_field("code", code_str, alt_value=code, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Unused
    unused = struct.unpack("!L", buf[4:8])[0]
    pointer = (unused & 0xf0000000) >> 28

    f.add_field("pointer", pointer)
    f.add_field("unused", as_hex(unused, 8), alt_value=unused, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Info
    info = f"{ICMP_TYPE_MAP[type][1]} ({code_map[code]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        f.add_field("IP + original datagram", data_len, unit="bytes",
                    virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN
    pkti.dissected += ICMP_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 0
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMP_HDRMINLEN
        pkti.dissected += len(buf) - ICMP_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update names
    chksum_field.name = "checksum"

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# =============
# Source quench
# =============


def icmp_srcqnch_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    type_field = f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type,
                             alt_sep=" ", alt_value_brackets=("(", ")"))
    _icmp_mark_as_deprecated(f, type_field)

    # Code
    code = buf[1]
    f.add_field("code", code)

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Unused
    unused = struct.unpack("!L", buf[4:8])[0]
    f.add_field("unused", as_hex(unused, 8), alt_value=unused, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Info
    info = f"{ICMP_TYPE_MAP[type][1]} ({code})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        f.add_field("IP + original datagram", data_len, unit="bytes",
                    virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN
    pkti.dissected += ICMP_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 0
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMP_HDRMINLEN
        pkti.dissected += len(buf) - ICMP_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update names
    chksum_field.name = "checksum"

    dump = f.line("info", "deprecated")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# ========
# Redirect
# ========


def icmp_redirect_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    code_map = {
        0: "redirect datagram for the network (or subnet)",
        1: "redirect datagram for the host",
        2: "redirect datagram for the type of service and network",
        3: "redirect datagram for the type of service and host",
    }

    try:
        code_str = code_map[code]
    except KeyError:
        code_str = "unknown"

    f.add_field("code", code_str, alt_value=code, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Unused
    gateway = struct.unpack("!L", buf[4:8])[0]
    f.add_field("gateway", str(ipaddress.ip_address(gateway)))

    # Info
    info = f"{ICMP_TYPE_MAP[type][1]} ({code_map[code]})"
    f.add_field("info", info, virtual=True)

    # Data
    data_len = len(buf) - ICMP_HDRMINLEN
    if data_len > 0:
        f.add_field("IP + original datagram", data_len, unit="bytes",
                    virtual=True)

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Update packet info
    pkti.remaining -= ICMP_HDRMINLEN
    pkti.dissected += ICMP_HDRMINLEN

    if not data_len:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None
    elif pkto.verbose:
        pkti.next_proto = 0
        pkti.next_proto_lookup_entry = "icmp.data"
    else:
        pkti.remaining -= len(buf) - ICMP_HDRMINLEN
        pkti.dissected += len(buf) - ICMP_HDRMINLEN

        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 1
    pkti.current_proto_layer = Layer.NETWORK
    pkti.current_proto_name = f.protocol

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update names
    chksum_field.name = "checksum"

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# =========
# Timestamp
# =========


def icmp_timestamp_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    f.add_field("code", code)

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Identifier
    id = struct.unpack("!H", buf[4:6])[0]
    id_field = f.add_field("id", id, alt_value=as_hex(id, 4), alt_sep=" ",
                           alt_value_brackets=("(", ")"))

    # Sequence number
    seq = struct.unpack("!H", buf[6:8])[0]
    seq_field = f.add_field("seq", seq, alt_value=as_hex(seq, 4), alt_sep=" ",
                            alt_value_brackets=("(", ")"))

    # Originate Timestamp
    ots = struct.unpack("!L", buf[8:12])[0]
    ots_field = f.add_field("ots", ots)

    # Receive Timestamp
    rts = struct.unpack("!L", buf[12:16])[0]
    rts_field = f.add_field("rts", rts)

    # Transmit Timestamp
    tts = struct.unpack("!L", buf[16:20])[0]
    tts_field = f.add_field("tts", tts)

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

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update field names
    chksum_field.name = "checksum"
    id_field.name = "identifier"
    seq_field.name = "sequence number"
    ots_field.name = "originate timestamp"
    rts_field.name = "receive timestamp"
    tts_field.name = "transmit timestamp"

    dump = f.line("type", id="id", seq="seq")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# ===========
# Information
# ===========


def icmp_inf_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    type_field = f.add_field("type", ICMP_TYPE_MAP[type][1], alt_value=type,
                             alt_sep=" ", alt_value_brackets=("(", ")"))
    _icmp_mark_as_deprecated(f, type_field)

    # Code
    code = buf[1]
    f.add_field("code", code)

    # Checksum
    chksum = struct.unpack("!H", buf[2:4])[0]
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum,
                                                    in_chksum_shouldbe)

        computed_chksum = in_chksum(buf)
        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Identifier
    id = struct.unpack("!H", buf[4:6])[0]
    id_field = f.add_field("id", id, alt_value=as_hex(id, 4), alt_sep=" ",
                           alt_value_brackets=("(", ")"))

    # Sequence number
    seq = struct.unpack("!H", buf[6:8])[0]
    seq_field = f.add_field("seq", seq, alt_value=as_hex(seq, 4), alt_sep=" ",
                            alt_value_brackets=("(", ")"))

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

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    # Update field names
    chksum_field.name = "checksum"
    id_field.name = "identifier"
    seq_field.name = "sequence number"

    dump = f.line("type", "deprecated", id="id", seq="seq")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


# =======
# Unknown
# =======


def icmp_unk_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
        f: FieldFormatter,
) -> str | None:
    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = f.protocol
        pkti.invalid_msg = f"length too short: {len(buf)}, must be at least {ICMP_HDRMINLEN}"
        return None

    # Type
    type = buf[0]
    f.add_field("type", "unknown", alt_value=type, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Code
    code = buf[1]
    f.add_field("code", "unknown", alt_value=code, alt_sep=" ",
                alt_value_brackets=("(", ")"))

    # Info
    info = f"unknown ICMP type: type={type}, code={code}"
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

    assert pkti.proto_stack is not None
    pkti.proto_stack.append("icmp")

    dump = f.line("info")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def icmp_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "ICMP"
    f = FieldFormatter(protocol)

    if len(buf) < ICMP_HDRMINLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID ICMP PACKET"
        return ""

    icmp_dissect_map: dict[int, Callable[[PacketOptions, PacketInfo, bytes, FieldFormatter], str | None]] = {
        ICMPType.ECHO_REPLY: icmp_echo_dissect,
        ICMPType.ECHO: icmp_echo_dissect,
        ICMPType.UNREACH: icmp_unreach_dissect,
        ICMPType.TIMEXCEED: icmp_timexceeded_dissect,
        ICMPType.PARAM_PROBLEM: icmp_param_problem_dissect,
        ICMPType.SOURCE_QUENCH: icmp_srcqnch_dissect,
        ICMPType.TIMESTAMP: icmp_timestamp_dissect,
        ICMPType.TIMESTAMP_REPLY: icmp_timestamp_dissect,
        ICMPType.REDIRECT: icmp_redirect_dissect,
        ICMPType.INF_REQUEST: icmp_inf_dissect,
        ICMPType.INF_REPLY: icmp_inf_dissect,
    }

    type = buf[0]

    try:
        dissector = icmp_dissect_map[type]
    except KeyError:
        dissector = icmp_unk_dissect

    assert pkti.proto_map is not None
    pkti.proto_map["icmp"] = f

    dump = dissector(pkto, pkti, buf, f)
    if dump is None:
        return ""

    return dump


def register_dissector_icmp(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("icmp", "Internet Control Message Protocol", "ip.proto", 1,
             icmp_dissect)


def create_dissector_entry() -> str:
    return "icmp.data"
