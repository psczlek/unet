import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, as_bin, as_hex, hexdump,
                                  hexstr, indent_lines, port_to_name)
from unet.printing import Assets

__all__ = [
    "TCP",
    "TCP_HDRLEN",
    "TCPFlag",
    "TCP_FLAG_MAP",
    "TCPOpt",
    "TCP_OPT_MAP",
    "TCP_OPT_MIN_LEN_MAP",
    "tcp_opt_common_dissect",
    "tcp_opt_eol_or_nop_dissect",
    "tcp_opt_mss_dissect",
    "tcp_opt_ws_dissect",
    "tcp_opt_sack_perm_dissect",
    "tcp_opt_sack_dissect",
    "tcp_opt_ts_dissect",
    "tcp_opt_unk_dissect",
    "tcp_opt_dissect",
    "tcp_dissect",
    "register_dissector_tcp",
    "create_dissector_entry",
]


class TCP:
    def __init__(self, buf: bytes) -> None:
        if len(buf) > TCP_HDRLEN:
            buf = buf[:TCP_HDRLEN]

        tcp = struct.unpack("!HHLLHHHH", buf)
        self.sport = tcp[0]
        self.dport = tcp[1]
        self.seq = tcp[2]
        self.ack = tcp[3]
        self.off = (tcp[4] & 0xf000) >> 12
        self.rsvrd = (tcp[4] & 0x0e00) >> 9
        self.flags = (tcp[4] & 0x01ff)
        self.win = tcp[5]
        self.chksum = tcp[6]
        self.uptr = tcp[7]


TCP_HDRLEN: Final = 20


class TCPFlag(IntEnum):
    AECN = 0x100
    CWR = 0x80
    ECE = 0x40
    URG = 0x20
    ACK = 0x10
    PSH = 0x8
    RST = 0x4
    SYN = 0x2
    FIN = 0x1


TCP_FLAG_MAP: Final[dict[int, tuple[str, str]]] = {
    TCPFlag.AECN: ("aecn", "accurate ecn"),
    TCPFlag.CWR: ("cwr", "congestion window reduce"),
    TCPFlag.ECE: ("ece", "ecn-echo"),
    TCPFlag.URG: ("urg", "urgent"),
    TCPFlag.ACK: ("ack", "acknowledgement"),
    TCPFlag.PSH: ("psh", "push"),
    TCPFlag.RST: ("rst", "reset"),
    TCPFlag.SYN: ("syn", "synchronize"),
    TCPFlag.FIN: ("fin", "finish"),
}


class TCPOpt(IntEnum):
    EOL = 0
    NOP = 1
    MSS = 2
    WS = 3
    SACK_PERM = 4
    SACK = 5
    TS = 8
    FO = 34


TCP_OPT_MAP: Final[dict[int, tuple[str, str]]] = {
    TCPOpt.EOL: ("EOL", "end of option list"),
    TCPOpt.NOP: ("NOP", "no operation"),
    TCPOpt.MSS: ("MSS", "maximum segment size"),
    TCPOpt.WS: ("WS", "window scale"),
    TCPOpt.SACK_PERM: ("SACK-PERM", "sack permitted"),
    TCPOpt.SACK: ("SACK", "selective acknowledgement"),
    TCPOpt.TS: ("TS", "timestamps"),
    TCPOpt.FO: ("FO", "TCP fast open cookie"),
}


TCP_OPT_MIN_LEN_MAP: Final[dict[int, int]] = {
    TCPOpt.EOL: 1,
    TCPOpt.NOP: 1,
    TCPOpt.MSS: 4,
    TCPOpt.WS: 3,
    TCPOpt.SACK_PERM: 2,
    TCPOpt.SACK: 2,
    TCPOpt.TS: 10,
    TCPOpt.FO: 2,
}


def tcp_opt_common_dissect(
        f: FieldFormatter,
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> None:
    kind = buf[0]

    if kind != 0 and kind != 1:
        length = buf[1]
    else:
        length = 1

    if length < TCP_OPT_MIN_LEN_MAP[kind]:
        pkti.invalid = True
        pkti.invalid_proto_name = (f"TCP option {TCP_OPT_MAP[kind][0]} "
                                   f"({TCP_OPT_MAP[kind][1]})")
        pkti.invalid_msg = (f"BAD LENGTH: {length}, MUST BE AT LEAST: "
                            f"{TCP_OPT_MIN_LEN_MAP[kind]} bytes")
        return

    try:
        name = f"{TCP_OPT_MAP[kind][1]} ({TCP_OPT_MAP[kind][0]})"
    except KeyError:
        name = "unknown"

    f.add_field("kind", kind, alt_value=name)
    f.add_field("length", length, unit="bytes" if len(buf) > 1 else "byte")


def tcp_opt_eol_or_nop_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) != 1:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE 1"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    dump = f.line("kind", "length", "bytes" if len(buf) > 1 else "byte")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_mss_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) != 4:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE 4"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    mss = struct.unpack("!H", buf[2:4])[0]
    f.add_field("mss", mss)

    dump = f.line("mss")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_ws_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) != 3:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE 3"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    ws = buf[2]
    f.add_field("shift count", ws, alt_value=f"(window size << {ws})",
                alt_sep=" ")

    dump = f.line("shift count")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_sack_perm_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) != 2:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE 2"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    dump = f.line("kind", "length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_sack_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) < 2:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE AT LEAST 2"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    sack_data_buf = buf[2:]
    sack_raw_data = [sack_data_buf[i:i + 4] for i in range(0, len(sack_data_buf), 4)]
    sack_data = [struct.unpack("!I", edge) for edge in sack_raw_data]
    sack_edges = [(sack_data[i], sack_data[i + 1]) for i in range(0, len(sack_data), 2)]

    data_field = f.add_field("data", len(sack_data_buf), unit="bytes")

    for left, right in sack_edges:
        data_field.add_field("left edge", left, unit="(raw)")
        data_field.add_field("right edge", right, unit="(raw)")

    dump = f.line("kind", "length", "bytes")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_ts_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]

    if len(buf) < 10:
        pkti.invalid = True
        pkti.invalid_proto_name = f"TCP option {TCP_OPT_MAP[kind][1]}"
        pkti.invalid_msg = f"BAD LENGTH: {len(buf)}, MUST BE AT LEAST 10"
        return ""

    f = FieldFormatter(TCP_OPT_MAP[kind][0])
    tcp_opt_common_dissect(f, pkto, pkti, buf)

    ts_val = struct.unpack("!I", buf[2:6])[0]
    f.add_field("timestamp value", ts_val)

    ts_ecr = struct.unpack("!I", buf[6:10])[0]
    f.add_field("timestamp echo reply", ts_ecr)

    dump = f.line(val="timestamp value", ecr="timestamp echo reply")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def tcp_opt_unk_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> str:
    kind = buf[0]
    length = buf[1]

    f = FieldFormatter("Unknown TCP option")
    f.add_field("kind", kind, alt_value="unknown")
    f.add_field("length", length, unit="bytes" if len(buf) > 1 else "byte")

    dump = f.line("kind", "length", "bytes" if len(buf) > 1 else "byte")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


_TCP_OPT_DISSECTOR_MAP: Final[dict[int, Callable[[PacketOptions, PacketInfo, bytes], str]]] = {
    TCPOpt.EOL: tcp_opt_eol_or_nop_dissect,
    TCPOpt.NOP: tcp_opt_eol_or_nop_dissect,
    TCPOpt.MSS: tcp_opt_mss_dissect,
    TCPOpt.WS: tcp_opt_ws_dissect,
    TCPOpt.SACK_PERM: tcp_opt_sack_perm_dissect,
    TCPOpt.SACK: tcp_opt_sack_dissect,
    TCPOpt.TS: tcp_opt_ts_dissect,
}


def tcp_opt_dissect(
        pkto: PacketOptions,
        pkti: PacketInfo,
        buf: bytes,
) -> list[str]:
    results = []
    off = 0

    while off < len(buf):
        kind = buf[off]

        if kind not in TCPOpt:
            return [f"[IP unknown option type: {kind}]"]

        if kind == TCPOpt.EOL or kind == TCPOpt.NOP:
            length = 1
        else:
            length = buf[off + 1]

        if length < TCP_OPT_MIN_LEN_MAP[kind]:
            name = (TCP_OPT_MAP[kind][0] if not pkto.verbose else
                    f"{TCP_OPT_MAP[kind][1]} ({TCP_OPT_MAP[kind][0]})")
            return [f"[IP option: {name} [length too short: {length}]]"]

        current_opt = buf[off:off + length]
        try:
            dissected_opt: str = _TCP_OPT_DISSECTOR_MAP[kind](pkto, pkti,
                                                              current_opt)
        except KeyError:
            dissected_opt = tcp_opt_unk_dissect(pkto, pkti, current_opt)

        if pkti.invalid:
            return []

        results.append(dissected_opt)
        off += length

    return results


def tcp_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "TCP"
    f = FieldFormatter(protocol)

    if len(buf) < TCP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID TCP PACKET"
        return ""

    tcp = TCP(buf[:TCP_HDRLEN])

    # Destination port
    sport = tcp.sport
    if pkto.numeric_port:
        sport_field = f.add_field("sport", sport)
    else:
        serv_name = port_to_name(sport, "tcp")

        if serv_name != "unknown":
            resolved_port = f"{serv_name}({sport})"
        else:
            resolved_port = sport

        sport_field = f.add_field("sport", resolved_port, alt_value=serv_name,
                                  alt_value_brackets=("(", ")"), alt_sep=" ")

    # Destination port
    dport = tcp.dport
    if pkto.numeric_port:
        dport_field = f.add_field("dport", dport)
    else:
        serv_name = port_to_name(dport, "tcp")

        if serv_name != "unknown":
            resolved_port = f"{serv_name}({dport})"
        else:
            resolved_port = dport

        dport_field = f.add_field("dport", resolved_port, alt_value=serv_name,
                                  alt_value_brackets=("(", ")"), alt_sep=" ")

    # Sequence number
    seq = tcp.seq
    next_seq = seq + (len(buf) - (tcp.off << 2))
    if (tcp.flags & 0x1) or (tcp.flags & 0x2):
        next_seq += 1

    seq_field = f.add_field("seq", seq, unit="(raw)")
    seq_field.add_field("next sequence number", next_seq, unit="(raw)",
                        virtual=True)

    # Acknowledgement number
    ack = tcp.ack
    ack_field = f.add_field("ack", ack, unit="(raw)")

    # Header length
    doff = tcp.off
    hlen = doff << 2
    if hlen < TCP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = f"INVALID HEADER LENGTH: {hlen}"
        return ""

    hlen_field = f.add_field("hlen", as_bin(doff, 16, 0, 4), bin_field=True,
                             sep=" = ", alt_value=hlen, alt_unit="bytes",
                             alt_sep=": ")
    hlen_field.add_note(str(doff))

    # TCP Segment length
    segment_len = len(buf) - hlen
    if segment_len >= 0:
        segment_len_field = f.add_field("segment_len", segment_len, unit="bytes",
                                        virtual=True)
    else:
        segment_len_field = f.add_field(
            "segment_len",
            f"HEADER LENGTH: {hlen} > BUFFER LENGTH: {len(buf)}",
            virtual=True,
        )

    # Reserved bits
    rsvrd = tcp.rsvrd
    rsvrd_field = f.add_field("rsvrd", as_bin(rsvrd, 16, 4, 3), bin_field=True,
                              sep=" = ", alt_value=as_hex(rsvrd, 1), alt_sep=": ")

    if rsvrd > 0:
        rsvrd_field.add_note("reserved bits should be 0")

    # Flags
    flags = tcp.flags
    set_flags: list[str] = []

    for val, names in TCP_FLAG_MAP.items():
        if flags & val:
            set_flags.append(f"{names[0]}")

    if not len(set_flags):
        set_flags.append("none")

    flags_field = f.add_field("flags", as_bin(flags, 16, 7, 9), bin_field=True,
                              sep=" = ", alt_value=as_hex(flags, 3),
                              alt_unit=f"[{', '.join(set_flags)}]", alt_sep=": ")

    flag_bits = [
        (int(bool(flags & TCPFlag.AECN)), "accurate ecn", 0, TCPFlag.AECN),
        (int(bool(flags & TCPFlag.CWR)), "congestion window reduce", 1, TCPFlag.CWR),
        (int(bool(flags & TCPFlag.ECE)), "ecn-echo", 2, TCPFlag.ECE),
        (int(bool(flags & TCPFlag.URG)), "urgent", 3, TCPFlag.URG),
        (int(bool(flags & TCPFlag.ACK)), "acknowledgement", 4, TCPFlag.ACK),
        (int(bool(flags & TCPFlag.PSH)), "push", 5, TCPFlag.PSH),
        (int(bool(flags & TCPFlag.RST)), "reset", 6, TCPFlag.RST),
        (int(bool(flags & TCPFlag.SYN)), "synchronize", 7, TCPFlag.SYN),
        (int(bool(flags & TCPFlag.FIN)), "finish", 8, TCPFlag.FIN),
    ]
    for has, name, off, value in flag_bits:
        flags_field.add_field(name, as_bin(has, 16, (7 + off), 1), bin_field=True,
                              sep=" = ", alt_value="set" if has else "not set",
                              alt_unit=f"({as_hex(value, 3)})", alt_sep=": ")
    flags_field.add_note(", ".join(set_flags))

    # Window
    win = tcp.win
    win_field = f.add_field("win", win)

    # Checksum
    chksum = tcp.chksum
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        from unet.modules.dissect.in_chksum import (in_chksum_shouldbe,
                                                    ip6_proto_chksum,
                                                    ip_proto_chksum)

        if ":" in pkti.net_src:
            computed_chksum = ip6_proto_chksum(buf, pkti.net_src, pkti.net_dst,
                                               6, len(buf))
        else:
            computed_chksum = ip_proto_chksum(buf, pkti.net_src, pkti.net_dst,
                                              6, len(buf))

        shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
        is_ok = (shouldbe == chksum)
        status = "correct" if is_ok else "incorrect"

        chksum_field.add_note(status)

        if not is_ok:
            chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

        chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Urgent pointer
    uptr = tcp.uptr
    uptr_field = f.add_field("uptr", uptr)

    # Options
    opt_buf = buf[TCP_HDRLEN:hlen]
    if len(opt_buf):
        if pkto.verbose:
            opt_field = f.add_field("options", len(opt_buf), unit="bytes")
            opts = tcp_opt_dissect(pkto, pkti, opt_buf)

            if pkti.invalid:
                return ""

            for opt in opts:
                opt = indent_lines(opt, 6)
                opt_field.add_field("TCP option", "\n" + opt)
        else:
            opts = ", ".join(tcp_opt_dissect(pkto, pkti, opt_buf))
            opt_field = f.add_field("options", f"{len(opt_buf)} bytes, [{opts}]")
    else:
        f.add_field("options", "[not set]")

    # Payload
    payload_len = len(buf) - hlen
    if payload_len > 0:
        payload_field = f.add_field("payload", payload_len, unit="bytes")
        payload_field.add_field(
            "data", (hexstr(buf[hlen:], 40)
                     + ("..." if payload_len > 40 else "")))

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Hexdump
    if pkto.dump_chunk:
        udp_hexdump = hexdump(buf[:hlen], indent=4)
        f.add_field("hexdump", "\n" + udp_hexdump)

    # Update packet info
    pkti.remaining -= hlen
    pkti.dissected += hlen

    if pkti.remaining > 0:
        pkti.next_proto = dport
        pkti.next_proto_lookup_entry = "tcp.data"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = 6
    pkti.current_proto_layer = Layer.TRANSPORT
    pkti.current_proto_name = protocol

    pkti.t_src = sport
    pkti.t_dst = dport

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["tcp"] = f
    pkti.proto_stack.append("tcp")

    # Update names
    sport_field.name = "source port"
    dport_field.name = "destination port"
    ack_field.name = "acknowledgement number"
    seq_field.name = "sequence number"
    hlen_field.name = "header length"
    segment_len_field.name = "segment length"
    rsvrd_field.name = "reserved bits"
    win_field.name = "window"
    chksum_field.name = "checksum"
    uptr_field.name = "urgent pointer"

    if pkti.fragmented:
        return ""

    dump = f.line("sport", Assets.RIGHTWARDS_ARROW, "dport", flags_field.alt_unit,
                  seq="seq", ack="ack", win="win", len="segment_len",
                  options="options")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_tcp(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("tcp", "Transmission Control Protocol", "ip.proto", 6, tcp_dissect)


def create_dissector_entry() -> str:
    return "tcp.data"
