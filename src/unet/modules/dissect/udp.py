import struct
from collections.abc import Callable
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, as_hex, hexdump, hexstr,
                                  port_to_name)
from unet.modules.dissect.ip import IPProto
from unet.printing import Assets

__all__ = [
    "UDP_HDRLEN",
    "UDP",
    "udp_dissect",
    "register_dissector_udp",
    "create_dissector_entry",
]


UDP_HDRLEN: Final = 8


class UDP:
    def __init__(self, buf: bytes) -> None:
        if len(buf) > UDP_HDRLEN:
            buf = buf[:UDP_HDRLEN]

        udp = struct.unpack("!HHHH", buf)
        self.sport = udp[0]
        self.dport = udp[1]
        self.len = udp[2]
        self.chksum = udp[3]


def udp_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "UDP"
    f = FieldFormatter(protocol)

    if len(buf) < UDP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID UDP PACKET"
        return ""

    udp = UDP(buf[:UDP_HDRLEN])

    # Source port
    sport = udp.sport
    if pkto.numeric_port:
        sport_field = f.add_field("sport", sport)
    else:
        serv_name = port_to_name(sport, "udp")

        if serv_name != "unknown":
            resolved_port = f"{serv_name}({sport})"
        else:
            resolved_port = sport

        sport_field = f.add_field("sport", resolved_port, alt_value=serv_name,
                                  alt_value_brackets=("(", ")"), alt_sep=" ")

    # Destination port
    dport = udp.dport
    if pkto.numeric_port:
        dport_field = f.add_field("dport", dport)
    else:
        serv_name = port_to_name(dport, "udp")

        if serv_name != "unknown":
            resolved_port = f"{serv_name}({dport})"
        else:
            resolved_port = dport

        dport_field = f.add_field("dport", resolved_port, alt_value=serv_name,
                                  alt_value_brackets=("(", ")"), alt_sep=" ")

    # Length
    length = udp.len
    if length < UDP_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID LENGTH: %d, MUST BE >= 8 BYTES" % length
        return ""
    len_field = f.add_field("len", length, unit="bytes")

    # Checksum
    chksum = udp.chksum
    chksum_field = f.add_field("chksum", as_hex(chksum, 4))

    if pkto.check_checksum:
        if chksum == 0:
            chksum_field.add_note("ignored")
        else:
            from unet.modules.dissect.in_chksum import (in_chksum_shouldbe,
                                                        ip6_proto_chksum,
                                                        ip_proto_chksum)

            if ":" in pkti.net_src:
                computed_chksum = ip6_proto_chksum(buf, pkti.net_src, pkti.net_dst,
                                                   17, len(buf))
            else:
                computed_chksum = ip_proto_chksum(buf, pkti.net_src, pkti.net_dst, 17,
                                                  len(buf))

            shouldbe = in_chksum_shouldbe(chksum, computed_chksum)
            is_ok = (shouldbe == chksum)
            status = "correct" if is_ok else "incorrect"

            chksum_field.add_note(status)

            if not is_ok:
                chksum_field.add_note(f"should be: {as_hex(shouldbe, 4)}")

            chksum_field.add_note(f"calculated checksum: {as_hex(shouldbe, 4)}")

    # Payload
    payload_len = len(buf) - UDP_HDRLEN
    if payload_len > 0:
        payload_field = f.add_field("payload", payload_len, unit="bytes")
        payload_field.add_field(
            "data", (hexstr(buf[UDP_HDRLEN:], 40)
                     + ("..." if payload_len > 40 else "")))

    if pkti.fragment_count > 0:
        f.add_field("reassembled", pkti.fragment_count, unit="fragments",
                    virtual=True)

    # Hexdump
    if pkto.dump_chunk:
        udp_hexdump = hexdump(buf[:UDP_HDRLEN], indent=4)
        f.add_field("hexdump", "\n" + udp_hexdump)

    # Update packet info
    pkti.remaining -= UDP_HDRLEN
    pkti.dissected += UDP_HDRLEN

    if pkti.remaining > 0:
        if dport in range(0, 1024):
            pkti.next_proto = dport
        elif sport in range(0, 1024):
            pkti.next_proto = sport
        else:
            pkti.next_proto = dport

        pkti.next_proto_lookup_entry = "udp.data"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.prev_proto = pkti.current_proto
    pkti.prev_proto_layer = pkti.current_proto_layer
    pkti.prev_proto_name = pkti.current_proto_name

    pkti.current_proto = IPProto.UDP.value
    pkti.current_proto_layer = Layer.TRANSPORT
    pkti.current_proto_name = protocol

    pkti.t_src = sport
    pkti.t_dst = dport

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["udp"] = f
    pkti.proto_stack.append("udp")

    # Update name for each field
    sport_field.name = "source port"
    dport_field.name = "destination port"
    len_field.name = "length"
    chksum_field.name = "checksum"

    dump = f.line("sport", Assets.RIGHTWARDS_ARROW, "dport", len="len")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_udp(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str],
        ], None]
) -> None:
    register("udp", "User Datagram Protocol", "ip.proto", 17, udp_dissect)


def create_dissector_entry() -> str:
    return "udp.data"
