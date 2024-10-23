import struct
from collections.abc import Callable
from enum import IntEnum
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions)
from unet.modules.dissect.dl import DLT_NULL

__all__ = [
    "NULL_HDRLEN",
    "NullType",
    "null_dissect",
    "register_dissector_null",
    "create_dissector_entry",
]


NULL_HDRLEN: Final = 4


class NullType(IntEnum):
    BSD_AF_INET = 2
    BSD_AF_NS = 6
    BSD_AF_ISO = 7
    BSD_AF_APPLETALK = 16
    BSD_AF_IPX = 23
    BSD_AF_INET6_BSD = 24
    BSD_AF_INET6_FREEBSD = 28
    BSD_AF_INET6_DARWIN = 30


def null_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "BSD Null/Loopback"

    if len(buf) < NULL_HDRLEN:
        error = f"invalid length, expected {NULL_HDRLEN} got {len(buf)}"
        return "%s [%s]" % (protocol, error)

    f = FieldFormatter(protocol)
    proto_type = struct.unpack("=I", buf[:NULL_HDRLEN])[0]

    if proto_type == NullType.BSD_AF_INET:
        value = f"IP ({proto_type})"
    elif proto_type in {NullType.BSD_AF_INET6_BSD, NullType.BSD_AF_INET6_FREEBSD, NullType.BSD_AF_INET6_DARWIN}:
        value = f"IPv6 ({proto_type})"
    elif proto_type == NullType.BSD_AF_ISO:
        value = f"ISO ({proto_type})"
    elif proto_type == NullType.BSD_AF_IPX:
        value = f"IPX ({proto_type})"
    else:
        value = f"unknown ({proto_type})"

    f.add_field("type", value)

    dump = f.line(type="type")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    # Update packet info
    pkti.remaining -= NULL_HDRLEN
    pkti.dissected += NULL_HDRLEN

    pkti.current_proto = DLT_NULL
    pkti.current_proto_layer = Layer.DATA_LINK
    pkti.current_proto_name = protocol

    if pkti.remaining > 0:
        pkti.next_proto = proto_type
        pkti.next_proto_lookup_entry = "null.proto_type"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.dl_hdr_len = NULL_HDRLEN

    pkti.proto_map["null"] = f

    pkti.proto_stack.append("null")

    return dump


def register_dissector_null(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
):
    register("null", "BSD Null/Loopback", "dl.type", DLT_NULL, null_dissect)


def create_dissector_entry() -> str:
    return "null.proto_type"
