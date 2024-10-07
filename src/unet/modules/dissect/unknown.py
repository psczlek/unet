from collections.abc import Callable

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, hexdump)

__all__ = [
    "unknown_dissect",
    "register_dissector_unknown",
    "create_dissector_entry",
]


def unknown_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "Unknown"
    f = FieldFormatter(protocol)

    f.add_field("captured", f"{pkti.captured} bytes").add_note("bytes captured")
    f.add_field("remaining", f"{pkti.remaining} bytes").add_note("bytes left to dissect")
    f.add_field("dissected", f"{pkti.dissected} bytes").add_note("bytes processed by dissectors")
    f.add_field("linktype", pkti.linktype_name)

    layer_info_map = {
        Layer.DATA_LINK: "2",
        Layer.NETWORK: "{2, 3}",
        Layer.TRANSPORT: "{3, 4}",
        Layer.OTHER: "{5, 6, 7}",
    }

    f.add_field("layer", layer_info_map[pkti.current_proto_layer])

    if pkti.dl_src is not None:
        f.add_field("data link source", pkti.dl_src)
    if pkti.dl_dst is not None:
        f.add_field("data link destination", pkti.dl_dst)

    if pkti.net_src is not None:
        f.add_field("network layer source", pkti.net_src)
    if pkti.net_dst is not None:
        f.add_field("network layer destination", pkti.net_dst)

    if pkti.t_src is not None:
        f.add_field("transport layer source", pkti.t_src)
    if pkti.t_dst is not None:
        f.add_field("transport layer destination", pkti.t_dst)

    f.add_field("info", "dissector for this protocol is not available or was not recognized")

    # Hexdump
    if pkto.dump_chunk:
        unknown_hexdump = hexdump(buf[pkti.dissected:], indent=4)
        f.add_field("hexdump", "\n" + unknown_hexdump)

    pkti.proto_map["unknown"] = f

    dump = f.line(captured="captured", remaining="remaining",
                  dissected="dissected", layer="layer", linktype="linktype")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_unknown(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("unknown", "Unknown", "unknown", 0, unknown_dissect)


def create_dissector_entry() -> str:
    return "unknown"
