from collections.abc import Callable

from unet.modules.dissect import PacketInfo, PacketOptions
from unet.modules.dissect.dl import DLT_RAW
from unet.modules.dissect.ip46 import ip46_dissect

__all__ = ["ip46_dissect"]


def raw_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    return ip46_dissect(pkto, pkti, buf)


def register_dissector_raw(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("raw", "Raw data", "dl.type", DLT_RAW, raw_dissect)
