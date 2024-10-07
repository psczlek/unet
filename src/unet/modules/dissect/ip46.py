from unet.modules.dissect.dissect import PacketInfo, PacketOptions
from unet.modules.dissect.ip import ip_dissect

__all__ = ["ip46_dissect"]


def ip46_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    ver = buf[0] >> 4
    if ver == 4:
        fmt = ip_dissect(pkto, pkti, buf)
    elif ver == 6:
        fmt = ip_dissect(pkto, pkti, buf)
    else:
        return f"unknown version: {ver}"
    return fmt


def register_dissector_ip46() -> None:
    pass
