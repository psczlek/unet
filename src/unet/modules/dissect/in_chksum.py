import struct
from socket import AF_INET6, inet_aton, inet_pton, ntohs

__all__ = ["in_chksum", "in_chksum_shouldbe", "ip_proto_chksum"]


def in_chksum(buf: bytes) -> int:
    if len(buf) % 2 != 0:
        buf += b"\x00"

    checksum = 0
    for i in range(0, len(buf), 2):
        word = struct.unpack("!H", buf[i:i + 2])[0]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    return checksum


def in_chksum_shouldbe(sum: int, computed_sum: int) -> int:
    shouldbe = sum
    shouldbe += ntohs(computed_sum)
    shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16)
    shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16)
    return shouldbe


def ip_proto_chksum(
        buf: bytes,
        src: str,
        dst: str,
        proto: int,
        length: int,
) -> int:
    class PseudoHeader:
        def __init__(self, src: str, dst: str, proto: int, length: int) -> None:
            src_ip = inet_aton(src)
            dst_ip = inet_aton(dst)
            self.ph = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, proto, length)

    ph = PseudoHeader(src, dst, proto, length)
    buff = ph.ph + buf
    return in_chksum(buff)


def ip6_proto_chksum(
        buf: bytes,
        src: str,
        dst: str,
        proto: int,
        length: int,
) -> int:
    class PseudoHeaderV6:
        def __init__(self, src: str, dst: str, proto: int, length: int) -> None:
            src_ip = inet_pton(AF_INET6, src)
            dst_ip = inet_pton(AF_INET6, dst)
            upper_layer_packet_length = struct.pack("!L", length)
            zeros = struct.pack("!BBB", 0, 0, 0)
            self.ph = src_ip + dst_ip + upper_layer_packet_length + zeros + struct.pack("!B", proto)

    ph = PseudoHeaderV6(src, dst, proto, length)
    buff = ph.ph + buf
    return in_chksum(buff)
