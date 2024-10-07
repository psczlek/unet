import logging
import secrets
import socket
from typing import Callable, Literal

import pytest

from unet.modules import ping

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


@pytest.mark.parametrize("width, limit", [
    (8, 0xff),
    (16, 0xffff),
    (32, 0xffffffff),
    (64, 0xffffffffffffffff)
])
def test_rand(width: Literal[8, 16, 32, 64], limit: int) -> None:
    assert 0 <= ping.rand(width) <= limit


def get_random_ipv4() -> str:
    # class A, public range: 1.0.0.0 - 127.0.0.0
    def random_class_a() -> str:
        first_octet = secrets.randbelow(128)
        return f"{first_octet}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}"

    # class B, public range: 128.0.0.0 - 191.255.0.0
    def random_class_b() -> str:
        first_octet = secrets.randbelow(192)
        return f"{first_octet}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}"

    # class c, public range: 192.0.0.0 - 223.255.255.0
    def random_class_c() -> str:
        first_octet = secrets.randbelow(224)
        return f"{first_octet}.{secrets.randbelow(256)}.{secrets.randbelow(256)}.{secrets.randbelow(256)}"

    class_a = random_class_a()
    class_b = random_class_b()
    class_c = random_class_c()
    ip_list = [class_a, class_b, class_c]
    return secrets.choice(ip_list)


def get_random_ipv6() -> str:
    return ':'.join(f"{secrets.randbits(16):04x}" for _ in range(8))


def get_random_bogus_ipv4() -> str:
    octets = [secrets.randbelow(300) for _ in range(4)]
    bogus_formats = [
        # this might return a valid address
        f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}",
        f"{octets[0]}.{octets[1]}.{octets[2]}",
        f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}.{secrets.randbelow(257)}",
        f"{octets[0]}..{octets[2]}.{octets[3]}",
        f"{octets[0]}.{octets[1]}.{octets[2]}.a"
    ]
    return secrets.choice(bogus_formats)


def get_random_bogus_ipv6() -> str:
    segments = [secrets.randbits(20) for _ in range(8)]
    bogus_formats = [
        ':'.join(f"{seg:05x}" for seg in segments),
        ':'.join(f"{seg:04x}" for seg in segments[:7]),
        ':'.join(f"{seg:04x}" for seg in segments[:9]),
        ':::'.join(f"{secrets.randbits(16):04x}" for _ in range(4)),
        ':'.join(f"{secrets.randbits(16):04x}" for _ in range(4)),
    ]
    return secrets.choice(bogus_formats)


@pytest.mark.parametrize("addr, family", [
    (get_random_ipv4(), socket.AF_INET),
    (get_random_ipv6(), socket.AF_INET6),
    (get_random_bogus_ipv4(), None),
    (get_random_bogus_ipv6(), None),
])
def test_addr_version(addr: str, family: int) -> None:
    assert ping.addr_version(addr) == family


# these aren't necessary since `addr_is_*` functions call `addr_version`, and
# `addr_version` calls `is_valid_addr`


@pytest.mark.parametrize("addr, expected", [
    (get_random_ipv4(), True),
    (get_random_ipv6(), True),
    (get_random_bogus_ipv4(), False),
    (get_random_bogus_ipv6(), False),
])
def test_is_valid_addr(addr: str, expected: bool) -> None:
    assert ping.is_valid_addr(addr) is expected


@pytest.mark.parametrize("addr_is_vx, addr, expected", [
    (ping.addr_is_v4, get_random_ipv4(), True),
    (ping.addr_is_v6, get_random_ipv6(), True),
    (ping.addr_is_v4, get_random_ipv6(), False),
    (ping.addr_is_v6, get_random_ipv4(), False),
    (ping.addr_is_v4, get_random_bogus_ipv4(), None),
    (ping.addr_is_v6, get_random_bogus_ipv6(), None),
])
def test_addr_is_vx(
        addr_is_vx: Callable[[str], bool | None],
        addr: str,
        expected: bool,
) -> None:
    assert addr_is_vx(addr) is expected
