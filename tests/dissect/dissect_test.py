import pytest
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw, raw

from unet.modules.dissect import (DeadCapture, Dissect, LiveCapture,
                                  PacketInfo, PacketOptions, hexdump,
                                  indent_lines)
from unet.modules.dissect.ip import ip_dissect
from unet.modules.dissect.udp import udp_dissect


@pytest.mark.skip("not needed")
def test_live() -> None:
    live = LiveCapture("en0")
    pkto = PacketOptions(verbose=True)
    pkti = PacketInfo(0, 1, "DLT_EN10MB", 1500, 1500, proto_stack=[])

    live.live_capture(callback=lambda cph: print(ip_dissect(pkto, pkti, cph.buf[14:])))

    print(f"{live.live_stats.qcap} packets processed")
    print(f"run time: {live.live_stats.run_time:.6f} sec")


@pytest.mark.skip("not needed")
def test_udp_dissect() -> None:
    pkto = PacketOptions(verbose=True)
    pkti = PacketInfo(0, 1, "DLT_EN10MB", 1262, 1262, proto_stack=[])

    udp = raw(IP() / UDP(len=9) / Raw(b"A" * 1234))
    dissected_ip = ip_dissect(pkto, pkti, udp[pkti.dissected:])
    dissected_udp = udp_dissect(pkto, pkti, udp[pkti.dissected:])

    if not pkto.verbose:
        print('\n' + dissected_ip + ' ' + dissected_udp)
    else:
        print('\n' + dissected_ip + '\n' + dissected_udp)

    print(f'\n\n{pkti}')


# @pytest.mark.skip("not needed")
def test_dissect() -> None:
    dissect = Dissect("live", interface="en0", wfile="unet", max_files=1,
                      max_wfile_len=5*1024)
    pkto = PacketOptions()
    print("\n")
    dissect.packet_print_loop(pkto)

