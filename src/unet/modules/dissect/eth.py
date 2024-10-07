import struct
from collections.abc import Callable
from enum import IntEnum
from pathlib import Path
from typing import Final

from unet.modules.dissect import (FieldFormatter, Layer, PacketInfo,
                                  PacketOptions, as_bin, as_hex, hexdump)
from unet.modules.dissect.dl import DLT_EN10MB
from unet.printing import Assets

__all__ = [
    "lookup_oui",
    "ETH_HDRLEN",
    "EtherType",
    "ETHERTYPE_MAP",
    "ETH_LG_BIT_MAP",
    "ETH_IG_BIT_MAP",
    "eth_dissect",
    "register_dissector_eth",
    "create_dissector_entry",
]


def _load_oui_lookup_file(path: str) -> dict[str, tuple[str, str]]:
    oui_lookup_table: dict[str, tuple[str, str]] = {}

    with Path(path).expanduser().resolve().open("r") as fhandle:
        for line in fhandle:
            parts = line.strip().split("\t")

            if len(parts) >= 3:
                oui = parts[0].strip().split("/")[0].strip()
                shortened_name = parts[1].strip()
                full_name = parts[2].strip()
                oui_lookup_table[oui] = (shortened_name, full_name)

    return oui_lookup_table


_OUI_FILE_PATH: Final = __file__.strip("eth.py") + "oui.txt"
_OUI_LOOKUP_TABLE: Final = _load_oui_lookup_file(_OUI_FILE_PATH)


def lookup_oui(oui: str) -> tuple[str, str]:
    try:
        return _OUI_LOOKUP_TABLE[oui.upper()]
    except KeyError:
        return oui, "unknown"


class Eth:
    def __init__(self, buf: bytes) -> None:
        if len(buf) > ETH_HDRLEN:
            buf = buf[:ETH_HDRLEN]

        eth = struct.unpack("!6s6sH", buf)

        def mac48_str(raw: bytes) -> str:
            raw_mac = struct.unpack("!6B", raw)
            return ":".join(f"{b:02x}" for b in raw_mac)

        self.dst = mac48_str(eth[0])
        self.src = mac48_str(eth[1])
        self.tl = eth[2]


ETH_HDRLEN: Final = 14


# https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
class EtherType(IntEnum):
    UNK = 0x0000
    XNS_IDP = 0x0600
    IP = 0x0800
    X25L3 = 0x0805
    ARP = 0x0806
    WOL = 0x0842
    WMX_M2M = 0x08f0
    BPQ = 0x08ff
    VINES_IP = 0x0bad
    VINES_ECHO = 0x0baf
    C15_HBEAT = 0x0c15
    TRAIN = 0x1984
    CGMP = 0x2001
    GIGAMON = 0x22e5
    MSRP = 0x22ea
    AVTP = 0x22f0
    ROHC = 0x22f1
    TRILL = 0x22f3
    L2ISIS = 0x22f4
    CENTRINO_PROMISC = 0x2452
    _3C_NBP_DGRAM = 0x3c07
    EPL_V1 = 0x3e3f
    C15_CH = 0x4742
    DEC = 0x6000
    DNA_DL = 0x6001
    DNA_RC = 0x6002
    DNA_RT = 0x6003
    LAT = 0x6004
    DEC_DIAG = 0x6005
    DEC_CUST = 0x6006
    DEC_SCA = 0x6007
    ETHBRIDGE = 0x6558
    RAW_FR = 0x6559
    REVARP = 0x8035
    DEC_LB = 0x8038
    DEC_LAST = 0x8041
    ATALK = 0x809b
    SNA = 0x80d5
    DLR = 0x80e1
    AARP = 0x80f3
    VLAN = 0x8100
    SLPP = 0x8102
    VLACP = 0x8103
    OLDSLPP = 0x8104
    NSRP = 0x8133
    IPX = 0x8137
    SNMP = 0x814c
    WCP = 0x80ff
    STP = 0x8181
    ISMP = 0x81fd
    ISMP_TBFLOOD = 0x81ff
    QNX_QNET6 = 0x8204
    IPv6 = 0x86dd
    WLCCP = 0x872d
    MINT = 0x8783
    MAC_CONTROL = 0x8808
    SLOW_PROTOCOLS = 0x8809
    PPP = 0x880b
    COBRANET = 0x8819
    MPLS = 0x8847
    MPLS_MULTI = 0x8848
    FOUNDRY = 0x885a
    PPPOED = 0x8863
    PPPOES = 0x8864
    LINK_CTL = 0x886c
    INTEL_ANS = 0x886d
    MS_NLB_HEARTBEAT = 0x886f
    JUMBO_LLC = 0x8870
    BRCM_TYPE = 0x8874
    HOMEPLUG = 0x887b
    CDMA2000_A10_UBS = 0x8881
    ATMOE = 0x8884
    EAPOL = 0x888e
    FORTINET_FGCP_HB = 0x8890
    PROFINET = 0x8892
    FORTINET_FGCP_SESSION = 0x8893
    REALTEK = 0x8899
    HYPERSCSI = 0x889a
    CSM_ENCAPS = 0x889b
    TELKONET = 0x88a1
    AOE = 0x88a2
    ECATF = 0x88a4
    IEEE_802_1AD = 0x88a8
    IEEE_EXTREME_MESH = 0x88a9
    EPL_V2 = 0x88ab
    XIMETA = 0x88ad
    BRDWALK = 0x88ae
    WAI = 0x88b4
    EXPERIMENTAL_ETH1 = 0x88b5
    EXPERIMENTAL_ETH2 = 0x88b6
    IEEE802_OUI_EXTENDED = 0x88b7
    IEC61850_GOOSE = 0x88b8
    IEC61850_GSE = 0x88b9
    IEC61850_SV = 0x88ba
    TIPC = 0x88ca
    RSN_PREAUTH = 0x88c7
    LLDP = 0x88cc
    SERCOS = 0x88cd
    _3GPP2 = 0x88d2
    CESOETH = 0x88d8
    LLTD = 0x88d9
    WSMP = 0x88dc
    VMLAB = 0x88de
    HOMEPLUG_AV = 0x88e1
    MRP = 0x88e3
    MACSEC = 0x88e5
    IEEE_802_1AH = 0x88e7
    ELMI = 0x88ee
    MVRP = 0x88f5
    MMRP = 0x88f6
    PTP = 0x88f7
    NCSI = 0x88f8
    PRP = 0x88fb
    FLIP = 0x8901
    CFM = 0x8902
    DCE = 0x8903
    FCOE = 0x8906
    CMD = 0x8909
    IEEE80211_DATA_ENCAP = 0x890d
    LINX = 0x8911
    FIP = 0x8914
    ROCE = 0x8915
    MIH = 0x8917
    TTE_PCF = 0x891d
    VNTAG = 0x8926
    SEL_L2 = 0x892b
    BLUECOM = 0x892d
    HSR = 0x892f
    IEEE_1905 = 0x893a
    IEEE_802_1BR = 0x893f
    ECP = 0x8940
    ONOS = 0x8942
    GEONETWORKING = 0x8947
    NSH = 0x894f
    PA_HBBACKUP = 0x8988
    LOOP = 0x9000
    RTMAC = 0x9021
    RTCFG = 0x9022
    QINQ_OLD = 0x9100
    EERO = 0x9104
    TECMP = 0x99fe
    _6LOWPAN = 0xa0ed
    ECPRI = 0xaefe
    CABLELABS = 0xb4e3
    XIP = 0xc0de
    NWP = 0xc0df
    LLT = 0xcafe
    TDMOE = 0xd00d
    AVSP = 0xd28b
    EXEH = 0xe555
    ATRL = 0xfbac
    FCFT = 0xfcfc
    ACIGLEAN = 0xfff2
    IEEE_802_1CB = 0xf1c1


ETHERTYPE_MAP: Final[dict[int, str]] = {
    EtherType.IP: "IPv4",
    EtherType.IPv6: "IPv6",
    EtherType.VLAN: "802.1Q Virtual LAN",
    EtherType.SLPP: "Simple Loop Protection Protocol",
    EtherType.VLACP: "Virtual LACP",
    EtherType.OLDSLPP: "Simple Loop Protection Protocol (old)",
    EtherType.ARP: "ARP",
    EtherType.WLCCP: "Cisco Wireless Lan Context Control Protocol",
    EtherType.MINT: "Motorola Media Independent Network Transport",
    EtherType.CENTRINO_PROMISC: "IEEE 802.11 (Centrino promiscuous)",
    EtherType.XNS_IDP: "XNS Internet Datagram Protocol",
    EtherType.X25L3: "X.25 Layer 3",
    EtherType.WOL: "Wake on LAN",
    EtherType.WMX_M2M: "WiMax Mac-to-Mac",
    EtherType.EPL_V1: "EPL_V1",
    EtherType.REVARP: "RARP",
    EtherType.DEC_LB: "DEC LanBridge",
    EtherType.ATALK: "AppleTalk LLAP bridging",
    EtherType.SNA: "SNA-over-Ethernet",
    EtherType.DLR: "EtherNet/IP Device Level Ring",
    EtherType.AARP: "AARP",
    EtherType.IPX: "Netware IPX/SPX",
    EtherType.VINES_IP: "Vines IP",
    EtherType.VINES_ECHO: "Vines Echo",
    EtherType.TRAIN: "Netmon Train",
    EtherType.LOOP: "Loopback",
    EtherType.FOUNDRY: "Foundry proprietary",
    EtherType.WCP: "Wellfleet Compression Protocol",
    EtherType.STP: "Spanning Tree Protocol",
    EtherType.ISMP: "Cabletron Interswitch Message Protocol",
    EtherType.ISMP_TBFLOOD: "Cabletron SFVLAN 1.8 Tag-Based Flood",
    EtherType.QNX_QNET6: "QNX 6 QNET protocol",
    EtherType.PPPOED: "PPPoE Discovery",
    EtherType.PPPOES: "PPPoE Session",
    EtherType.LINK_CTL: "HomePNA, wlan link local tunnel",
    EtherType.INTEL_ANS: "Intel ANS probe",
    EtherType.MS_NLB_HEARTBEAT: "MS NLB heartbeat",
    EtherType.JUMBO_LLC: "Jumbo LLC",
    EtherType.BRCM_TYPE: "Broadcom tag",
    EtherType.HOMEPLUG: "Homeplug",
    EtherType.HOMEPLUG_AV: "Homeplug AV",
    EtherType.MRP: "MRP",
    EtherType.IEEE_802_1AD: "802.1ad Provider Bridge (Q-in-Q)",
    EtherType.MACSEC: "802.1AE (MACsec)",
    EtherType.IEEE_1905: "1905.1a Convergent Digital Home Network for Heterogeneous Technologies",
    EtherType.IEEE_802_1AH: "802.1ah Provider Backbone Bridge (mac-in-mac)",
    EtherType.IEEE_802_1BR: "802.1br Bridge Port Extension E-Tag",
    EtherType.EAPOL: "802.1X Authentication",
    EtherType.FORTINET_FGCP_HB: "Fortinet FGCP (FortiGate Cluster Protocol) HB (HeartBeat)",
    EtherType.RSN_PREAUTH: "802.11i Pre-Authentication",
    EtherType.MPLS: "MPLS label switched packet",
    EtherType.MPLS_MULTI: "MPLS multicast label switched packet",
    EtherType._3C_NBP_DGRAM: "3Com NBP Datagram",
    EtherType.DEC: "DEC proto",
    EtherType.DNA_DL: "DEC DNA Dump/Load",
    EtherType.DNA_RC: "DEC DNA Remote Console",
    EtherType.DNA_RT: "DEC DNA Routing",
    EtherType.LAT: "DEC LAT",
    EtherType.DEC_DIAG: "DEC Diagnostics",
    EtherType.DEC_CUST: "DEC Customer use",
    EtherType.DEC_SCA: "DEC LAVC/SCA",
    EtherType.DEC_LAST: "DEC LAST",
    EtherType.ETHBRIDGE: "Transparent Ethernet bridging",
    EtherType.CGMP: "Cisco Group Management Protocol",
    EtherType.GIGAMON: "Gigamon Header",
    EtherType.MSRP: "802.1Qat Multiple Stream Reservation Protocol",
    EtherType.MMRP: "802.1ak Multiple Mac Registration Protocol",
    EtherType.NSH: "Network Service Header",
    EtherType.PA_HBBACKUP: "PA HB Backup",
    EtherType.AVTP: "IEEE 1722 Audio Video Transport Protocol",
    EtherType.ROHC: "Robust Header Compression(RoHC)",
    EtherType.TRILL: "Transparent Interconnection of Lots of Links",
    EtherType.L2ISIS: "Intermediate System to Intermediate System",
    EtherType.MAC_CONTROL: "MAC Control",
    EtherType.SLOW_PROTOCOLS: "Slow Protocols",
    EtherType.RTMAC: "Real-Time Media Access Control",
    EtherType.RTCFG: "Real-Time Configuration Protocol",
    EtherType.CDMA2000_A10_UBS: "CDMA2000 A10 Unstructured byte stream",
    EtherType.ATMOE: "ATM over Ethernet",
    EtherType.PROFINET: "PROFINET",
    EtherType.REALTEK: "Realtek Layer 2 Protocols",
    EtherType.AOE: "ATA over Ethernet",
    EtherType.ECATF: "EtherCAT frame",
    EtherType.TELKONET: "Telkonet powerline",
    EtherType.EPL_V2: "ETHERNET Powerlink v2",
    EtherType.XIMETA: "XiMeta Technology",
    EtherType.CSM_ENCAPS: "CSM_ENCAPS Protocol",
    EtherType.EXPERIMENTAL_ETH1: "Local Experimental Ethertype 1",
    EtherType.EXPERIMENTAL_ETH2: "Local Experimental Ethertype 2",
    EtherType.IEEE802_OUI_EXTENDED: "IEEE 802a OUI Extended Ethertype",
    EtherType.IEC61850_GOOSE: "IEC 61850/GOOSE",
    EtherType.IEC61850_GSE: "IEC 61850/GSE management services",
    EtherType.IEC61850_SV: "IEC 61850/SV (Sampled Value Transmission)",
    EtherType.TIPC: "Transparent Inter Process Communication",
    EtherType.LLDP: "802.1 Link Layer Discovery Protocol (LLDP)",
    EtherType._3GPP2: "CDMA2000 A10 3GPP2 Packet",
    EtherType.TTE_PCF: "TTEthernet Protocol Control Frame",
    EtherType.CESOETH: "Circuit Emulation Services over Ethernet (MEF8)",
    EtherType.LLTD: "Link Layer Topology Discovery (LLTD)",
    EtherType.WSMP: "(WAVE) Short Message Protocol (WSM)",
    EtherType.VMLAB: "VMware Lab Manager",
    EtherType.COBRANET: "Cirrus Cobranet Packet",
    EtherType.NSRP: "Juniper Netscreen Redundant Protocol",
    EtherType.EERO: "EERO Broadcast Packet",
    EtherType.LLT: "Veritas Low Latency Transport (not officially registered)",
    EtherType.CFM: "IEEE 802.1Q Connectivity Fault Management (CFM) protocol",
    EtherType.DCE: "Data Center Ethernet (DCE) protocol(Cisco)",
    EtherType.FCOE: "Fibre Channel over Ethernet",
    EtherType.IEEE80211_DATA_ENCAP: "IEEE 802.11 data encapsulation",
    EtherType.LINX: "LINX IPC Protocol",
    EtherType.FIP: "FCoE Initialization Protocol",
    EtherType.MIH: "Media Independent Handover Protocol",
    EtherType.ELMI: "Ethernet Local Management Interface (MEF16)",
    EtherType.PTP: "PTPv2 over Ethernet (IEEE1588)",
    EtherType.NCSI: "Network Controller Sideband Interface",
    EtherType.PRP: "Parallel Redundancy Protocol (PRP) and HSR Supervision (IEC62439 Part 3)",
    EtherType.FLIP: "Flow Layer Internal Protocol",
    EtherType.ROCE: "RDMA over Converged Ethernet",
    EtherType.TDMOE: "Digium TDM over Ethernet Protocol",
    EtherType.WAI: "WAI Authentication Protocol",
    EtherType.VNTAG: "VN-Tag",
    EtherType.SEL_L2: "Schweitzer Engineering Labs Layer 2 Protocol",
    EtherType.HSR: "High-availability Seamless Redundancy (IEC62439 Part 3)",
    EtherType.BPQ: "AX.25 (BPQether driver)",
    EtherType.CMD: "CiscoMetaData",
    EtherType.GEONETWORKING: "GeoNetworking",
    EtherType.XIP: "eXpressive Internet Protocol",
    EtherType.NWP: "Neighborhood Watch Protocol",
    EtherType.BLUECOM: "bluecom Protocol",
    EtherType.QINQ_OLD: "QinQ: old non-standard 802.1ad",
    EtherType.TECMP: "Technically Enhanced Capture Module Protocol "
                     "(TECMP) or ASAM Capture Module Protocol (CMP)",
    EtherType._6LOWPAN: "6LoWPAN",
    EtherType.AVSP: "Arista Vendor Specific Protocol",
    EtherType.ECPRI: "eCPRI",
    EtherType.CABLELABS: "CableLabs Layer-3 Protocol",
    EtherType.EXEH: "EXos internal Extra Header",
    EtherType.ATRL: "Allied Telesis Resiliency Link",
    EtherType.ACIGLEAN: "Cisco ACI ARP gleaning",
    EtherType.IEEE_802_1CB: "802.1CB Frame Replication and Elimination for Reliability",
}


ETH_LG_BIT_MAP: Final[dict[int, str]] = {
    0: "globally unique",
    1: "locally administrated",
}


ETH_IG_BIT_MAP: Final[dict[int, str]] = {
    0: "unicast",
    1: "multicast",
}


def eth_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "Eth"
    f = FieldFormatter(protocol)

    if len(buf) < ETH_HDRLEN:
        pkti.invalid = True
        pkti.invalid_proto_name = protocol
        pkti.invalid_msg = "INVALID ETH PACKET"
        return ""

    eth = Eth(buf[:ETH_HDRLEN])

    # Destination
    dst = eth.dst
    if not pkto.numeric_mac:
        dst_numeric = dst
        dst = lookup_oui(dst[:8])[0]
        dst = f"{dst}:{dst_numeric[9:]}"

    dst_field = f.add_field("dst", dst)

    # LG bit
    dst_lg_bit = (buf[0] & 0b00000010) >> 1
    dst_field.add_field("lg bit", as_bin(dst_lg_bit, 24, 6, 1),
                        alt_value=ETH_LG_BIT_MAP[dst_lg_bit],
                        alt_value_brackets=("(", ")"), alt_sep=" ")

    # IG bit
    dst_ig_bit = buf[0] & 0b00000001
    dst_field.add_field("ig bit", as_bin(dst_ig_bit, 24, 7, 1),
                        alt_value=ETH_IG_BIT_MAP[dst_ig_bit],
                        alt_value_brackets=("(", ")"), alt_sep=" ")

    if not pkto.numeric_mac:
        dst_field.add_field("numeric", dst_numeric, sep=" = ")

    # Source
    src = eth.src
    if not pkto.numeric_mac:
        src_numeric = src
        src = lookup_oui(src[:8])[0]
        src = f"{src}:{src_numeric[9:]}"

    src_field = f.add_field("src", src)

    # LG bit
    src_lg_bit = (buf[6] & 0b00000010) >> 1
    src_field.add_field("lg bit", as_bin(src_lg_bit, 24, 6, 1),
                        alt_value=ETH_LG_BIT_MAP[src_lg_bit],
                        alt_value_brackets=("(", ")"), alt_sep=" ")

    # IG bit
    src_ig_bit = buf[6] & 0b00000001
    src_field.add_field("ig bit", as_bin(src_ig_bit, 24, 7, 1),
                        alt_value=ETH_IG_BIT_MAP[src_ig_bit],
                        alt_value_brackets=("(", ")"), alt_sep=" ")

    if not pkto.numeric_mac:
        src_field.add_field("numeric", src_numeric, sep=" = ")

    # Type/Length
    type = eth.tl
    try:
        type_str = ETHERTYPE_MAP[type]
    except KeyError:
        type_str = "Unknown"
    f.add_field("type", type_str, alt_value=as_hex(type, 4))

    # Padding

    if pkto.dump_chunk:
        eth_hexdump = hexdump(buf[:ETH_HDRLEN], indent=4)
        f.add_field("hexdump", "\n" + eth_hexdump)

    # Update packet info
    pkti.remaining -= ETH_HDRLEN
    pkti.dissected += ETH_HDRLEN

    if pkti.remaining > 0:
        pkti.next_proto = type
        pkti.next_proto_lookup_entry = "eth.type"
    else:
        pkti.next_proto = -1
        pkti.next_proto_lookup_entry = None

    pkti.current_proto = DLT_EN10MB
    pkti.current_proto_layer = Layer.DATA_LINK
    pkti.current_proto_name = protocol

    pkti.dl_src = src
    pkti.dl_dst = dst

    assert pkti.proto_map is not None
    assert pkti.proto_stack is not None

    pkti.proto_map["eth"] = f

    pkti.dl_hdr_len = ETH_HDRLEN

    pkti.proto_stack.append("eth")

    # Update names
    dst_field.name = "destination mac"
    src_field.name = "source mac"

    dump = f.line("dst", Assets.RIGHTWARDS_ARROW, "src", type="type")
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_eth(
        register: Callable[[
            str,
            str,
            str,
            int,
            Callable[[PacketOptions, PacketInfo, bytes], str]
        ], None],
) -> None:
    register("eth", "Ethernet", "dl.type", DLT_EN10MB, eth_dissect)


def create_dissector_entry() -> str:
    return "eth.type"
