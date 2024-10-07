"""
Dump traffic on a network.
"""


from __future__ import annotations

import ctypes as c
import queue
import shutil
import signal
import socket
import sys
import textwrap
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from functools import partial
from pathlib import Path
from types import FrameType, ModuleType, TracebackType
from typing import Any, Final, Literal

from unet.coloring import RGB, Color, Hex, supports_colors, supports_true_color
from unet.flag import FlagParser, Group, OptionFlag, PositionalFlag
from unet.modloader import load_module, lookup_symbol
from unet.printing import Assets, eprint


def _error(message: str, code: int = 1) -> None:
    precedence = (f"{Color.red(Color.bold('error'))}: "
                  f"{Color.red(Color.bold('dissect'))}")
    eprint(message, exit_code=code, precedence=precedence)


try:
    import libpcap as pcap
except ModuleNotFoundError:
    error_message = "\n".join([
        "libpcap is not installed, install libpcap and try again.\n",
        "%*s pip install libpcap" % (6, ""),
        "%*s pip3 install libpcap" % (6, ""),
    ])

    _error(error_message)

__all__ = [
    "BYTEORDER",
    "ARPHRD_NETROM",
    "ARPHRD_ETHER",
    "ARPHRD_EETHER",
    "ARPHRD_AX25",
    "ARPHRD_PRONET",
    "ARPHRD_CHAOS",
    "ARPHRD_IEEE802",
    "ARPHRD_ARCNET",
    "ARPHRD_APPLETLK",
    "ARPHRD_DLCI",
    "ARPHRD_ATM",
    "ARPHRD_METRICOM",
    "ARPHRD_IEEE1394",
    "ARPHRD_EUI64",
    "ARPHRD_INFINIBAND",
    "ARPHRD_SLIP",
    "ARPHRD_CSLIP",
    "ARPHRD_SLIP6",
    "ARPHRD_CSLIP6",
    "ARPHRD_RSRVD",
    "ARPHRD_ADAPT",
    "ARPHRD_ROSE",
    "ARPHRD_X25",
    "ARPHRD_HWX25",
    "ARPHRD_CAN",
    "ARPHRD_MCTP",
    "ARPHRD_PPP",
    "ARPHRD_CISCO",
    "ARPHRD_HDLC",
    "ARPHRD_LAPB",
    "ARPHRD_DDCMP",
    "ARPHRD_RAWHDLC",
    "ARPHRD_RAWIP",
    "ARPHRD_TUNNEL",
    "ARPHRD_TUNNEL6",
    "ARPHRD_FRAD",
    "ARPHRD_SKIP",
    "ARPHRD_LOOPBACK",
    "ARPHRD_LOCALTLK",
    "ARPHRD_FDDI",
    "ARPHRD_BIF",
    "ARPHRD_SIT",
    "ARPHRD_IPDDP",
    "ARPHRD_IPGRE",
    "ARPHRD_PIMREG",
    "ARPHRD_HIPPI",
    "ARPHRD_ASH",
    "ARPHRD_ECONET",
    "ARPHRD_IRDA",
    "ARPHRD_FCPP",
    "ARPHRD_FCAL",
    "ARPHRD_FCPL",
    "ARPHRD_FCFABRIC",
    "ARPHRD_IEEE802_TR",
    "ARPHRD_IEEE80211",
    "ARPHRD_IEEE80211_PRISM",
    "ARPHRD_IEEE80211_RADIOTAP",
    "ARPHRD_IEEE802154",
    "ARPHRD_IEEE802154_MONITOR",
    "ARPHRD_PHONET",
    "ARPHRD_PHONET_PIPE",
    "ARPHRD_CAIF",
    "ARPHRD_IP6GRE",
    "ARPHRD_NETLINK",
    "ARPHRD_6LOWPAN",
    "ARPHRD_VSOCKMON",
    "ARPHRD_VOID",
    "ARPHRD_NONE",
    "datalinktype",
    "get_capture_devs",
    "as_bin",
    "as_hex",
    "hexdump",
    "hexstr",
    "addr_to_name",
    "port_to_name",
    "Note",
    "Field",
    "FieldFormatterColor",
    "FieldFormatter",
    "indent_lines",
    "Layer",
    "CapturedPacketHeader",
    "LiveCaptureStats",
    "LiveCaptureError",
    "LiveCapture",
    "DeadCaptureStats",
    "DeadCaptureError",
    "DeadCapture",
    "PacketInfo",
    "PacketOptions",
    "dump_dissector_template",
    "Dissect",
    "main",
]


BYTEORDER = sys.byteorder


ARPHRD_NETROM: Final = 0
ARPHRD_ETHER: Final = 1
ARPHRD_EETHER: Final = 2
ARPHRD_AX25: Final = 3
ARPHRD_PRONET: Final = 4
ARPHRD_CHAOS: Final = 5
ARPHRD_IEEE802: Final = 6
ARPHRD_ARCNET: Final = 7
ARPHRD_APPLETLK: Final = 8
ARPHRD_DLCI: Final = 15
ARPHRD_ATM: Final = 19
ARPHRD_METRICOM: Final = 23
ARPHRD_IEEE1394: Final = 24
ARPHRD_EUI64: Final = 27
ARPHRD_INFINIBAND: Final = 32
ARPHRD_SLIP: Final = 256
ARPHRD_CSLIP: Final = 257
ARPHRD_SLIP6: Final = 258
ARPHRD_CSLIP6: Final = 259
ARPHRD_RSRVD: Final = 260
ARPHRD_ADAPT: Final = 264
ARPHRD_ROSE: Final = 270
ARPHRD_X25: Final = 271
ARPHRD_HWX25: Final = 272
ARPHRD_CAN: Final = 280
ARPHRD_MCTP: Final = 290
ARPHRD_PPP: Final = 512
ARPHRD_CISCO: Final = 513
ARPHRD_HDLC: Final = ARPHRD_CISCO
ARPHRD_LAPB: Final = 516
ARPHRD_DDCMP: Final = 517
ARPHRD_RAWHDLC: Final = 518
ARPHRD_RAWIP: Final = 519
ARPHRD_TUNNEL: Final = 768
ARPHRD_TUNNEL6: Final = 769
ARPHRD_FRAD: Final = 770
ARPHRD_SKIP: Final = 771
ARPHRD_LOOPBACK: Final = 772
ARPHRD_LOCALTLK: Final = 773
ARPHRD_FDDI: Final = 774
ARPHRD_BIF: Final = 775
ARPHRD_SIT: Final = 776
ARPHRD_IPDDP: Final = 777
ARPHRD_IPGRE: Final = 778
ARPHRD_PIMREG: Final = 779
ARPHRD_HIPPI: Final = 780
ARPHRD_ASH: Final = 781
ARPHRD_ECONET: Final = 782
ARPHRD_IRDA: Final = 783
ARPHRD_FCPP: Final = 784
ARPHRD_FCAL: Final = 785
ARPHRD_FCPL: Final = 786
ARPHRD_FCFABRIC: Final = 787
ARPHRD_IEEE802_TR: Final = 800
ARPHRD_IEEE80211: Final = 801
ARPHRD_IEEE80211_PRISM: Final = 802
ARPHRD_IEEE80211_RADIOTAP: Final = 803
ARPHRD_IEEE802154: Final = 804
ARPHRD_IEEE802154_MONITOR: Final = 805
ARPHRD_PHONET: Final = 820
ARPHRD_PHONET_PIPE: Final = 821
ARPHRD_CAIF: Final = 822
ARPHRD_IP6GRE: Final = 823
ARPHRD_NETLINK: Final = 824
ARPHRD_6LOWPAN: Final = 825
ARPHRD_VSOCKMON: Final = 826
ARPHRD_VOID: Final = 0xffff
ARPHRD_NONE: Final = 0xfffe


class DissectError(Exception):
    pass


# =================
# Utility functions
# =================


def datalinktype(interface: str) -> int | None:
    """
    Retrieve data link type for an interface.

    Parameters
    ----------
    interface : str
        The name of the interface, e.g. 'eth0'.

    Returns
    -------
    int | None
        The DLT value or None if the
    """
    errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    handle = pcap.open_live(interface.encode("utf-8"), 1, 1, 1, errbuf)
    if not handle:
        return None
    try:
        dlt: int = pcap.datalink(handle)
        if dlt == -1:
            return None
        return dlt
    finally:
        pcap.close(handle)


def get_capture_devs() -> dict[str, tuple[str | None, list[str]]]:
    def get_flags(bits: int) -> list[str]:
        if bits == 0:
            return ['NONE']

        flags = []

        flag_bits = [
            (pcap.PCAP_IF_UP, 'UP'),
            (pcap.PCAP_IF_RUNNING, 'RUNNING'),
            (pcap.PCAP_IF_LOOPBACK, 'LOOPBACK'),
            (pcap.PCAP_IF_WIRELESS, 'WIRELESS'),
        ]
        for flag_bit, label in flag_bits:
            if flag_bit & bits:
                flags.append(label)

        if bits & pcap.PCAP_IF_CONNECTION_STATUS:
            connection_status_bits = [
                (pcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN, 'UNKNOWN'),
                (pcap.PCAP_IF_CONNECTION_STATUS_CONNECTED, 'CONNECTED'),
                (pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED, 'DISCONNECTED'),
                (pcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE, 'NOT_APPLICABLE')
            ]
            for flag_bit, label in connection_status_bits:
                if (bits & pcap.PCAP_IF_CONNECTION_STATUS) == flag_bit:
                    flags.append(label)
                    break

        return flags

    errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    devs = {}
    devlist = c.POINTER(pcap.pcap_if_t)()

    if pcap.findalldevs(c.byref(devlist), errbuf) != 0:
        message = errbuf.value.decode('utf-8').lower()
        raise DissectError(message)

    dev = devlist
    while dev:
        name = dev.contents.name.decode('utf-8')
        description = dev.contents.description

        if description is not None:
            description = description.decode('utf-8')

        flags = get_flags(dev.contents.flags)
        spec = description, flags
        devs[name] = spec
        dev = dev.contents.next

    pcap.freealldevs(devlist)

    return devs


# wireshark-like binary formats
def as_bin(v: int, width: int, offset: int = 0, num_bits: int = 0) -> str:
    """
    Convert an integer value to its formatted binary representation.

    Parameters
    ----------
    v : int
        Value to convert.

    width : int
        Total width of the value in bits.

    offset : int
        Number of positions in bits to offset the binary representation. (default: 0)

    num_bits : int
        Number of bits to include in the binary representation. (default: 0)

    Returns
    -------
    str
        A string that is the binary representation of the supplied value.
    """
    # Convert the value to a binary string, removing the '0b' prefix
    bin_str = bin(v)[2:]
    # Pad the binary string with 0s to reach `num_bits` length. If `num_bits` is <= 0,
    # pad to the nearest multiple of 4 bits based on the current length of `bin_str`
    bin_str = bin_str.zfill(num_bits if num_bits > 0 else ((len(bin_str) + 3) // 4) * 4)

    # Truncate the string to the last `num_bits`
    if num_bits > 0:
        bin_str = bin_str[-num_bits:]

    # Replace leading unused bits with dots based on the `offset` value
    bin_str = "." * offset + bin_str

    # Pad the end with dots to ensure the string aligns with the specified `width`
    if len(bin_str) < width:
        bin_str = bin_str.ljust(width, ".")

    # Split the binary representation into chunks of 4 bits
    groups = [bin_str[i:i + 4] for i in range(0, len(bin_str), 4)]

    # Join the 4-bit groups with spaces in between and return the formatted string
    formatted_str = " ".join(groups)
    return formatted_str


def as_hex(v: int, width: int) -> str:
    """
    Conver an integer value to its formatted hex representation.

    Parameters
    ----------
    v : int
        Value to convert.

    width : int
        Total width of the value in nibbles.

    Returns
    -------
    str
        A string that is the hex representation of the supplied value.
    """
    # For ones this function shouldn't exist when we can just write an f-string
    # directly, but when dealing with a lot of hex formats having that as a function
    # will be more readable
    return f"0x{v:0{width}x}"


def hexdump(buf: bytes, width: int = 16, indent: int = 0) -> str:
    """
    Generate a hex dump of the given bytes.

    Parameters
    ----------
    buf : bytes
        Byte sequence to convert to hex.

    width : int
        Number of bytes to include per line. (default: 16)

    indent : int
        Indentation to apply to each line. (default: 0)

    Returns
    -------
    str
        A string containing the formatted hex dump of the provided byte sequence.
    """
    # Helper function to convert a chunk of bytes into a hex dump line,
    # including offset, hex bytes, and printable characters.
    def format_line(address: int, chunk: bytes) -> str:
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_chars = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        # Result ~= [0x0000] 41 41 41 41 41... AAAAA...
        return f"{' ' * indent}[0x{address:04x}]  {hex_bytes:<{width * 3}}  {ascii_chars}"

    result = []

    for i in range(0, len(buf), width):
        chunk = buf[i:i + width]
        result.append(format_line(i, chunk))

    return "\n".join(result)


def hexstr(buf: bytes, limit: int, indent: int = 0) -> str:
    """
    Convert a chunk of bytes to hex.

    Parameters
    ----------
    buf : bytes
        Byte sequence to convert.

    limit : int
        Number of bytes to include in the dump.

    indent : int
        Indentation to apply to result. (default 0)

    Returns
    -------
    str
        Converted bytes.
    """
    hex_string = "".join(f"{byte:02x}" for byte in buf)
    hex_string = hex_string[:limit]
    if indent:
        hex_string = " " * indent + hex_string
    return hex_string


def addr_to_name(addr: str) -> str:
    """
    Try to resolve an IP address to a host name.

    Parameters
    ----------
    addr : str
        Address to resolve.

    Returns
    -------
    str
        Host name of the supplied IP address or unchaged address when could not
        resolve.
    """
    try:
        name = socket.gethostbyaddr(addr)[0]
    except socket.herror:
        name = addr
    return name


def port_to_name(port: int, proto: str) -> str:
    """
    Try to resolve a port number to a service name.

    Parameters
    ----------
    port : int
        Port which to map to a service name.

    proto : str
        Protocol to use for the lookup, either 'tcp' or 'udp', otherwise any
        protocol will match.

    Returns
    -------
    str
        Service name corresponding to the supplied port number or 'unknown' when
        could not resolve.
    """
    if port > 65535:
        return "unknown"
    try:
        name = socket.getservbyport(port, proto)
    except OSError:
        name = "unknown"
    return name


# ==========
# Formatting
# ==========


@dataclass(eq=False)
class Note:
    """
    Object for storing comments.

    Attributes
    ----------
    contents : str
        Comment to store.

    prefix : str | None
        A string preceding contents. (default: None)

    prefix_sep : str
        A character separating prefix from contents. (default: ":")

    notes: list[Note] | None
        Further comments which will be attached to the note. (default: None)

    Methods
    -------
    add_note(contents, prefix=None, prefix_sep=":", notes=None)
        Create a new note.
    """

    contents: str
    prefix: str | None = None
    prefix_sep: str = ":"
    notes: list[Note] | None = None

    def add_note(
            self,
            contents: str,
            prefix: str | None = None,
            prefix_sep: str = ":",
            notes: list[Note] | None = None,
    ) -> Note:
        """
        Create a new note.

        Parameters
        ----------
        contents : str
            Comment to store.

        prefix : str | None
            A string preceding contents. (default: None)

        prefix_sep : str
            A character separating prefix from contents. (default: ":")

        notes: list[Note] | None
            Further comments which will be attached to the note. (default: None)

        Returns
        -------
        Note
            The Note object with the supplied attributes.
        """
        if self.notes is None:
            self.notes = []

        if len(prefix_sep) > 1:
            prefix_sep = prefix_sep[0]

        note = Note(contents, prefix, prefix_sep)
        self.notes.append(note)

        if notes is not None:
            self.notes.extend(notes)

        return note


def _convert_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, (tuple, list)):
        return f"[{', '.join(_convert_value(v) for v in value)}]"
    elif isinstance(value, dict):
        return f"[{', '.join(f'{_convert_value(k)}={_convert_value(v)}' for k, v in value.items())}]"
    else:
        raise ValueError(f"type: {type(value)} is not a valid type for "
                         "field value [int, float, str, bool, tuple, list, "
                         "dict]")


@dataclass(eq=False)
class Field:
    """
    Object for storing information about a protocol field.

    Attributes
    ----------
    name : str
        Name of the field.

    value : Any
        Value of the field.

    bin_field : bool
        Whether the value is in binary form. (default: False)

    unit : str | None
        The unit of the value. (default: None)

    value_brackets : tuple[str, str] | None
        Brackets in which to put the value. (default: None)

    sep : str
        A character separating the name from the value. (default: ": ")

    alt_name : str | None
        Alternative field name. (default: None)

    alt_value : Any | None
        Alternative field value. (default: None)

    alt_unit: str | None
        The unit of the alternative value. (default: None)

    alt_value_brackets : tuple[str, str] | None
        Brackets in which to put the alternative value. (default: None)

    alt_sep : str
        A character separating the alternative name from the alternative value.
        (default: " = ")

    virtual : bool
        Whether the field is not a real protocol field. (default: False)

    fields : list[Field] | None
        Further details about the field. (default: None)

    notes : list[Note] | None
        Comments for the field. (default: None)

    Methods
    -------
    add_field(name, value, bin_field=False, unit=None, value_brackets=None,
              sep=": ", alt_name=None, alt_value=None, alt_value_brackets=None,
              alt_sep=" = ", fields=None, notes=None)
              Create a new field.

    add_note(contents, prefix=None, prefix_sep=":", notes=None)
        Attach a note to the field.
    """

    name: str
    value: Any
    bin_field: bool = False
    unit: str | None = None
    value_brackets: tuple[str, str] | None = None
    sep: str = ": "
    alt_name: str | None = None
    alt_value: Any | None = None
    alt_unit: str | None = None
    alt_value_brackets: tuple[str, str] | None = None
    alt_sep: str = " = "
    virtual: bool = False
    fields: list[Field] | None = None
    notes: list[Note] | None = None

    def add_field(
            self,
            name: str,
            value: Any,
            bin_field: bool = False,
            unit: str | None = None,
            value_brackets: tuple[str, str] | None = None,
            sep: str = ": ",
            alt_name: str | None = None,
            alt_value: Any | None = None,
            alt_unit: str | None = None,
            alt_value_brackets: tuple[str, str] | None = None,
            alt_sep: str = " = ",
            virtual: bool = False,
            fields: list[Field] | None = None,
            notes: list[Note] | None = None,
    ) -> Field:
        """
        Add a new field.

        Parameters
        ----------
        name : str
            Name of the field.

        value : Any
            Value of the field.

        bin_field : bool
            Whether the value is in binary form. (default: False)

        unit : str | None
            The unit of the value. (default: None)

        value_brackets : tuple[str, str] | None
            Brackets in which to put the value. (default: None)

        sep : str
            A character separating the name from the value. (default: ": ")

        alt_name : str | None
            Alternative field name. (default: None)

        alt_value : Any | None
            Alternative field value. (default: None)

        alt_unit: str | None
            The unit of the alternative value. (default: None)

        alt_value_brackets : tuple[str, str] | None
            Brackets in which to put the alternative value. (default: None)

        alt_sep : str
            A character separating the alternative name from the alternative value.
            (default: " = ")

        virtual : bool
            Whether the field is not a real protocol field. (default: False)

        fields : list[Field] | None
            Further details about the field. (default: None)

        notes : list[Note] | None
            Comments for the field. (default: None)

        Returns
        -------
        Field
            The Field object with the supplied attributes.
        """
        if self.fields is None:
            self.fields = []

        if not isinstance(value, str):
            value = _convert_value(value)

        if alt_value is not None:
            if not isinstance(alt_value, str):
                alt_value = _convert_value(alt_value)

        field = Field(name, value, bin_field, unit, value_brackets, sep,
                      alt_name, alt_value, alt_unit, alt_value_brackets,
                      alt_sep, virtual, fields, notes)

        self.fields.append(field)

        return field

    def add_note(
            self,
            contents: str,
            prefix: str | None = None,
            prefix_sep: str = ":",
            notes: list[Note] | None = None,
    ) -> Note:
        """
        Attach a note to the field.

        Parameters
        ----------
        contents : str
            Comment to store.

        prefix : str | None
            A string preceding contents. (default: None)

        prefix_sep : str
            A character separating prefix from contents. (default: ":")

        notes: list[Note] | None
            Further comments which will be attached to the note. (default: None)

        Returns
        -------
        Note
            The Note object with the supplied attributes.
        """
        if self.notes is None:
            self.notes = []

        if len(prefix_sep) > 0:
            prefix_sep = prefix_sep[0]

        note = Note(contents, prefix, prefix_sep)

        self.notes.append(note)

        if notes is not None:
            self.notes.extend(notes)

        return note


def _get_default_colors(k: str) -> str | RGB | Hex | None:
    default_colors: dict[str, tuple[str | None, RGB | Hex | None]] = {
        "protocol": ("cyan bold", RGB(204, 136, 252, bold=True)),
        "name": ("blue", RGB(136, 202, 252)),
        "value": ("pink", RGB(255, 191, 243)),
        "unit": ("light_yellow", RGB(252, 136, 227)),
        "value_brackets": ("light_gray", RGB(160, 160, 160)),
        "sep": ("light_gray", RGB(160, 160, 160)),
        "alt_name": ("yellow", RGB(249, 226, 175)),
        "alt_value": ("cyan", RGB(191, 255, 234)),
        "alt_unit": ("light_yellow", RGB(136, 252, 225)),
        "alt_value_brackets": ("light_gray", RGB(160, 160, 160)),
        "alt_sep": ("light_gray", RGB(160, 160, 160)),
        "note_prefix": ("light_gray", RGB(179, 145, 213)),
        "note_sep": ("light_gray", RGB(160, 160, 160)),
        "note_contents": ("light_gray", RGB(188, 255, 192)),
    }
    try:
        if supports_true_color():
            color = default_colors[k][1]
        elif supports_colors():
            color = default_colors[k][0]
        else:
            color = None
        return color
    except KeyError:
        return None


@dataclass(frozen=True)
class FieldFormatterColor:
    """
    Object that defines color formatting options for FieldFormatter

    Attributes
    ----------
    protocol : str | RGB | Hex | None
    name : str | RGB | Hex | None
    value : str | RGB | Hex | None
    unit : str | RGB | Hex | None
    value_brackets : str | RGB | Hex | None
    sep : str | RGB | Hex | None
    alt_name : str | RGB | Hex | None
    alt_value : str | RGB | Hex | None
    alt_unit : str | RGB | Hex | None
    alt_value_brackets : str | RGB | Hex | None
    alt_sep : str | RGB | Hex | None
    note_prefix : str | RGB | Hex | None
    note_sep : str | RGB | Hex | None
    note_contents : str | RGB | Hex | None
    """

    protocol: str | RGB | Hex | None = _get_default_colors("protocol")
    name: str | RGB | Hex | None = _get_default_colors("name")
    value: str | RGB | Hex | None = _get_default_colors("value")
    unit: str | RGB | Hex | None = _get_default_colors("unit")
    value_brackets: str | RGB | Hex | None = _get_default_colors("value_brackets")
    sep: str | RGB | Hex | None = _get_default_colors("sep")
    alt_name: str | RGB | Hex | None = _get_default_colors("alt_name")
    alt_value: str | RGB | Hex | None = _get_default_colors("alt_value")
    alt_unit: str | RGB | Hex | None = _get_default_colors("alt_unit")
    alt_value_brackets: str | RGB | Hex | None = _get_default_colors("alt_value_brackets")
    alt_sep: str | RGB | Hex | None = _get_default_colors("alt_sep")
    note_prefix: str | RGB | Hex | None = _get_default_colors("note_prefix")
    note_sep: str | RGB | Hex | None = _get_default_colors("note_sep")
    note_contents: str | RGB | Hex | None = _get_default_colors("note_contents")


class FieldFormatter:
    """
    Create a protocol dump using the fields added to this object.

    Attributes
    ----------
    protocol : str
        Abbreviated name of a protocol, e.g., IP.

    brackets : str | None
        Brackets used to indicate the start and end of the protocol dump. (default: None)

    wrap : bool
        Whether to wrap the dump. This is meaningful only for dumps created by the `line`
        method. (default: False)

    wrap_at : int | None
        Position at which to break the line. If `wrap` is set and this is None,
        the default value will be: terminal width - len(protocol).
        (default: None)

    colorify : bool
        Whether to use colors. (default: True)

    colors : FieldFormatterColor | None
        Colors to use for coloring the dump. If `colorify` is set and this is
        None, default colors will be used. (default: None)

    Methods
    -------
    add_field(name, value, bin_field=False, unit=None, value_brackets=None,
              sep=": ", alt_name=None, alt_value=None, alt_unit=None,
              alt_value_brackets=None, alt_sep=" = ", fields=None, notes=None)
    """

    UNKNOWN_PROTO: Final = "UNKNOWN"
    EMPTY_PROTO: Final = "EMPTY"

    def __init__(
            self,
            protocol: str,
            brackets: str | None = None,
            wrap: bool = False,
            wrap_at: int | None = None,
            colorify: bool = True,
            colors: FieldFormatterColor | None = None,
    ) -> None:
        if not len(protocol):
            self.protocol = self.UNKNOWN_PROTO
        else:
            self.protocol = protocol

        self.brackets = brackets
        if self.brackets is not None:
            if len(self.brackets) < 2:
                self.brackets = "[]"
            elif len(self.brackets) > 2:
                self.brackets = self.brackets[:2]

        self.wrap = wrap
        self.wrap_at = wrap_at
        if self.wrap and self.wrap_at is None:
            self.wrap_at = shutil.get_terminal_size().columns - len(self.protocol)

        self.colorify = colorify
        self.colors = colors
        if self.colorify and self.colors is None:
            self.colors = FieldFormatterColor()

        self._fields: dict[str, Field] = {}
        self._notes: dict[int, Note] = {}
        self._note_offset = 0

    def add_field(
            self,
            name: str,
            value: Any,
            bin_field: bool = False,
            unit: str | None = None,
            value_brackets: tuple[str, str] | None = None,
            sep: str = ": ",
            alt_name: str | None = None,
            alt_value: Any | None = None,
            alt_unit: str | None = None,
            alt_value_brackets: tuple[str, str] | None = None,
            alt_sep: str = " = ",
            virtual: bool = False,
            fields: list[Field] | None = None,
            notes: list[Note] | None = None,
    ) -> Field:
        if not isinstance(value, str):
            value = _convert_value(value)

        if alt_value is not None:
            if not isinstance(alt_value, str):
                alt_value = _convert_value(alt_value)

        field = Field(name, value, bin_field, unit, value_brackets, sep,
                      alt_name, alt_value, alt_unit, alt_value_brackets,
                      alt_sep, virtual, fields, notes)

        self._fields[name] = field

        return field

    def add_note(
            self,
            offset: int,
            contents: str,
            prefix: str | None = None,
            prefix_sep: str = ":",
            notes: list[Note] | None = None,
    ) -> Note | None:
        """
        This function lacks documentation.

        Parameters
        ----------
        contents : str
            Comment to store.

        prefix : str | None
            A string preceding contents. (default: None)

        prefix_sep : str
            A character separating prefix from contents. (default: ":")

        notes: list[Note] | None
            Further comments which will be attached to the note. (default: None)

        Returns
        -------
        Note
            The Note object with the supplied attributes.
        """
        if len(prefix_sep) > 1:
            prefix_sep = prefix_sep[0]

        note = Note(contents, prefix, prefix_sep, notes)

        self._notes[offset] = note

        return note

    def line(self, *args: str, **kwargs: str) -> str:
        """
        Short, one line representation
        """
        lines = []

        if self.brackets is not None:
            open, close = self.brackets[0], self.brackets[1]

            if self.colorify:
                open, close = (Color.color(open, self.colors.value_brackets),
                               Color.color(close, self.colors.value_brackets))
        else:
            open, close = ("",) * 2

        if (not len(args) and not len(kwargs)) or not len(self._fields):
            lines.extend([open, f"<{self.EMPTY_PROTO}>", close])
            return "%s %s" % (self.protocol, "".join(lines))

        if len(args):
            for arg in args:
                try:
                    field = self._fields[arg]
                    field_val = field.value

                    if self.colorify and self.colors is not None:
                        field_val = Color.color(field_val, self.colors.value)

                    lines.append(field_val)
                except KeyError:
                    if self.colorify and self.colors is not None:
                        if (arg in Assets
                                or arg in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'):
                            arg = Color.color(arg, self.colors.sep)
                        else:
                            arg = Color.color(arg, self.colors.alt_unit)

                    lines.append(arg)

            formatted_lines = " ".join(lines)
            formatted_lines = "%s%s%s" % (open, formatted_lines, close)

        if len(kwargs):
            if "junction" in kwargs:
                junction = kwargs.pop("junction")
            else:
                junction = "="

            if self.colorify and self.colors is not None:
                junction = Color.color(junction, self.colors.sep)

            for key, value in kwargs.items():
                if self.colorify and self.colors is not None:
                    key = Color.color(key, self.colors.name)

                line = [key + junction]

                try:
                    field = self._fields[value]
                    field_val = field.value

                    if self.colorify and self.colors is not None:
                        field_val = Color.color(field_val, self.colors.value)

                    line.append(field_val)
                except KeyError:
                    line.append(value)

                lines.append("".join(line))

            formatted_lines = " ".join(lines)
            formatted_lines = "%s%s%s" % (open, formatted_lines, close)

        prefix = self.protocol
        if self.colorify and self.colors is not None:
            prefix = Color.color(prefix, self.colors.protocol)

        if self.wrap:
            if self.wrap_at is not None:
                if len(formatted_lines) > self.wrap_at:
                    lines = textwrap.wrap(formatted_lines, self.wrap_at)
                    indent = len(prefix) + 1
                    lines[1:] = [f"{' ' * indent}{line}" for line in lines[1:]]
                    formatted_lines = "\n".join(lines)

        dump = "%s %s" % (prefix, formatted_lines)

        return dump

    def _color_field(self, field: Field) -> Field:
        if self.colors is not None:
            name = Color.color(field.name, self.colors.name)
            value = Color.color(field.value, self.colors.value)

            unit = field.unit
            if unit is not None:
                unit = Color.color(unit, self.colors.unit)

            value_brackets = field.value_brackets
            if value_brackets is not None:
                value_brackets = (
                    Color.color(value_brackets[0], self.colors.value_brackets),
                    Color.color(value_brackets[1], self.colors.value_brackets),
                )

            sep = Color.color(field.sep, self.colors.sep)

            alt_name = field.alt_name
            if alt_name is not None:
                alt_name = Color.color(alt_name, self.colors.alt_name)

            alt_value = field.alt_value
            if alt_value is not None:
                alt_value = Color.color(alt_value, self.colors.alt_value)

            alt_unit = field.alt_unit
            if alt_unit is not None:
                alt_unit = Color.color(alt_unit, self.colors.alt_unit)

            alt_value_brackets = field.alt_value_brackets
            if alt_value_brackets is not None:
                alt_value_brackets = (
                    Color.color(alt_value_brackets[0], self.colors.value_brackets),
                    Color.color(alt_value_brackets[1], self.colors.value_brackets),
                )

            alt_sep = Color.color(field.alt_sep, self.colors.alt_sep)

            field = Field(name, value, field.bin_field, unit, value_brackets,
                          sep, alt_name, alt_value, alt_unit, alt_value_brackets,
                          alt_sep, field.virtual, field.fields, field.notes)

        return field

    def _color_note(self, note: Note) -> Note:
        if self.colors is not None:
            prefix = note.prefix
            if prefix is not None:
                prefix = Color.color(prefix, self.colors.note_prefix)

            sep = Color.color(note.prefix_sep, self.colors.note_sep)
            contents = Color.color(note.contents, self.colors.note_contents)
            note = Note(contents, prefix, sep, note.notes)

        return note

    def _format_field(self, field: Field, indent: int = 2) -> str:
        lines = []

        if self.colorify:
            field = self._color_field(field)

        name = field.name
        value = field.value
        is_bit_field = field.bin_field
        unit = field.unit
        value_brackets = field.value_brackets
        sep = field.sep
        alt_name = field.alt_name
        alt_value = field.alt_value
        alt_unit = field.alt_unit
        alt_value_brackets = field.alt_value_brackets
        alt_sep = field.alt_sep
        virtual = field.virtual
        fields = field.fields
        notes = field.notes

        if alt_name is not None:
            alt_name = " (%s)" % alt_name

        if value_brackets is not None:
            open, close = value_brackets[:2][0], value_brackets[:2][1]
            value = "%s%s%s" % (open, value, close)

        if is_bit_field:
            lines.extend([value, sep, name])

            if alt_name is not None:
                lines.append(alt_name)
        else:
            lines.append(name)

            if alt_name is not None:
                lines.append(alt_name)

            lines.extend([sep, value])

        if unit is not None:
            lines.extend([" ", unit])

        if alt_value is not None:
            if alt_unit is not None:
                alt_value = "%s %s" % (alt_value, alt_unit)

            if alt_value_brackets is not None:
                open, close = alt_value_brackets[:2][0], alt_value_brackets[:2][1]
                alt_value = "%s%s%s" % (open, alt_value, close)

            lines.extend([alt_sep, alt_value])

        if fields is not None:
            for f in fields:
                formatted_field = self._format_field(f, indent + 2)
                formatted_field = "\n%s" % formatted_field
                lines.append(formatted_field)

        if notes is not None:
            for n in notes:
                formatted_note = self._format_note(n, indent + 2)
                formatted_note = "\n%s" % formatted_note
                lines.append(formatted_note)

        formatted_lines = "".join(lines)
        if virtual:
            formatted_lines = "[%s]" % formatted_lines

        if virtual:
            indent += 1

        result = "%*s%s" % (indent, "", formatted_lines)

        return result

    def _format_note(self, note: Note, indent: int = 2) -> str:
        lines = []

        if self.colorify:
            note = self._color_note(note)

        if note.prefix is not None:
            prefix = "%s%s" % (note.prefix, note.prefix_sep)
            lines.append(prefix)

        lines.append(note.contents)

        if note.notes is not None:
            for n in note.notes:
                formatted_note = self._format_note(n, indent + 2)
                formatted_note = "\n%s" % formatted_note

                lines.append(formatted_note)

        formatted_lines = " ".join(lines)
        result = "%*s[%s]" % (indent, "", formatted_lines)

        return result

    def lines(self, *args: str, **kwargs: str) -> str:
        """
        """
        lines = []

        if "indent" in kwargs:
            indent = int(kwargs["indent"])
        else:
            indent = 2

        if self.brackets is not None:
            open, close = self.brackets[0], self.brackets[1]

            if self.colorify:
                open, close = (Color.color(open, self.colors.value_brackets),
                               Color.color(close, self.colors.value_brackets))
        else:
            open, close = ("",) * 2

        if not len(self._fields):
            lines.extend([open, f"{' ' * indent}<{self.EMPTY_PROTO}>", close])
            return "%s %s" % (self.protocol, "\n".join(lines))

        for field in self._fields.values():
            formatted_field = self._format_field(field, indent)
            lines.append(formatted_field)

        if open and close:
            formatted_lines = "%s\n%s\n%s" % (open, "\n".join(lines), close)
        else:
            formatted_lines = "\n" + "\n".join(lines)

        if self.colorify and self.colors is not None:
            self.protocol = Color.color(self.protocol, self.colors.protocol)

        if "prefix" not in kwargs:
            prefix = [self.protocol]

            if len(args) > 0:
                for arg in args:
                    try:
                        field = self._fields[arg]
                        f = "%s%s %s" % (arg, ":", field.value)

                        prefix.append(f)
                    except KeyError:
                        continue

            formatted_prefix = ", ".join(prefix)
        else:
            formatted_prefix = kwargs["prefix"]

        dump = "%s %s" % (formatted_prefix, formatted_lines)

        return dump


def indent_lines(lines: str, indent: int) -> str:
    """
    Adjust a string according to the supplied indent.

    Parameters
    ----------
    lines : str
        String to be indented.

    indent : int
        Number of spaces to precede the string.

    Returns
    -------
    str
        `lines` but indented.
    """
    indented_lines = []
    for line in lines.split("\n"):
        line = " " * indent + line
        indented_lines.append(line)
    return "\n".join(indented_lines)


# =======
# Dissect
# =======


class Layer(IntEnum):
    DATA_LINK = 2
    NETWORK = 3
    TRANSPORT = 4
    OTHER = 5   # Session, Presentation, Application


@dataclass(frozen=True)
class CapturedPacketHeader:
    """
    Metadata and content for a captured packet.

    Attributes
    ----------
    timestamp : tuple[int, int]
        The time stamp this packet was captured as (seconds, microseconds).

    length : int
        The total length of the packet.

    buf : bytes
        Packet data.

    caplen : int
        The length of the capture portion of the packet.
    """

    timestamp: tuple[int, int]
    length: int
    buf: bytes
    caplen: int


@dataclass
class LiveCaptureStats:
    """
    Statistics for the live captures.

    Attributes
    ----------
    cap : int
        Number of packets received.

    qcap : int
        Number of packets processed.

    bcap : int
        Number of bytes processed.

    drop : int
        Number of packets dropped because lack of room in the operating system's
        buffer, because packets were not being read fast enough.

    ifdrop : int
        Number of packets dropped by the network interface.

    start_time : tuple[int, int] | None
        The time since the epoch when the capture process started,
        as (seconds, microseconds).

    end_time : tuple[int, int] | None
        The time since the epoch when the capture process was terminated,
        as (seconds, microseconds).

    run_time : float
        The run time of the capture process.
    """

    cap: int = 0
    qcap: int = 0
    bcap: int = 0
    drop: int = 0
    ifdrop: int = 0
    start_time: tuple[int, int] | None = None
    end_time: tuple[int, int] | None = None
    run_time: float = 0.0


class LiveCaptureError(Exception):
    pass


class LiveCapture:
    def __init__(
            self,
            interface: str,
            count: int = -1,
            snapshot_length: int = 262140,
            promiscuous: bool = True,
            monitor: bool = False,
            buffer_timeout: int = 1000,
            immediate: bool = True,
            buffer_size: int = 8388608,
            timestamp_type: Literal["host", "host_lowperc", "host_hiperc",
                                    "host_hiperc_unsynced", "adapter",
                                    "adapter_unsynced"] = "host",
            timestamp_precision: Literal["micro", "nano"] = "micro",
            nonblock: bool = True,
            timeout: int = 0,
            wfile: str | None = None,
            max_files: int = -1,
            max_wfile_len: int = -1,
            filter: str | None = None,
    ) -> None:
        """
        Capture data as it flows across the network.
        """

        # Capture settings
        self.interface = interface
        self.count = count
        self.snapshot_length = snapshot_length
        self.promiscuous = promiscuous
        self.monitor = monitor
        self.buffer_timeout = buffer_timeout
        self.immediate = immediate
        self.buffer_size = buffer_size
        self.nonblock = nonblock
        self.timeout = timeout
        self.wfile = wfile
        self.max_files = max_files
        self.max_wfile_len = max_wfile_len
        self.filter = filter

        # Time stamp settings
        timestamp_type_map = {
            "host": pcap.PCAP_TSTAMP_HOST,
            "host_lowperc": pcap.PCAP_TSTAMP_HOST_LOWPREC,
            "host_hiperc": pcap.PCAP_TSTAMP_HOST_HIPREC,
            "host_hiperc_unsynced": pcap.PCAP_TSTAMP_HOST_HIPREC_UNSYNCED,
            "adapter": pcap.PCAP_TSTAMP_ADAPTER,
            "adapter_unsynced": pcap.PCAP_TSTAMP_ADAPTER_UNSYNCED,
        }
        self.timestamp_type = timestamp_type_map[timestamp_type]

        timestamp_precision_map = {
            "micro": pcap.PCAP_TSTAMP_PRECISION_MICRO,
            "nano": pcap.PCAP_TSTAMP_PRECISION_NANO,
        }
        self.timestamp_precision = timestamp_precision_map[timestamp_precision]

        # Capture handle
        self._lpd: pcap.pcap_t | None = None

        # Write handle
        self._lpdd: pcap.pcap_dumper_t | None = None
        self._current_file_number = 0
        self._current_file_size = 0
        if self.wfile:
            self._wfile_path = Path(self.wfile).expanduser().resolve()

        # Link type information
        self._llt = -1
        self._lltn = "NONE"

        # Capture thread
        self._ct: threading.Thread | None = None

        # Captured packets
        self._cp: queue.Queue[CapturedPacketHeader | None] = queue.Queue()

        # Function to apply to each packet captured
        self._live_callback: Callable[[CapturedPacketHeader], None] | None = None

        # Statistics: packets captured, processed, dropped, dropper by the
        # network interface
        self._live_stats = LiveCaptureStats()

        self._status = 0

    def _live_open(self) -> pcap.pcap_t:
        """
        Open a capture handle for the live captures.

        Raises
        ------
        LiveCaptureError
            There are four cases at which this method can raise:
                * A capture handle could not be created.
                * Options could not be set on the capture handle.
                * The handle could not be activated.
                * The capture filter could not be set on the handle.

        Returns
        -------
        pcap_t
            A capture handle.
        """
        # Open a capture handle on the specified interface
        errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
        device = self.interface.encode("utf-8")
        filter = self.filter
        pd = pcap.create(device, errbuf)

        # Couldn't create a capture handle for some reason. Retrieve the error
        # message and raise the error.
        if pd is None:
            message = errbuf.value.decode("utf-8").lower()
            raise LiveCaptureError(f"failed to create a capture handle: {message}")

        # Try to set options on the capture handle. If this method fails, the
        # `LiveCaptureError` will be raised with the appropriate message telling
        # us which option couldn't be set and the reason why it could not (I guess).
        self._live_set_capture_options(pd)

        # Try to activate the capture handle.
        status = pcap.activate(pd)

        # Check if the capture handle has been activated. If the status doesn't
        # indicate success, this will raise the `LiveCaptureError` with the
        # appropriate message telling us what has gone wrong.
        self._live_check_activate_status(status, pd)

        # Set filter if provided
        if filter:
            self._live_set_filter(pd)

        # At this point everything works fine, the capture handle is open,
        # options are set and filters are applied. We can return the handle
        # to the caller
        return pd

    def _live_open_new_pcap_file(self) -> None:
        if self.max_files > 0:
            self._current_file_number = self._current_file_number % self.max_files

        file = f"{self.wfile}.{self._current_file_number}.pcap"

        if Path(file).exists():
            Path(file).unlink()

        errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
        pdd = pcap.dump_open_append(self._lpd, file.encode('utf-8'))
        if pdd is None:
            errmsg = "failed to open pcap write handle for file [%s]:" % file
            errmsg = "%s %s" % (errmsg, pcap.geterr(errbuf))
            raise LiveCaptureError(errmsg)

        self._lpdd = pdd
        self._current_file_size = 0

    def _live_set_capture_options(self, ch: pcap.pcap_t) -> None:
        """
        Set options on a capture handle.

        Attributes
        ----------
        ch : pcap_t
            Capture handle on which to set options.

        Raises
        ------
        LiveCaptureError
            If an option could not be set.

        Returns
        -------
        None
        """
        options = [
            (pcap.set_snaplen, self.snapshot_length, "snapshot length"),
            (pcap.set_timeout, self.buffer_timeout, "packet buffer timeout"),
            (pcap.set_buffer_size, self.buffer_size, "buffer size"),
            (pcap.set_tstamp_type, self.timestamp_type, "time stamp type"),
            (pcap.set_tstamp_precision, self.timestamp_precision, "time stamp precision"),
        ]

        if self.promiscuous:
            options.append((pcap.set_promisc, self.promiscuous, "promiscuous mode"))

        if self.monitor and pcap.can_set_rfmon(ch):
            options.append((pcap.set_rfmon, self.monitor, "monitor mode"))

        if self.immediate:
            options.append((pcap.set_immediate_mode, self.immediate, "immediate mode"))

        for setter, value, description in options:
            status = setter(ch, value)

            if status != 0:
                pcap.close(ch)

                errmsg = "can't set [%s] on [%s] device:" % (description,
                                                             self.interface)
                errmsg = "%s %s" % (
                    errmsg,
                    pcap.statustostr(status).decode("utf-8").lower(),
                )
                raise LiveCaptureError(errmsg)

        if self.nonblock:
            errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
            status = pcap.setnonblock(ch, self.nonblock, errbuf)

            if status != 0:
                pcap.close(ch)

                errmsg = "can't set nonblock mode on [%s] device:" % self.interface
                errmsg = "%s %s" % (errmsg, errbuf.value.decode("utf-8").lower())
                raise LiveCaptureError(errmsg)

    def _live_check_activate_status(self, status: int, ch: pcap.pcap_t) -> None:
        """
        Check if the capture handle status is an error status.

        Attributes
        ----------
        status : int
            Status code returned by the `pcap.activate` function.

        ch : pcap_t
            Capture handle for which this check is performed.

        Raises
        ------
        LiveCaptureError
            If the status is an error status.

        Returns
        -------
        None
        """
        if status < 0:
            err_map = {
                pcap.PCAP_ERROR_ACTIVATED: "handle has already been activated",
                pcap.PCAP_ERROR_NO_SUCH_DEVICE: f"device '{self.interface}' does not exist",
                pcap.PCAP_ERROR_PERM_DENIED: "operation not permitted, permission denied",
                pcap.PCAP_ERROR_PROMISC_PERM_DENIED: "insufficient permissions for promiscuous mode",
                pcap.PCAP_ERROR_RFMON_NOTSUP: f"device '{self.interface}' does not support monitor mode",
                pcap.PCAP_ERROR_IFACE_NOT_UP: f"device '{self.interface}' is not up",
            }

            # Close the handle and raise the error
            if status in err_map:
                pcap.close(ch)
                raise LiveCaptureError(err_map[status])
            else:
                pcap.close(ch)

                errmsg = pcap.geterr(ch).value.decode("utf-8").lower()
                raise LiveCaptureError(errmsg)

    def _live_set_filter(self, handle: pcap.pcap_t) -> None:
        """
        Set capture filter.

        Attributes:
        -----------
        handle : pcap_t
            Capture handle on which to set the filter.

        Raises
        ------
        LiveCaptureError
            If the filter could not be set.

        Returns
        -------
        None
        """
        bpf_program = pcap.bpf_program()
        filter = self.filter.encode("utf-8")
        status = pcap.compile(handle, c.byref(bpf_program), filter, 1,
                              pcap.PCAP_NETMASK_UNKNOWN)

        if status != 0:
            pcap.freecode(bpf_program)

            errmsg = "failed to compile the filter [%s]:" % filter.decode("utf-8")
            errmsg = "%s %s" % (errmsg, pcap.geterr(handle).decode("utf-8").lower())
            raise LiveCaptureError(errmsg)

        status = pcap.setfilter(handle, c.byref(bpf_program))

        if status != 0:
            pcap.freecode(bpf_program)

            errmsg = "failed to set the filter [%s]:" % filter.decode("utf-8")
            errmsg = "%s %s" % (errmsg, pcap.geterr(handle).decode("utf-8").lower())
            raise LiveCaptureError(errmsg)

        pcap.freecode(c.byref(bpf_program))

    def _live_process_captured_packet(
            self,
            user: Any,
            header: Any,
            data: Any,
    ) -> None:
        # Process a captured packet
        pkthdr = c.cast(header, c.POINTER(pcap.pkthdr)).contents

        ts = (pkthdr.ts.tv_sec, pkthdr.ts.tv_usec)
        caplen, length = pkthdr.caplen, pkthdr.len
        pkt = c.string_at(data, caplen)

        captured_packet = CapturedPacketHeader(ts, length, pkt, caplen)

        # Add packet to the pool
        self._cp.put(captured_packet)

        self._live_stats.qcap += 1
        self._live_stats.bcap += caplen

        # Write packet to pcap file if wfile is specified
        if self.wfile:
            self._live_write_packet(pkthdr, pkt)

        # If there's the callback, call the function
        if self._live_callback is not None:
            self._live_callback(captured_packet)

    def _live_write_packet(self, header: pcap.pkthdr, data: bytes) -> None:
        if self._lpdd is None:
            self._live_open_new_pcap_file()

        header_ptr = c.pointer(header)
        data_ptr = c.cast(c.c_char_p(data), c.POINTER(c.c_ubyte))
        # dump takes the write handle as `u_char *`
        pdd_ptr = c.cast(self._lpdd, c.POINTER(c.c_ubyte))

        pcap.dump(pdd_ptr, header_ptr, data_ptr)

        self._current_file_size += header.caplen + 16

        if self.max_wfile_len > 0:
            current_filename = f"{self.wfile}.{self._current_file_number}.pcap"
            self._current_file_size = Path(current_filename).stat().st_size

            if self._current_file_size >= self.max_wfile_len * 1024:
                pcap.dump_close(self._lpdd)
                self._current_file_number += 1
                self._live_open_new_pcap_file()

    def _live_capture_threaded(self) -> None:
        self._ct = threading.Thread(target=self._live_capture_single_threaded)
        self._ct.start()

    def _live_signal_handler(
            self,
            signum: int,
            frame: FrameType | None,
    ) -> None:
        if signum == signal.SIGINT:
            self._live_capture_stop()

    def _live_capture_single_threaded(self) -> None:
        # Record start time
        t = time.time()
        s = int(t)
        m = int((t - s) * 1000000)
        self.live_stats.start_time = (s, m)

        while True:
            status = pcap.dispatch(
                self._lpd,
                self.count,
                pcap.pcap_handler(self._live_process_captured_packet),
                None,
            )

            # Loop break
            if status == -2 or self._status == -2:
                pcap.close(self._lpd)
                break
            # Error
            elif status == -1:
                message = "an error occured while capturing packets: %s" % (
                    pcap.geterr(self._lpd).decode("utf-8").lower()
                )
                pcap.close(self._lpd)
                raise LiveCaptureError(message)

            if self.count == -1 and (self.count == self.live_stats.qcap):
                self._live_capture_stop()
                break

    def _live_capture_stop(self) -> None:
        # Record end time
        t = time.time()
        s = int(t)
        m = int((t - s) * 1000000)
        self.live_stats.end_time = (s, m)
        # Record run time
        self.live_stats.run_time = (
            float(f"{self.live_stats.end_time[0]}.{self.live_stats.end_time[1]}")
            - float(f"{self.live_stats.start_time[0]}.{self.live_stats.start_time[1]}")
        )

        # Break the loop
        pcap.breakloop(self._lpd)
        self._status = -2

        # Dump statistics
        stats = pcap.stat()
        pcap.stats(self._lpd, c.byref(stats))

        self._live_stats.cap = stats.ps_recv
        self._live_stats.drop = stats.ps_drop
        self._live_stats.ifdrop = stats.ps_ifdrop

        # Close the write handle if packets were being saved to a file
        if self._lpdd:
            pcap.dump_close(self._lpdd)
            self._lpdd = None

    def live_capture(
            self,
            callback: Callable[[CapturedPacketHeader], None] | None = None,
            threaded: bool = False,
    ) -> None:
        """
        Capture data as it flows across a network.

        Parameters
        ----------
        callback : Callable[[CapturedPacketHeader], None] | None
            Function to apply to each packet captured. (default: None)

        threaded : bool
            Whether to run capture in a separate thread. If this is set, then
            after the capture process is complete, the `stop()` function has to
            be called to stop and clean the capture thread. (default: False)

        Returns
        -------
        None
        """
        # Open the capture handle
        try:
            self._lpd = self._live_open()
        except LiveCaptureError as e:
            if self._lpd:
                pcap.close(self._lpd)
            _error(str(e))

        # Retrieve linktype for the capture handle
        self._llt = pcap.datalink(self._lpd)
        linktype_name = pcap.datalink_val_to_name(self._llt)
        if linktype_name is not None:
            self._lltn = f"DLT_{linktype_name.decode('utf-8')}"

        # Assign the callback
        self._live_callback = callback

        # Start packet capture loop
        if threaded:
            # If done with capture the `stop` method MUST be called
            self._live_capture_threaded()
        else:
            # Register the signal to break the loop
            signal.signal(signal.SIGINT, partial(self._live_signal_handler))
            self._live_capture_single_threaded()

    def live_is_active(self) -> bool:
        """
        Check whether the capture thread is active.

        Returns
        -------
        bool
            True if the capture thread is active, otherwise False.
        """
        return self._ct is not None and self._ct.is_alive()

    def live_stop(self) -> None:
        """
        Stop the capture thread.

        Returns
        -------
        None
        """
        if self._ct:
            self._live_capture_stop()
            self._ct.join()
            self._cp.put(None)

    def live_get(self) -> CapturedPacketHeader | None:
        """
        Obtain a packet from the pool.

        Returns
        -------
        CapturedPacketHeader
            pass
        """
        return self._cp.get()

    def live_empty(self) -> bool:
        """
        Whether the pool is empty.

        Returns
        -------
        bool
            True if the captured packets pool is empty, otherwise False.
        """
        return self._cp.empty()

    def live_clear(self) -> None:
        """
        Clear the capture pool.

        Returns
        -------
        None
        """
        while not self._cp.empty():
            self._cp.get()
            self._cp.task_done()

    @property
    def live_linktype(self) -> int:
        """
        Get the linktype for an interface on which the capture handle is open.

        Returns
        -------
        int
            A DLT_* value.
        """
        return self._llt

    @property
    def live_linktype_name(self) -> str:
        """
        Get the name of the linktype.

        Returns
        -------
        str
            DLT_* as a string.
        """
        return self._lltn

    @property
    def live_stats(self) -> LiveCaptureStats:
        """
        Pass

        Returns
        -------
        LiveCaptureStats
            pass
        """
        return self._live_stats


@dataclass
class DeadCaptureStats:
    """
    Statistics for the dead captures (file reads).

    Attributes
    ----------
    read : int
        Number of packets read from a capture file.

    readb : int
        Number of bytes read from the capture file.
    """

    read: int = 0
    readb: int = 0


class DeadCaptureError(Exception):
    pass


class DeadCapture:
    def __init__(
            self,
            file_or_files: str | list[str],
            count: int = -1,
            timestamp_precision: Literal["micro", "nano"] | None = None,
            filter: str | None = None,
    ) -> None:
        """
        Read packets from a capture file.
        """

        self.file_or_files = [file_or_files] if isinstance(file_or_files, str) else file_or_files
        self.count = count

        timestamp_precision_map = {
            "micro": pcap.PCAP_TSTAMP_PRECISION_MICRO,
            "nano": pcap.PCAP_TSTAMP_PRECISION_NANO,
        }
        if timestamp_precision is not None:
            self.timestamp_precision = timestamp_precision_map[timestamp_precision]
        else:
            self.timestamp_precision = timestamp_precision

        self.filter = filter

        # Queue of files to process
        self._file_queue = deque(self.file_or_files)

        # Current file being processed
        self._current_file: str | None = None

        # Link type information
        self._rlt = -1
        self._rltn = "NONE"

        # Read handle
        self._rpd: pcap.pcap_t | None = None

        # Read thread
        self._rt: threading.Thread | None = None

        # Packets read
        self._rp: queue.Queue[CapturedPacketHeader | None] = queue.Queue()

        # Function to apply to each packet
        self._dead_callback: Callable[[CapturedPacketHeader], None] | None = None

        # Statistics: packets read, bytes read
        self._dead_stats = DeadCaptureStats()

        self._status = 0

    def __enter__(self) -> DeadCapture:
        self.dead_read()
        return self

    def __exit__(
            self,
            exc_type: type[BaseException],
            exc_value: BaseException | None,
            traceback: TracebackType | None,
    ) -> None:
        self.dead_stop()
        self._dead_close()

    def _dead_open_next_file(self) -> pcap.pcap_t | None:
        if not self._file_queue:
            return None

        self._current_file = str(Path(self._file_queue.popleft()).expanduser().resolve())
        if not Path(self._current_file).exists():
            raise DeadCaptureError(f"file: {self._current_file} does not exist")

        errbuf = c.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

        if self.timestamp_precision is not None:
            pd = pcap.open_offline_with_tstamp_precision(
                self._current_file.encode("utf-8"),
                self.timestamp_precision,
                errbuf
            )
        else:
            pd = pcap.open_offline(self._current_file.encode("utf-8"), errbuf)

        if pd is None:
            message = errbuf.value.decode("utf-8").lower()
            raise DeadCaptureError(f"failed to open pcap file '{self._current_file}': {message}")

        # Update link type information for the new file
        self._rlt = pcap.datalink(pd)

        linktype_name = pcap.datalink_val_to_name(self._rlt)
        if linktype_name is not None:
            self._rltn = f"DLT_{linktype_name.decode('utf-8')}"

        # Set filter if provided
        if self.filter:
            self._dead_set_filter(pd)

        return pd

    def _dead_set_filter(self, handle: pcap.pcap_t) -> None:
        bpf_program = pcap.bpf_program()
        status = pcap.compile(handle, c.byref(bpf_program),
                              self.filter.encode("utf-8"), 1,
                              pcap.PCAP_NETMASK_UNKNOWN)

        if status != 0:
            message = pcap.geterr(handle).decode("utf-8").lower()
            raise DeadCaptureError(f"failed to compile filter: {message}")

        status = pcap.setfilter(handle, c.byref(bpf_program))

        if status != 0:
            message = pcap.geterr(handle).decode("utf-8").lower()
            raise DeadCaptureError(f"failed to set filter: {message}")

        pcap.freecode(c.byref(bpf_program))

    def _dead_close(self) -> None:
        if self._rpd is not None:
            pcap.close(self._rpd)
            self._rpd = None

    def _dead_process_read_packet(
            self,
            user: Any,
            header: pcap.pkthdr,
            data: Any,
    ) -> None:
        # Process a read packet
        pkthdr = c.cast(header, c.POINTER(pcap.pkthdr)).contents

        ts = (pkthdr.ts.tv_sec, pkthdr.ts.tv_usec)
        caplen, length = pkthdr.caplen, pkthdr.len
        pkt = c.string_at(data, caplen)

        cph = CapturedPacketHeader(ts, length, pkt, caplen)

        # Add packet to the queue
        self._rp.put(cph)

        self._dead_stats.read += 1
        self._dead_stats.readb += caplen

        # If there's a callback, call the function
        if self._dead_callback is not None:
            self._dead_callback(cph)

    def _dead_read_threaded(self) -> None:
        self._rt = threading.Thread(target=self._dead_read_single_threaded)
        self._rt.start()

    def _dead_signal_handler(
            self,
            signum: int,
            frame: FrameType | None,
    ) -> None:
        if signum == signal.SIGINT:
            self._dead_read_stop()

    def _dead_read_single_threaded(self) -> None:
        while True:
            if self._rpd is None:
                self._rpd = self._dead_open_next_file()
                if self._rpd is None:
                    # No more files to process
                    break

            status = pcap.loop(
                self._rpd,
                self.count,
                pcap.pcap_handler(self._dead_process_read_packet),
                None)

            # Close the current file
            self._dead_close()

            # Loop break or error
            if status == -2 or status == -1 or self._status == -2:
                self._dead_close()
                break

        # End of all files reached
        self._rp.put(None)

    def _dead_read_stop(self) -> None:
        # Break the loop
        pcap.breakloop(self._rpd)
        self._status = -2
        self._rpd = None

    def dead_read(
            self,
            callback: Callable[[CapturedPacketHeader], None] | None = None,
            threaded: bool = False,
    ) -> None:
        """
        Read packets from the PCAP file(s).

        Parameters
        ----------
        callback : Callable[[CapturedPacketHeader], None] | None
            Function to apply to each packet read. (default: None)

        threaded : bool
            Whether to run reading in a separate thread. If this is set, then
            after the reading process is complete, the `stop()` function has to
            be called to stop and clean the reading thread. (default: False)

        Returns
        -------
        None
        """
        self._dead_callback = callback

        if threaded:
            self._dead_read_threaded()
        else:
            signal.signal(signal.SIGINT, partial(self._dead_signal_handler))
            self._dead_read_single_threaded()

    def is_dead_active(self) -> bool:
        """
        Check whether the reading thread is active.

        Returns
        -------
        bool
            True if the reading thread is active, otherwise False.
        """
        return self._rt is not None and self._rt.is_alive()

    def dead_stop(self) -> None:
        """
        Stop the reading thread.

        Returns
        -------
        None
        """
        if self._rt is not None and self._rpd is not None:
            self._dead_read_stop()
            self._rt.join()
            self._rp.put(None)

    def dead_get(self) -> CapturedPacketHeader | None:
        """
        Obtain a packet from the queue.

        Returns
        -------
        CapturedPacketHeader | None
            The next packet from the queue, or None if the queue is empty.
        """
        return self._rp.get()

    def dead_empty(self) -> bool:
        """
        Check whether the packet queue is empty.

        Returns
        -------
        bool
            True if the packet queue is empty, otherwise False.
        """
        return self._rp.empty()

    def dead_clear(self) -> None:
        """
        Clear the packet queue.

        Returns
        -------
        None
        """
        while not self._rp.empty():
            self._rp.get()
            self._rp.task_done()

    @property
    def dead_linktype(self) -> int:
        """
        Get the linktype for the current PCAP file.

        Returns
        -------
        int
            A DLT_* value.
        """
        return self._rlt

    @property
    def dead_linktype_name(self) -> str:
        """
        Get the name of the linktype for the current PCAP file.

        Returns
        -------
        str
            DLT_* as a string.
        """
        return self._rltn

    @property
    def dead_stats(self) -> DeadCaptureStats:
        """
        Get the statistics for the PCAP reading process.

        Returns
        -------
        DeadCaptureStats
            Statistics about the packets read.
        """
        return self._dead_stats


@dataclass
class PacketInfo:
    """
    Information gathered about a packet after being processed by dissectors.
    """

    packet_num: int

    linktype: int
    linktype_name: str

    captured: int
    remaining: int
    dissected: int = 0

    next_proto: int | str | None = None
    next_proto_lookup_entry: str | None = None

    current_proto: int | str | None = None
    current_proto_layer: Layer | None = None
    current_proto_name: str | None = None

    prev_proto: int | str | None = None
    prev_proto_layer: Layer | None = None
    prev_proto_name: str | None = None

    dl_src: str | None = None
    dl_dst: str | None = None

    net_src: str | None = None
    net_dst: str | None = None

    t_src: int | None = None
    t_dst: int | None = None

    proto_map: dict[str, FieldFormatter] | None = None

    fragmented: bool = False
    defragment: bool = False
    fragment_count: int = 0
    fragment_pool: queue.Queue[bytes] = field(default_factory=lambda: PacketInfo.init_fragment_pool(), init=False)

    dl_hdr_len: int | None = None
    proto_stack: list[str] | None = None

    invalid: bool = False
    invalid_proto_name: str | None = None
    invalid_msg: str | None = None

    @classmethod
    def init_fragment_pool(cls) -> queue.Queue[bytes]:
        if not hasattr(cls, "fragment_pool"):
            cls.fragment_pool = queue.Queue()
        return cls.fragment_pool

    def add_fragment(self, fragment: bytes) -> None:
        PacketInfo.fragment_pool.put(fragment)

    def get_fragments(self) -> list[bytes]:
        fragments = []
        while not PacketInfo.fragment_pool.empty():
            fragments.append(PacketInfo.fragment_pool.get())
        return fragments


@dataclass(frozen=True)
class PacketOptions:
    verbose: bool = False
    dump_short_packet_info: bool = False
    packet_num: bool = True
    dump: bool = False
    dump_chunk: bool = False
    numeric_mac: bool = False
    numeric_ip: bool = False
    numeric_port: bool = False
    check_checksum: bool = False
    dissect_invalid: bool = False
    timestamp: bool = True
    l2: bool = False
    unknown: bool = False


def dump_dissector_template(name: str, path: str) -> None:
    template = f"""from __future__ import annotations

from typing import Any, Callable

from unet.modules.dissect import FieldFormatter, Layer, PacketInfo, PacketOptions

__all__ = ["{name}_dissect"]


def {name}_dissect(pkto: PacketOptions, pkti: PacketInfo, buf: bytes) -> str:
    protocol = "{name.upper()}"
    f = FieldFormatter(protocol, brackets="[]")

    dump = f.line()
    if pkto.verbose:
        dump = f.lines(prefix=dump)

    return dump


def register_dissector_{name}(
        register: Callable[[
                str,
                str,
                str,
                int,
                Callable[[PacketOptions, PacketInfo, bytes], str]
            ], None],
) -> None:
    # Add the dissect routine to the disscet table here
    register('name', 'full name', 'dissect table entry', 0, {name}_dissect)


# If this protocol will require new entry in the dissect table, create it here.
# Otherwise, remove this function
def create_dissector_entry() -> str:
    # Return the entry identifier e.g. 'ip.proto' and the initial value for the
    # entry
    return ""
"""
    write_path = Path(f"{path}/{name}.py").expanduser().resolve()
    if write_path.exists():
        raise ValueError(f"file: {str(write_path)} already exists")
    with write_path.open("w") as f:
        f.write(template)
        f.flush()


@dataclass(frozen=True)
class DissectorInfo:
    a_name: str
    l_name: str
    entry: str
    id: int | str
    dissect_routine: Callable[[PacketOptions, PacketInfo, bytes], str]
    dissect_routine_name: str


class Dissect(LiveCapture, DeadCapture):
    def __init__(
            self,
            action: Literal["live", "dead"],
            interface: str | None = None,
            count: int = -1,
            snapshot_length: int = 262140,
            promiscuous: bool = True,
            monitor: bool = False,
            buffer_timeout: int = 1000,
            immediate: bool = True,
            buffer_size: int = 8388608,
            timestamp_type: Literal["host", "host_lowperc", "host_hiperc",
                                    "host_hiperc_unsynced", "adapter",
                                    "adapter_unsynced"] = "host",
            timestamp_precision: Literal["micro", "nano"] = "micro",
            nonblock: bool = True,
            timeout: int = 0,
            wfile: str | None = None,
            max_files: int = -1,
            max_wfile_len: int = -1,
            rfile: str | list[str] | None = None,
            filter: str | None = None,
            dissectors_path: str | None = None,
            colorify: bool = True
    ) -> None:
        self.action = action
        self.colorify = colorify

        self._colors = FieldFormatterColor()

        self._module_handles = self._load_dissector_modules(dissectors_path)
        self._dissect_table = self._create_dissect_table_entries()

        self._remove_unnecessary(self._module_handles)
        self._register_dissectors()

        # Initialize parents
        # Live
        if self.action == "live":
            if interface is None:
                raise ValueError("interface must be specified for live captures")
            LiveCapture.__init__(self, interface, count, snapshot_length,
                                 promiscuous, monitor, buffer_timeout,
                                 immediate, buffer_size, timestamp_type,
                                 timestamp_precision, nonblock, timeout, wfile,
                                 max_files, max_wfile_len, filter)
        # Dead
        else:
            if rfile is None:
                raise ValueError("read files must be specified for dead captures")
            DeadCapture.__init__(self, rfile, count, timestamp_precision, filter)

    def _load_dissector_modules(
            self,
            dissectors_path: str | None = None,
    ) -> dict[str, ModuleType]:
        handles = {}
        built_in_path = Path(__file__.strip("dissect.py")).resolve()
        exclude = {"__init__.py", "dissect.py", "__pycache__"}

        # Helper function to recursively process a directory
        def process_directory(path: Path) -> None:
            for item in path.rglob("*.py"):
                name = item.name
                stem = item.stem

                if name in exclude:
                    continue

                handle = load_module(str(item), stem)
                if handle is None:
                    continue

                handles[stem] = handle

        # Load built-in modules
        process_directory(built_in_path)

        # Load other supplied to us
        if dissectors_path is not None:
            other_path = Path(dissectors_path).expanduser().resolve()

            if other_path.is_dir():
                process_directory(other_path)
            elif other_path.is_file() and other_path.suffix == ".py":
                handle = load_module(str(other_path), other_path.stem)
                if handle is not None:
                    handles[other_path.stem] = handle

        return handles

    def _create_dissect_table_entries(self) -> dict[str, Any]:
        entries = {}

        for handle in self._module_handles.values():
            if not lookup_symbol(handle, "create_dissector_entry"):
                continue

            create_dissector_entry = getattr(handle, "create_dissector_entry")
            entry = create_dissector_entry()
            entries[entry] = {}

        return entries

    def _create_dissect_entry(
            self,
            entry: str,
            init_value,
    ) -> None:
        if entry in self._dissect_table:
            return
        self._dissect_table[entry] = init_value

    def _remove_unnecessary(self, handles: dict[str, Any]) -> None:
        # Remove unnecessary modules
        for name, handle in list(handles.items()):
            if (not lookup_symbol(handle, f"{name}_dissect")
                    or not lookup_symbol(handle, f"register_dissector_{name}")):
                del handles[name]
                continue

    def _register_dissectors(self) -> None:
        for name, handle in self._module_handles.items():
            if not lookup_symbol(handle, f"register_dissector_{name}"):
                continue

            register_dissector = getattr(handle, f"register_dissector_{name}")
            try:
                register_dissector(self._register_dissector)
            except TypeError:
                continue

    def _register_dissector(
            self,
            a_name: str,
            l_name: str,
            entry: str,
            id: int | str,
            dissect_routine: Callable[[PacketOptions, PacketInfo, bytes], str],
    ) -> None:
        try:
            self._dissect_table[entry]
        except KeyError:
            return

        if id in self._dissect_table[entry]:
            return

        di = DissectorInfo(a_name, l_name, entry, id, dissect_routine,
                           dissect_routine.__name__)
        self._dissect_table[entry][a_name] = di

    def packet_dissect(
            self,
            pkto: PacketOptions,
            pkt_num: int,
            caplen: int,
            length: int,
            buf: bytes,
            timestamp: tuple[int, int],
            linktype: int,
            linktype_name: str,
    ) -> str:
        parts = []

        pkti = PacketInfo(
            pkt_num,
            linktype,
            linktype_name,
            caplen,
            caplen,
            proto_map={},
            proto_stack=[],
        )

        pkti.next_proto = linktype
        pkti.next_proto_lookup_entry = "dl.type"

        try:
            while pkti.next_proto != -1:
                have_dissector = False

                if pkti.next_proto_lookup_entry is None:
                    break

                for dissector_info in self._dissect_table[pkti.next_proto_lookup_entry].values():
                    if dissector_info.id == pkti.next_proto:
                        dissector = dissector_info.dissect_routine

                        if pkti.defragment:
                            fragments = pkti.get_fragments()

                            pkti.fragment_count = len(fragments)
                            pkti.defragment = False

                            raw_pkt = b"".join(fragments)
                        else:
                            raw_pkt = buf[pkti.dissected:]

                        dump = dissector(pkto, pkti, raw_pkt)

                        if pkti.invalid:
                            dump = self._handle_invalid_packet(pkto, pkti,
                                                               timestamp)
                            parts.append(dump)
                            return self._format_packet_dump(parts, pkto, pkti,
                                                            buf, timestamp)

                        if (pkti.current_proto_layer != Layer.DATA_LINK
                                or (pkti.current_proto_layer == Layer.DATA_LINK
                                    and pkto.l2)):
                            parts.append(dump)

                        have_dissector = True
                        break

                if not have_dissector:
                    self._handle_no_dissector(pkto, pkti, buf, parts)
                    break

        except KeyError:
            if pkti.next_proto is not None or pkti.next_proto != -1:
                self._handle_no_dissector(pkto, pkti, buf, parts)

        dump = self._format_packet_dump(parts, pkto, pkti, buf, timestamp)
        return dump

    def _handle_invalid_packet(
            self,
            pkto: PacketOptions,
            pkti: PacketInfo,
            timestamp: tuple[int, int],
    ) -> str:
        dump = f"{pkti.invalid_msg.upper()}"

        if pkti.invalid_proto_name is not None:
            dump = f"[{pkti.invalid_proto_name}, {dump}]"

        if self.colorify:
            dump = Color.color(dump, "red highlight")

        return dump

    def _handle_no_dissector(
            self,
            pkto: PacketOptions,
            pkti: PacketInfo,
            buf: bytes,
            parts: list[str],
    ) -> None:
        if pkti.current_proto_layer is None:
            pkti.current_proto_layer = Layer.DATA_LINK
        elif pkti.current_proto_layer == Layer.DATA_LINK:
            pkti.current_proto_layer = Layer.NETWORK
        elif pkti.current_proto_layer == Layer.NETWORK:
            pkti.current_proto_layer = Layer.TRANSPORT
        elif pkti.current_proto_layer == Layer.TRANSPORT:
            pkti.current_proto_layer = Layer.OTHER

        if (pkti.current_proto_layer in {2, 3, 4}
                or (pkti.current_proto_layer >= 5 and pkto.unknown)):
            dissector = self._dissect_table["unknown"]["unknown"].dissect_routine
            dump = dissector(pkto, pkti, buf)
            parts.append(dump)

    def _format_packet_dump(
            self,
            parts: list[str],
            pkto: PacketOptions,
            pkti: PacketInfo,
            buf: bytes,
            timestamp: tuple[int, int],
    ) -> str:
        f = FieldFormatter("Packet")
        f.add_field("packet number", pkti.packet_num)

        if self.action == "live":
            f.add_field("interface", self.interface)
        else:
            f.add_field("from", self._current_file)

        f.add_field("arrival time (since epoch)", f"{timestamp[0]}.{timestamp[1]}")
        f.add_field("linktype", pkti.linktype, alt_value=pkti.linktype_name,
                    alt_value_brackets=("(", ")"), alt_sep=" ")
        f.add_field("capture length", pkti.captured, unit="bytes",
                    alt_value=pkti.captured * 8, alt_unit="bits", alt_sep=": ")
        f.add_field("protocol stack", ", ".join(pkti.proto_stack),
                    value_brackets=("[", "]"))

        if pkto.verbose:
            parts.insert(0, f.lines())

            dump = "\n\n".join(parts)
            dump = indent_lines("\n" + dump, indent=2)
        else:
            dump = ": ".join(parts)

        if pkto.dump:
            packet_hexdump = hexdump(buf, indent=2)
            if pkto.verbose:
                packet_hexdump = f"\n{packet_hexdump}"
            if self.colorify:
                packet_hexdump = Color.color(packet_hexdump, self._colors.alt_value)
            dump = f"{dump}\n{packet_hexdump}"

        if pkto.verbose:
            dump = f"{dump}"

        if pkto.timestamp:
            t = self._format_timestamp(timestamp)
            dump = f"{t}: {dump}"

        if pkto.packet_num:
            packet_num = self._format_packet_num(pkti.packet_num)
            dump = f"{packet_num}. {dump}"

        if pkto.verbose:
            max_x = shutil.get_terminal_size().columns
            delim = Assets.HORIZONTAL_LINE * max_x
            if self.colorify:
                delim = Color.color(delim, self._colors.sep)
            dump = f"\n{delim}{dump}\n{delim}"

        if not pkto.verbose and pkto.dump:
            dump = "\n" + dump

        return dump

    def _format_timestamp(self, timestamp):
        t = time.strftime("%H:%M:%S", time.localtime(timestamp[0])) + f".{timestamp[1]}"
        return Color.color(t, self._colors.unit) if self.colorify else t

    def _format_packet_num(self, packet_num):
        packet_num_str = str(packet_num)
        return Color.color(packet_num_str, self._colors.alt_unit) if self.colorify else packet_num_str

    def packet_print(
            self,
            pkto: PacketOptions,
            cph: CapturedPacketHeader,
    ) -> None:
        dissected_packet = self.packet_dissect(
            pkto,
            self.pkt_num,
            cph.caplen,
            cph.length,
            cph.buf,
            cph.timestamp,
            self.live_linktype if self.action == "live" else self.dead_linktype,
            self.live_linktype_name if self.action == "live" else self.dead_linktype_name,
        )
        print(dissected_packet)
        self.pkt_num += 1

    def packet_print_loop(
            self,
            pkto: PacketOptions,
            threaded: bool = False,
    ) -> None:
        setattr(self, "pkt_num", 1)

        if self.action == "live":
            # Start capture loop
            self.live_capture(callback=lambda cph: self.packet_print(pkto, cph),
                              threaded=threaded)
        else:
            self.dead_read(callback=lambda cph: self.packet_print(pkto, cph),
                           threaded=threaded)

    def print_stats(self) -> None:
        stats = self.live_stats if self.action == "live" else self.dead_stats
        if self.action == "live":
            if not self.colorify:
                stats_dump = [
                    f"{stats.cap} packets captured",
                    f"{stats.bcap} bytes captured",
                    f"{stats.qcap} packets processed",
                    f"{stats.drop} packets dropped",
                    f"\ndone in: {stats.run_time:.6f} seconds"
                ]
            else:
                stats_dump = [
                    "%s %s" % (
                        Color.color(str(stats.cap), self._colors.value),
                        Color.color("packets captured", self._colors.name),
                    ),
                    "%s %s" % (
                        Color.color(str(stats.bcap), self._colors.value),
                        Color.color("bytes captured", self._colors.name),
                    ),
                    "%s %s" % (
                        Color.color(str(stats.qcap), self._colors.value),
                        Color.color("packets processed", self._colors.name),
                    ),
                    "%s %s" % (
                        Color.color(str(stats.drop), self._colors.value),
                        Color.color("packets dropped", self._colors.name),
                    ),
                    "\n%s: %s %s" % (
                        Color.color("done in", self._colors.name),
                        Color.color(f"{stats.run_time:.6f}", self._colors.value),
                        Color.color("seconds", self._colors.alt_unit),
                    ),
                ]
        else:
            if not self.colorify:
                stats_dump = [
                    f"{stats.read} packets read",
                    f"{stats.readb} bytes read",
                ]
            else:
                stats_dump = [
                    "%s %s" % (
                        Color.color(str(stats.read), self._colors.value),
                        Color.color("packets read", self._colors.name),
                    ),
                    "%s %s" % (
                        Color.color(str(stats.readb), self._colors.value),
                        Color.color("bytes read", self._colors.name),
                    ),
                ]
        print("\n".join(stats_dump))

    def list_dissect_table_entries(self) -> None:
        pass

    def list_dissectors(self) -> None:
        pass


FLAGS: Final[dict[str, PositionalFlag | OptionFlag | Group]] = {
    "filter": PositionalFlag(
        help="set capture filter. Process only those packets for which the filter "
             "is true. If not set all packets on the network will be processed",
        nargs="?",
        default=None,
    ),
    "iflag": OptionFlag(
        short="-i",
        long="--interface",
        help="capture packets on <interface>",
        type=str,
        required=False,
        default=None,
        metavar="<interface>",
    ),
    "cflag": OptionFlag(
        short="-c",
        long="--count",
        help="exit after receiving <count> packets",
        type=int,
        required=False,
        default=-1,
        metavar="<count>",
    ),
    "sflag": OptionFlag(
        short="-s",
        long="--snapshot-length",
        help="specify the snapshot length (in bytes) for packet capture. "
             "This sets the maximum amount of data to capture for each packet. "
             "A higher value captures more packet data, while a lower value "
             "improves performance by only capturing packet headers.",
        type=int,
        required=False,
        default=262140,
        metavar="<length>",
    ),
    "Pflag": OptionFlag(
        short="-P",
        long="--no-promisc",
        help="don't put interface into promiscuous mode",
        action="store_false",
        required=False,
        default=True,
    ),
    "Tflag": OptionFlag(
        short="-T",
        long="--bufer-timeout",
        help="set the buffer timeout in ms for packet capture. Determines how "
             "long to wait before delivering packets",
        required=False,
        default=1000,
        metavar="<ms>",
    ),
    "Iflag": OptionFlag(
        short="-I",
        long="--immediate",
        help="deliver packets to process them as soon as they arrive",
        action="store_true",
        required=False,
        default=False,
    ),
    "bflag": OptionFlag(
        short="-b",
        long="--buffer-size",
        help="set the capture buffer size (in bytes)",
        type=int,
        required=False,
        default=8388608,
        metavar="<size>",
    ),
    "Nflag": OptionFlag(
        short="-N",
        long="--no-non-block",
        help="do not put capture process in non-blocking mode. This might result "
             "in delays on interrupt events (like ctrl+c)",
        action="store_false",
        required=False,
        default=True,
    ),
    "tflag": OptionFlag(
        short="-t",
        long="--timestamp-type",
        help="set the time stamp type for the capture to <type>",
        type=str,
        choices={"host", "host_lowperc", "host_hiperc", "host_hiperc_unsynced",
                 "adapter", "adapter_unsynced"},
        required=False,
        default="host",
        metavar='<type>'
    ),
    "pflag": OptionFlag(
        short="-p",
        long="--timestamp-precision",
        help="set the time stamp precision for the capture",
        type=str,
        choices={"micro", "nano"},
        required=False,
        default="micro",
        metavar="<micro,nano>"
    ),
    "rflag": OptionFlag(
        short="-r",
        long="--read",
        help="file or comma separated list of files from which to read packets",
        type=str,
        required=False,
        default=None,
        metavar="<f.pcap0,f.pcap1,...>",
    ),
    "wflag": OptionFlag(
        short="-w",
        long="--write",
        help="write captured packets to file",
        type=str,
        required=False,
        default=None,
        metavar="<name>",
    ),
    "mflag": OptionFlag(
        short="-m",
        long="--max-files",
        help="limit the number of files to the supplied number `n`. If the number "
             "of files created will reach `n`, files from the beginning will be "
             "overwritten (used only with `-w`)",
        type=int,
        required=False,
        default=-1,
        metavar="<n>",
    ),
    "Mflag": OptionFlag(
        short="-M",
        long="--max-file-len",
        help="keep capture file(s) around `len` KiB big",
        type=int,
        required=False,
        default=-1,
        metavar="<len>",
    ),
    "gflag": OptionFlag(
        short="-g",
        help="do not print packets, dump only the count",
        action="store_true",
        required=False,
        default=False,
    ),
    "list_interfaces": OptionFlag(
        long="--list-interfaces",
        help="print list of interfaces and exit",
        action="store_true",
        required=False,
        default=False,
    ),
    "new": OptionFlag(
        long="--new",
        help="dump the dissector file template",
        type=str,
        required=False,
        default=None,
        metavar="<name>",
    ),
    "new_path": OptionFlag(
        long="--new-path",
        help="use this path to dump the dissector file template",
        type=str,
        required=False,
        default=".",
        metavar="<path>",
    ),
    "Dflag": OptionFlag(
        short="-D",
        long="--dpath",
        help="load custom dissectors from `path`",
        type=str,
        required=False,
        default=None,
        metavar="<path>",
    ),
    "kflag": OptionFlag(
        short="-k",
        long="--no-color",
        help="disable colors",
        action="store_false",
        required=False,
        default=False,
    ),
    "output options": Group(
        arguments={
            "vflag": OptionFlag(
                short="-v",
                help="verbose output",
                action="store_true",
                required=False,
                default=False,
            ),
            "nflag": OptionFlag(
                short="-n",
                help="include packet number at the beginning of the dump line",
                action="store_true",
                required=False,
                default=False,
            ),
            "Xflag": OptionFlag(
                short="-X",
                help="dump packet in hex",
                action="store_true",
                required=False,
                default=False,
            ),
            "xflag": OptionFlag(
                short="-x",
                help="dump each packet chunk in hex separately",
                action="store_true",
                required=False,
                default=False,
            ),
            "Aflag": OptionFlag(
                short="-A",
                help="do not try to resolve mac addresses",
                action="store_true",
                required=False,
                default=False,
            ),
            "aflag": OptionFlag(
                short="-a",
                help="do not try to resolve ip addresses",
                action="store_true",
                required=False,
                default=False,
            ),
            "dflag": OptionFlag(
                short="-d",
                help="do not try to resolve port numbers to service names",
                action="store_true",
                required=False,
                default=False,
            ),
            "Sflag": OptionFlag(
                short="-S",
                help="validate checksums if possible",
                action="store_true",
                required=False,
                default=False,
            ),
            "jflag": OptionFlag(
                short="-j",
                help="include timestamp in the packet dump",
                action="store_true",
                required=False,
                default=False,
            ),
            "eflag": OptionFlag(
                short="-e",
                help="dump link level headers",
                action="store_true",
                required=False,
                default=False,
            ),
            "uflag": OptionFlag(
                short="-u",
                help="dump header as unknown if a dissector was not found or "
                     "was not recognized. This only applies to protocols from "
                     "layers session, presentation and application. Protocols "
                     "from layers below are dumped as unknown even if this option "
                     "is not set",
                action="store_true",
                required=False,
                default=False,
            )
        }
    )
}


def main(args: list[str]) -> None:
    parser = FlagParser(prog="dissect", description="dump traffic on a network")
    parser.add_arguments(FLAGS)

    flags = parser.parse_args(args)

    # List interfaces and exit
    if flags.list_interfaces:
        colors = FieldFormatterColor()
        interfaces = get_capture_devs()

        for num, interface in enumerate(interfaces, start=1):
            interface = Color.color(interface, colors.name)
            num_str = Color.color(str(num), colors.alt_unit)
            output = f"{num_str}. {interface}"
            print(output)

        return

    # Create new dissector template
    if flags.new:
        dump_dissector_template(flags.new, flags.new_path)
        colors = FieldFormatterColor()
        output = (f"+ created {Color.color(flags.new, colors.name)} in "
                  f"{Color.color(flags.new_path, colors.value)}")
        print(output)
        return

    # Set action based on flags
    action: Literal["dead", "live"] = "dead" if flags.rflag else "live"

    if action == "live":
        colors = FieldFormatterColor()
        output = "%s: capturing on: %s, snapshot length: %s bytes" % (
            Color.color("unet dissect", colors.value),
            Color.color(flags.iflag, colors.alt_name),
            Color.color(str(flags.sflag), colors.alt_unit),
        )
        print(output, end="\n\n")
    else:
        colors = FieldFormatterColor()
        output = "%s: reading from: %s, snapshot length: %s bytes" % (
            Color.color("unet dissect", colors.value),
            Color.color(str(Path(flags.rflag).expanduser().resolve()), colors.name),
            Color.color(str(flags.sflag), colors.alt_unit),
        )
        print(output, end="\n\n")

    # Initialize Dissect
    try:
        interface = flags.iflag
        count = flags.cflag
        snapshot_length = flags.sflag
        promiscuous = flags.Pflag
        monitor = False
        buffer_timeout = flags.Tflag
        immediate = flags.Iflag
        buffer_size = flags.bflag
        timestamp_type = flags.tflag
        timestamp_precision = flags.pflag
        nonblock = flags.Nflag
        timeout = 0
        wfile = flags.wflag
        max_files = flags.mflag
        max_wfile_len = flags.Mflag
        rfile = flags.rflag.split(",") if flags.rflag else None
        capture_filter = flags.filter
        dissectors_path = flags.Dflag

        dissect = Dissect(
            action, interface, count, snapshot_length, promiscuous, monitor,
            buffer_timeout, immediate, buffer_size, timestamp_type,
            timestamp_precision, nonblock, timeout, wfile, max_files,
            max_wfile_len, rfile, capture_filter, dissectors_path)
    except Exception as e:
        _error(str(e))

    # Set packet options
    pkto = PacketOptions(
        flags.vflag, False, flags.nflag, flags.Xflag, flags.xflag,
        flags.Aflag, flags.aflag, flags.dflag, flags.Sflag,
        False, flags.jflag, flags.eflag
    )

    # Process packets
    if not flags.gflag:
        dissect.packet_print_loop(pkto)
    else:
        pkt_count = 0
        byte_count = 0
        colors = FieldFormatterColor()

        def callback(cph: CapturedPacketHeader) -> None:
            nonlocal pkt_count, byte_count, colors
            pkt_count += 1
            byte_count += cph.caplen

            output = "\r%s packets captured, %s bytes, %s KiB, %s MiB " % (
                Color.color(str(pkt_count), colors.value),
                Color.color(str(byte_count), colors.alt_value),
                Color.color(f"{byte_count / 1024:.2f}", colors.alt_value),
                Color.color(f"{byte_count / (1024 ** 2):.2f}", colors.alt_value),
            )

            print(output, end="")

        dissect.live_capture(callback=callback)

    if action == "live":
        dissect.live_clear()
    else:
        dissect.dead_clear()

    print()
    dissect.print_stats()
