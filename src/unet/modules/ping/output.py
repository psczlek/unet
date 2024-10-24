from typing import Final

from unet.flag import Group, OptionFlag

__all__ = ["OUTPUT_FLAGS"]


# This is the same as the dissect module, but we use 'long' only to save characters
# for the main program to consume.
OUTPUT_FLAGS: Final = {
    "output": Group(
        description="packet printing options",
        arguments={
            "no_capture": OptionFlag(
                long="--no-capture",
                help="do not capture send/received packets",
                action="store_true",
                required=False,
                default=False,
            ),
            "verbose": OptionFlag(
                short="-V",
                long="--verbose",
                help="verbose output",
                action="store_true",
                required=False,
                default=False,
            ),
            "timestamp": OptionFlag(
                short="-T",
                long="--timestamp",
                help="include timestamp in the packet dump",
                action="store_true",
                required=False,
                default=False,
            ),
            "num": OptionFlag(
                short="-N",
                long="--num",
                help="include packet number at the beginning of the dump line",
                action="store_true",
                required=False,
                default=False,
            ),
            "hexdump": OptionFlag(
                short="-x",
                long="--hexdump",
                help="dump packet int hex",
                action="store_true",
                required=False,
                default=False,
            ),
            "dumpchunk": OptionFlag(
                short="-u",
                long="--dump-chunk",
                help="dump each packet chunk in hex separately",
                action="store_true",
                required=False,
                default=False,
            ),
            "no_mac_resolve": OptionFlag(
                short="-A",
                long="--no-mac-resolve",
                help="do not try to resolve mac addresses",
                action="store_true",
                required=False,
                default=False,
            ),
            "no_ip_resolve": OptionFlag(
                short="-a",
                long="--no-ip-resolve",
                help="do not try to resolve ip addresses",
                action="store_true",
                required=False,
                default=False,
            ),
            "no_port_resolve": OptionFlag(
                short="-k",
                long="--no-port-resolve",
                help="do not try to resolve port numbers to service names",
                action="store_true",
                required=False,
                default=False,
            ),
            "sum_ok": OptionFlag(
                short="-S",
                long="--validate-sum",
                help="validate checksums if possible",
                action="store_true",
                required=False,
                default=False,
            ),
            "l2": OptionFlag(
                short="-e",
                long="--l2",
                help="dump link level headers",
                action="store_true",
                required=False,
                default=False,
            ),
            "unknown": OptionFlag(
                long="--unknown",
                help="dump header as unknown if a dissector was not found or "
                     "was not recognized. This only applies to protocols from "
                     "layers session, presentation and application. Protocols "
                     "from layers below are dumped as unknown even if this "
                     "option is not set",
                action="store_true",
                required=False,
                default=False,
            ),
            "no_sent": OptionFlag(
                long="--no-sent",
                help="do not show sent packets",
                action="store_true",
                required=False,
                default=False,
            ),
            "bpf": OptionFlag(
                long="--bpf",
                help="apply custom BPF filter",
                type=str,
                required=False,
                default=None,
                metavar="<filter expression>",
            ),
            "bpf_append": OptionFlag(
                long="--bpf-append",
                help="append expression to the automatically generated BPF filter",
                type=str,
                required=False,
                default=None,
                metavar="<filter expression>",
            ),
            "save": OptionFlag(
                long="--save",
                help="save captured packets to a file",
                type=str,
                required=False,
                default=None,
                metavar="<filename>"
            ),
        }
    )
}
