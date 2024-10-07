from dataclasses import dataclass

import pytest


@pytest.mark.parametrize("args, expected", [
    ([], None),
    (
        ["ping", "192.168.0.1", "-m", "tcp", "-v", "-p", "1-1024"],
        {"ping": ["192.168.0.1", "-m", "tcp", "-v", "-p", "1-1024"]},
    ),
    (
        ["-p", "remote", "-l", "192.168.0.1", "traceroute", "192.168.0.2", "-i", "eth0"],
        {"unet": ["-p"], "remote": ["-l", "192.168.0.1"], "traceroute": ["192.168.0.2", "-i", "eth0"]},
    ),
    (
        ["--show-modules"],
        {"unet": ["--show-modules"]},
    ),
    (
        ["-p", "dissect", "-v", "-c", "128", "--bpf=", "'ip src 192.168.0.1'", "ping", "-m", "icmp", "192.168.0.1"],
        {"unet": ["-p"], "dissect": ["-v", "-c", "128", "--bpf=", "'ip src 192.168.0.1'"], "ping": ["-m", "icmp", "192.168.0.1"]},
    ),
    (
        ["--show-history"],
        {"unet": ["--show-history"]},
    ),
    (
            ["--show-history"],
            {"unet": ["--show-history"]},
    ),
])
def test_args(args: list[str], expected: dict[str, list[str]] | None) -> None:
    # assume the following are implemented
    known_tools = {"unet", "ping", "dissect", "traceroute", "remote"}
    print(process_args(known_tools, args))


# TODO: add check for invalid invokes
def process_args(known_tools: set[str], args: list[str]) -> dict[str, list[str]] | None:
    # nothing to do
    if not len(args):
        return None
    invoked: dict[str, int] = {}
    # collect invoked tools and their indexes from the args list.
    # Indexes will be used later to slice the list accordingly
    for arg in args:
        if arg in known_tools:
            invoked[arg] = args.index(arg)
    args_map: dict[str, list[str]] = {}
    # if no tool has been invoked but there are arguments to parse
    # pass them to the main one
    if not len(invoked):
        args_map["unet"] = args
    # remove invalid invokes
    for name in args_map:
        if name not in known_tools:
            args_map.pop(name)
    return args_map
