import sys
from coloring import Color


def eprintln(
        msg: str,
        terminate: bool = True,
        exit_code: int = 1,
        flush: bool = False,
        precedence: str = "error",
        end: str = "\n"
    ) -> None:
    """Print an error message to stderr and exit the program if needed"""
    sys.stderr.write(f"{Color.redify(f'{precedence}')}: {msg}{end}")
    if flush: sys.stderr.flush()
    if terminate: exit(exit_code)


def wprintln(
        msg: str,
        flush: bool = False,
        precedence: str = "warning",
        end: str = "\n"
    ) -> None:
    """Print a warning message to stderr"""
    sys.stderr.write(f"{Color.yellowify(f'{precedence}')}: {msg}{end}")
    if flush: sys.stderr.flush()


def iprintln(
        msg: str,
        flush: bool = False,
        precedence: str = "info",
        end: str = "\n"
    ) -> None:
    """Print an info message to stdout"""
    sys.stdout.write(f"{Color.blueify(f'{precedence}')}: {msg}{end}")
    if flush: sys.stdout.flush()
