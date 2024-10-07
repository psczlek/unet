import locale
import sys
from enum import StrEnum

from unet.coloring import Color

__all__ = ["eprint", "wprint", "supports_utf8", "Assets"]


def eprint(
        msg: str,
        /,
        *,
        terminate: bool = True,
        exit_code: int = 1,
        flush: bool = False,
        precedence: str = "error",
        end: str = "\n",
) -> None:
    """
    Print an error message to stderr and exit the program if needed.
    """
    if not msg:
        return
    sys.stderr.write(f"{Color.red(Color.bold(f'{precedence}'))}: {msg}{end}")
    if flush:
        sys.stderr.flush()
    if terminate:
        exit(exit_code)


def wprint(
        msg: str,
        /,
        *,
        flush: bool = False,
        precedence: str = "warning",
        end: str = "\n",
) -> None:
    """
    Print a warning message to stderr.
    """
    if not msg:
        return
    sys.stderr.write(f"{Color.yellow(Color.bold(f'{precedence}'))}: {msg}{end}")
    if flush:
        sys.stderr.flush()


def supports_utf8() -> bool:
    """
    Check if the current system supports UTF-8.
    """
    is_a_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return locale.getpreferredencoding().lower() == "utf-8" and is_a_tty


class Assets(StrEnum):
    """
    Miscellaneous UTF-8 characters and their ASCII equivalents if UTF-8 is
    not supported.
    """

    RIGHTWARDS_ARROW = "→" if supports_utf8() else "->"
    LEFTWARDS_ARROW = "←" if supports_utf8() else "<-"
    RIGHTWARDS_DOUBLE_ARROW = "⇒" if supports_utf8() else "=>"
    LEFTWARDS_DOUBLE_ARROW = "⇐" if supports_utf8() else "<="
    HORIZONTAL_LINE = "─" if supports_utf8() else "-"
    VERTICAL_LINE = "│" if supports_utf8() else "|"
    CROSS = "┼" if supports_utf8() else "+"
    TOP_T_INTERSECTION = "┬" if supports_utf8() else "+"
    BOTTOM_T_INTERSECTION = "┴" if supports_utf8() else "+"
    TOP_LEFT_ROUNDED_JUNCTION = "╭" if supports_utf8() else "+"
    TOP_RIGHT_ROUNDED_JUNCTION = "╮" if supports_utf8() else "+"
    BOTTOM_LEFT_ROUNDED_JUNCTION = "╰" if supports_utf8() else "+"
    BOTTOM_RIGHT_ROUNDED_JUNCTION = "╯" if supports_utf8() else "+"
