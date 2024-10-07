"""
Colorify terminal output.
"""


import os
import string
import sys
from dataclasses import dataclass
from typing import Final

__all__ = [
    "disable_colors",
    "supports_colors",
    "supports_true_color",
    "Color",
]


_on = True


def disable_colors() -> None:
    global _on
    _on = False


def supports_colors() -> bool:
    """
    Check if ANSI colors are supported.

    Returns
    -------
    bool
        True if ansi colors are supported. False otherwise.
    """
    if not _on:
        return False

    supported_platform = os.name != ("nt" or "ANSICON" in os.environ
                                     or "WT_SESSION" in os.environ)
    is_a_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return supported_platform and is_a_tty


def supports_true_color() -> bool:
    """
    Check if true colors are supported.

    Returns
    -------
    bool
        True if true colors are supported. False otherwise.
    """
    if not _on:
        return False

    true_color_env_vars = ["COLORTERM", "ITERM_SESSION_ID", "WT_SESSION"]
    true_color_terms = ["truecolor", "24bit"]
    is_a_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    for evar in true_color_env_vars:
        if evar in os.environ:
            if os.environ[evar] in true_color_terms or evar == "COLORTERM":
                return True and is_a_tty

    return False


@dataclass(frozen=True)
class RGB:
    r: int
    g: int
    b: int
    bold: bool = False


@dataclass(frozen=True)
class Hex:
    value: str
    bold: bool = False


class Color:
    """
    Colorify terminal output.
    """

    ANSI_COLORS: Final = {
        "red": "\x1b[0;31m",
        "light_red": "\x1b[0;91m",
        "green": "\x1b[0;32m",
        "light_green": "\x1b[0;92m",
        "yellow": "\x1b[0;33m",
        "light_yellow": "\x1b[0;93m",
        "blue": "\x1b[0;34m",
        "light_blue": "\x1b[0;94m",
        "pink": "\x1b[0;35m",
        "light_pink": "\x1b[0;95m",
        "cyan": "\x1b[0;36m",
        "light_cyan": "\x1b[0;96m",
        "gray": "\x1b[0;38;5;240m",
        "light_gray": "\x1b[0;37m",
        "normal": "\x1b[0m",
        "bold": "\x1b[1m",
        "highlight": "\x1b[3m",
    }

    colors: dict[str, str | RGB | Hex] = {
        "red": "\x1b[0;31m",
        "light_red": "\x1b[0;91m",
        "green": "\x1b[0;32m",
        "light_green": "\x1b[0;92m",
        "yellow": "\x1b[0;33m",
        "light_yellow": "\x1b[0;93m",
        "blue": "\x1b[0;34m",
        "light_blue": "\x1b[0;94m",
        "pink": "\x1b[0;35m",
        "light_pink": "\x1b[0;95m",
        "cyan": "\x1b[0;36m",
        "light_cyan": "\x1b[0;96m",
        "gray": "\x1b[0;38;5;240m",
        "light_gray": "\x1b[0;37m",
        "normal": "\x1b[0m",
        "bold": "\x1b[1m",
        "highlight": "\x1b[3m",
    }

    # =================
    # coloring routines
    # =================

    @staticmethod
    def red(msg: str, /) -> str:
        return Color.color(msg, "red")

    @staticmethod
    def light_red(msg: str, /) -> str:
        return Color.color(msg, "light_red")

    @staticmethod
    def green(msg: str, /) -> str:
        return Color.color(msg, "green")

    @staticmethod
    def light_green(msg: str, /) -> str:
        return Color.color(msg, "light_green")

    @staticmethod
    def blue(msg: str, /) -> str:
        return Color.color(msg, "blue")

    @staticmethod
    def light_blue(msg: str, /) -> str:
        return Color.color(msg, "light_blue")

    @staticmethod
    def yellow(msg: str, /) -> str:
        return Color.color(msg, "yellow")

    @staticmethod
    def light_yellow(msg: str, /) -> str:
        return Color.color(msg, "light_yellow")

    @staticmethod
    def gray(msg: str, /) -> str:
        return Color.color(msg, "gray")

    @staticmethod
    def light_gray(msg: str, /) -> str:
        return Color.color(msg, "light_gray")

    @staticmethod
    def pink(msg: str, /) -> str:
        return Color.color(msg, "pink")

    @staticmethod
    def light_pink(msg: str, /) -> str:
        return Color.color(msg, "light_pink")

    @staticmethod
    def cyan(msg: str, /) -> str:
        return Color.color(msg, "cyan")

    @staticmethod
    def light_cyan(msg: str, /) -> str:
        return Color.color(msg, "light_cyan")

    @staticmethod
    def bold(msg: str, /) -> str:
        return Color.color(msg, "bold")

    @staticmethod
    def color(
            msg: str,
            color: RGB | Hex | str | None = None,
            /) -> str:
        """
        Color a message.

        Parameters
        ----------
        msg : str
            String to be colored.

        color : RGB | Hex | str | None
            Color name, tuple with RGB values or hex color code. (default None)

        Returns
        -------
        str
            Colorified `msg`.
        """
        if color is None:
            return msg
        elif isinstance(color, str):
            return Color.ansi(msg, color)
        elif isinstance(color, RGB):
            return Color.rgb(msg, color)
        elif isinstance(color, Hex):
            return Color.hex(msg, color)

    @staticmethod
    def ansi(msg: str, color_or_colors: str, /) -> str:
        """
        Color a message using ANSI color.

        Parameters
        ----------
        msg : str
            String to be colored.

        color_or_colors : str
            Color name or names.

        Returns
        -------
        str
            Colorified `msg`.
        """
        if not supports_colors() or not len(color_or_colors):
            return msg

        colors = Color.ANSI_COLORS
        text = [colors[color]
                for color in color_or_colors.split() if color in colors]

        text.append(str(msg))
        text.append(colors["normal"])

        return "".join(text)

    @staticmethod
    def rgb(msg: str, color: RGB, background: RGB | None = None, /) -> str:
        """
        Color a message using RGB values.

        Parameters
        ----------
        msg : str
            String to be colored.

        color : RGB
            Tuple containing RGB values.

        background : RGB | None
            Background color to apply. (default None)

        Returns
        -------
        str
            Colorified `msg`.
        """
        if not supports_true_color():
            return msg

        r, g, b = color.r, color.g, color.b
        bold_prefix = "1;" if color.bold else ""

        if background is not None:
            bg_r, bg_g, bg_b = background.r, background.g, background.b
            return f"\x1b[{bold_prefix}38;2;{r};{g};{b};48;2;{bg_r};{bg_g};{bg_b}m{msg}\x1b[0m"

        return f"\x1b[{bold_prefix}38;2;{r};{g};{b}m{msg}\x1b[0m"

    @staticmethod
    def hex(msg: str, color: Hex, background: Hex | None = None, /) -> str:
        """
        Color a message using hex codes.

        Parameters
        ----------
        msg : str
            String to be colored.

        color : Hex
            Hex color code.

        background : Hex | None
            Background color to apply. (default None)

        Returns
        -------
        str
            Colorified `msg`.
        """
        value = color.value

        if "#" in value:
            value = value.lstrip("#")

        if (len(value) > 6
                or len(value) < 6
                or any(char not in string.hexdigits for char in value)
                or not supports_true_color()):
            return msg

        r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
        bold_prefix = "1;" if color.bold else ""

        if background is not None:
            bg_value = background.value.lstrip("#")
            bg_r, bg_g, bg_b = (int(bg_value[i:i + 2], 16) for i in (0, 2, 4))
            return f"\x1b[{bold_prefix}38;2;{r};{g};{b};48;2;{bg_r};{bg_g};{bg_b}m{msg}\x1b[0m"

        return f"\x1b[{bold_prefix}38;2;{r};{g};{b}m{msg}\x1b[0m"
