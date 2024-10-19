"""
Config file reader.
"""


import json
from pathlib import Path
from typing import Any

from unet.coloring import Color
from unet.printing import eprint

__all__ = ["ConfReader"]


class ConfReader:
    """
    Config file reader.
    """

    def __init__(self, file: str, /) -> None:
        self._file = Path(file).expanduser().resolve()
        if not self._file.exists():
            eprint(f"supplied config path does not exist: {self._file}",
                   precedence="error: confreader:")

        self._data: dict[str, Any] = {}

    def read(self) -> dict[str, Any]:
        """
        Read the contents of the config file.

        Returns
        -------
        dict[str, Any]
            The contents of the config file.
        """
        with self._file.open("r") as f:
            self._data = json.load(f)
            return self._data

    def print(self) -> None:
        """
        Print the contents of the config file.

        Returns
        -------
        None
        """

        def json_print(data: dict[str, Any], indent: int = 0) -> None:
            indent_str = " " * indent

            if isinstance(data, dict):
                if len(data) == 0:
                    print(f"{indent_str}{{}}")

                for key, value in data.items():
                    key_colored = Color.color(key, "cyan")
                    if isinstance(value, (dict, list)):
                        print(f"{indent_str}{key_colored}:")
                        json_print(value, indent + 2)
                    else:
                        value_colored = Color.color(value, "green")
                        print(f"{indent_str}{key_colored}: {value_colored}")
            elif isinstance(data, list):
                if len(data) == 0:
                    print(f"{indent_str}* none")

                for item in data:
                    if isinstance(item, (dict, list)):
                        print(f"{indent_str}-")
                        json_print(item, indent + 2)
                    else:
                        item_colored = Color.color(item, "green")
                        print(f"{indent_str}- {item_colored}")
            else:
                value_colored = Color.color(data, "green")
                print(f"{indent_str}{value_colored}")

        print(f"path: {Color.blue(str(self._file))}", end="\n\n")
        json_print(self._data)
