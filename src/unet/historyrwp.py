"""
Read, write, print the contents of the history file.
"""


import datetime
import shutil
from pathlib import Path
from types import TracebackType
from typing import Literal, Type

from unet.coloring import Color
from unet.printing import Assets

__all__ = ["HistoryRWP"]


class HistoryRWP:
    """
    Read, write, print the contents of the history file.
    """

    def __init__(
            self,
            file: str,
            mode: Literal["read", "write"],
            /,
    ) -> None:
        self._fpath = Path(file).expanduser().resolve()
        self._mode = ""

        if not self._fpath.exists():
            self._fpath.touch(mode=0o664, exist_ok=True)
            self._mode = "rb" if mode == "read" else "a"
        elif self._fpath.exists() and mode == "write":
            self._mode = "a"
        else:
            self._mode = "rb" if mode == "read" else "a"

        self._fd = self._fpath.open(self._mode)

    def __enter__(self) -> "HistoryRWP":
        return self

    def __exit__(
            self,
            exc_type: Type[BaseException] | None = None,
            exc_val: BaseException | None = None,
            exc_tb: TracebackType | None = None,
    ) -> None:
        self._fd.close()

    def read(self, buf: bytearray, size: int, /) -> int:
        """
        Read the contents of the history file into the supplied buffer.

        Parameters
        ----------
        buf : bytearray
            Buffer into which the contents will be read.

        size : int
            Number of bytes to read.

        Returns
        -------
        int
            The number of bytes read.
        """
        if self._mode != "rb":
            return 0

        if size < 0:
            return -1

        bytes_read = 0

        try:
            while size > 0:
                chunk = self._fd.read(min(size, 1024))

                if not chunk:
                    break

                buf.extend(chunk)
                bytes_read += len(chunk)
                size -= len(chunk)
        except KeyboardInterrupt:
            self._fd.close()

        return bytes_read

    def write(self, msg: str, /) -> int:
        """
        Write a message into the history file.

        Parameters
        ----------
        msg:
            Message to write.

        Returns
        -------
        int
            The number of bytes written.
        """
        if self._mode == "rb":
            return 0

        datefmt = datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S.%f")
        fmt = f"[{datefmt}]: {msg}\n"

        return self._fd.write(fmt)

    def print(self) -> None:
        """
        Read the history file and print its contents.

        Returns
        -------
        None
        """
        if self._mode != "rb":
            return

        lines = []

        fsize = self._fpath.stat().st_size
        max_x = shutil.get_terminal_size().columns - 1

        top_sep = Assets.HORIZONTAL_LINE * max_x
        top_sep = Color.gray(
            f"{top_sep[:2]}{Assets.TOP_T_INTERSECTION}{top_sep[2:]}")

        middle_sep = Assets.HORIZONTAL_LINE * max_x
        middle_sep = Color.gray(
            f"{middle_sep[:2]}{Assets.CROSS}{middle_sep[2:]}")

        bottom_sep = Assets.HORIZONTAL_LINE * max_x
        bottom_sep = Color.gray(
            f"{bottom_sep[:2]}{Assets.BOTTOM_T_INTERSECTION}{bottom_sep[2:]}")

        edge_sep = Color.gray(Assets.VERTICAL_LINE)

        try:
            str_path = Color.blue(str(self._fpath))
            path_line = f"{top_sep}  {edge_sep} path: {str_path}\n{middle_sep}"
            lines.append(path_line)

            while fsize > 0:
                line = self._fd.readline()

                time = Color.yellow(line.decode().split(": ")[0])
                message = Color.green(line.decode().split(": ")[1].strip("\n"))

                lines.append(f"  {edge_sep} {time}: {message}")

                fsize -= len(line)

            lines.append(bottom_sep)
            print("\n".join(lines))
        except KeyboardInterrupt:
            self._fd.close()
