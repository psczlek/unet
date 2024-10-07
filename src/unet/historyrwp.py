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

        datefmt = datetime.datetime.today().strftime("%Y-%m-%d %I:%M:%S.%f %p")
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

        fsize = self._fpath.stat().st_size
        max_x = shutil.get_terminal_size().columns
        horizontal_line = Color.gray(Assets.HORIZONTAL_LINE) * max_x
        vertical_line = Color.gray(Assets.VERTICAL_LINE)
        str_path = str(self._fpath)

        try:
            print(f"{horizontal_line}\n"
                  f"  {vertical_line} path: {Color.blue(str_path)}\n"
                  f"{horizontal_line}")

            while fsize > 0:
                line = self._fd.readline()
                msg = line.decode().split(": ")
                print(f"  {vertical_line} {Color.yellow(msg[0])}: {Color.green(msg[1])}",
                      end="")
                fsize -= len(line)

            print(horizontal_line)
        except KeyboardInterrupt:
            self._fd.close()
