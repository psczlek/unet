"""
Read, write, print log files.
"""


import datetime
from multiprocessing import Pool
from pathlib import Path
from typing import Literal

from unet.coloring import Color
from unet.printing import Assets

__all__ = ["LogRWP"]


class LogRWP:
    """
    Read, write, print log files.
    """

    def __init__(self, path: str, mode: Literal["read", "write"], /) -> None:
        self._logdir_path = Path(path).expanduser().resolve()
        self._mode = mode

    def read(self, name: str, buf: bytearray, size: int, /) -> int:
        """
        Read the contents of a log file into the supplied buffer.

        Parameters
        ----------
        name : str
            File from which to read the contents.

        buf : bytearray
            Buffer into which the contents will be read.

        size : int
            Number of bytes to read.

        Returns
        -------
        int
            The number of bytes read.
        """
        if self._mode != "read":
            return 0

        if size < 0:
            return -1

        bytes_read = 0
        fpath = self._logdir_path / name

        if not fpath.is_file():
            return -1

        with fpath.open("r") as f:
            try:
                while size > 0:
                    chunk = f.read(min(size, 1024))

                    if not chunk:
                        break

                    buf.extend(chunk.encode())
                    bytes_read += len(chunk)
                    size -= len(chunk)
            except KeyboardInterrupt:
                f.close()

        return bytes_read

    def write(self, name: str, msg: str, /) -> int:
        """
        Write a message to a log file.

        Parameters
        ----------
        name : str
            File to which write a message.

        msg : str
            Message to write.

        Returns
        -------
        int
            The number of bytes written.
        """
        if self._mode != "write":
            return 0

        fpath = self._logdir_path / name

        if not fpath.is_file():
            return -1

        datefmt = datetime.datetime.today().strftime("%Y-%m-%d %I:%M:%S %p")
        fmt = f"[{datefmt}]: {msg}\n"

        with fpath.open("a+") as f:
            return f.write(fmt)

    def print(self, name: str, /) -> None:
        """
        Print the contents of a log file.

        Parameters
        ----------
        name : str
            Name of a log file to print.

        Returns
        -------
        None
        """
        if self._mode != "read":
            return

        fpath = self._logdir_path / name

        if not fpath.is_file():
            return

        fsize = fpath.stat().st_size

        with fpath.open("r") as f:
            try:
                while fsize > 0:
                    line = f.readline()
                    date, msg = line.split(": ")
                    print(f"{Color.yellow(date)}: {msg}", end="")
                    fsize -= len(line)
            except KeyboardInterrupt:
                f.close()

    def _pprint(self, name: str, /) -> None:
        print(f"{f' begin {name} ':{Assets.HORIZONTAL_LINE}^80}")
        self.print(name)
        print(f"{f' end {name} ':{Assets.HORIZONTAL_LINE}^80}")

    def print_all(self) -> None:
        """
        Print the contents of all log files.

        Returns
        -------
        None
        """
        if self._mode != "read":
            return

        to_print = []

        for f in self._logdir_path.iterdir():
            if not f.is_file():
                continue

            to_print.append(f.name)

        if not len(to_print):
            print("there's nothing to print")

        if len(to_print) == 1:
            self._pprint(to_print[0])
        else:
            with Pool() as pool:
                pool.map(self._pprint, to_print)
