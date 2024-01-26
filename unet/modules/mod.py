from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional


class ExitCode(Enum):
    SUCCESS = 0
    FAILURE = 1


class Module(ABC):
    @abstractmethod
    def __init__(self) -> None: ...

    @abstractmethod
    def main(self) -> Optional[ExitCode]: ...

    @abstractmethod
    def help(self) -> None: ...
