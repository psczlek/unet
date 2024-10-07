from enum import Enum, unique

__all__ = ["ExitCode"]


@unique
class ExitCode(Enum):
    SUCCESS = 0
    FAILURE = 1
