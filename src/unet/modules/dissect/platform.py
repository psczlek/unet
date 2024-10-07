import sys

__all__ = ["LINUX", "DARWIN", "OPENBSD", "FREEBSD", "NETBSD"]


LINUX = sys.platform.startswith("linux")
DARWIN = sys.platform.startswith("darwin")
OPENBSD = sys.platform.startswith("openbsd")
FREEBSD = sys.platform.startswith("freebsd")
NETBSD = sys.platform.startswith("netbsd")
