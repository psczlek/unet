from unet.configure import configure, is_configured

if not is_configured():
    configure()

import platform
import sys
from pathlib import Path


def unet_entry() -> None:
    supported_platforms = ["Linux", "Darwin"]
    current_platform = platform.system()
    if current_platform not in supported_platforms:
        from unet.printing import eprint
        eprint(f"unet has not been tested on '{current_platform}'")

    python_version = sys.version.split()[0]
    if sys.version_info < (3, 12):
        from unet.printing import eprint
        eprint(f"unet requires python 3.12+, used version {python_version}")

    sys.path.append(str(Path().parent.absolute()))

    from unet.main import main
    main(sys.argv[1:])


if __name__ == "__main__":
    unet_entry()
