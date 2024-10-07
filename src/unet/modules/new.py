"""
Create a new blank unet module.
"""


from pathlib import Path

from unet.coloring import Color
from unet.flag import FlagParser
from unet.printing import eprint

__all__ = ["main"]


def _error(message: str) -> None:
    precedence = (f"{Color.red(Color.bold('error'))}: "
                  f"{Color.red(Color.bold('new'))}")
    eprint(message, precedence=precedence)


def _dump_template(name: str, path: str) -> None:
    dst_dir = Path(path).expanduser().resolve()
    if not dst_dir.exists():
        _error(f"destination directory '{str(dst_dir)}' does not exist")

    template = f"""\"\"\"
{name} lacks documentation.
\"\"\"


from unet.flag import FlagParser

__all__ = ["main"]


def main(args: list[str]) -> None:
    parser = FlagParser(prog="{name}", description="this module lacks documentation")
"""

    dst_dir = dst_dir / (name + ".py")
    if dst_dir.exists():
        _error(f"module '{name}' already exists")

    with dst_dir.open("w") as f:
        f.write(template)


def main(args: list[str]) -> None:
    parser = FlagParser(prog="new", description="create a new blank unet module")

    parser.add_argument("-n", "--name", type=str, required=True,
                        help="name of the new module to be created. This will "
                             "be the identifier used to reference the module.",
                        metavar="<name>")
    parser.add_argument("-p", "--path", type=str, required=True,
                        help="absolute or relative path where the new module "
                             "file should be saved. Ensure the directory exists "
                             "or has the required permissions.",
                        metavar="<path>")

    flags = parser.parse_args(args)
    _dump_template(flags.name, flags.path)

    output = (f"+ new module {Color.cyan(flags.name)} created in "
              f"{Color.light_yellow(flags.path)}")
    print(output)
