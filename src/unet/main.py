from pathlib import Path
from typing import Final

from unet.coloring import Color, disable_colors
from unet.confreader import ConfReader
from unet.flag import FlagParser
from unet.historyrwp import HistoryRWP
from unet.modloader import ModuleLoader, get_signature, lookup_symbol
from unet.printing import Assets, eprint

__all__ = ["main"]


_NAME: Final = "unet (dev)"
_VERSION: Final = "1.0.0"
_RELEASE_DATE: Final = "2024-10-08"


def _error(message: str) -> None:
    precedence = (f"{Color.red(Color.bold('error'))}: "
                  f"{Color.red(Color.bold('unet'))}")
    eprint(message, precedence=precedence)


def _usage() -> str:
    message = [
        "%s: %s <%s> <%s>" % (
            Color.color("usage", "blue"),
            Color.color("unet", "light_blue"),
            Color.color("tool name", "blue"),
            Color.color("options", "yellow"),
        ),
        "       %s <%s>" % (
            Color.color("unet", "light_blue"),
            Color.color("options", "yellow"),
        ),
        "\nrun '%s %s <%s>' for more information on a specific "
        "tool." % (
            Color.color("unet", "light_blue"),
            Color.color("help", "blue"),
            Color.color("tool name", "blue"),
        ),
        "run '%s %s' to list all available tools" % (
            Color.color("unet", "light_blue"),
            Color.color("--list-tools", "blue"),
        ),
        "run '%s %s' to quickly create a blank tool" % (
            Color.color("unet", "light_blue"),
            Color.color("new -n <name> -p <path>", "blue"),
        ),
    ]

    return "\n".join(message)


def main(args: list[str]) -> None:
    if len(args) == 0:
        usage = _usage()
        print(usage)
        return

    # Read the config file
    conf = ConfReader("~/.config/unet/config.json")
    conf_data = conf.read()

    if not conf_data["colors"]:
        disable_colors()

    # Check if history logging is enabled; if so, write the invoked command
    # to the file
    if conf_data["history"]:
        hist_file = Path(conf_data["history_file_path"]).expanduser().resolve()

        # Check if the history file exists
        if hist_file.exists():
            # Get the size of the file in bytes
            file_size = hist_file.stat().st_size

            if file_size >= 5 * 1024:
                hist_file.unlink()

        with HistoryRWP(str(hist_file), "write") as hist:
            invoked_command = "unet " + " ".join(args)
            hist.write(invoked_command)

    # Check for updates and fetch the latest version if needed
    if conf_data["auto_update"]:
        pass

    # Load modules
    to_load: set[Path] = set()
    built_in_modules_path = Path(__file__.strip("main.py")) / Path("modules")
    external_modules_path = Path(conf_data["modules"]["external"]["path"]).expanduser().resolve()
    fetched_modules_path = Path(conf_data["modules"]["fetched"]).expanduser().resolve()

    excluded = {"__init__.py", "__pycache__"}

    def add_modules_to_load(
            path: Path,
            to_load: set[Path],
            excluded: set[str],
    ) -> None:
        for mod in path.iterdir():
            if mod.is_file() and mod.suffix == ".py" and mod.name not in excluded:
                add_module(to_load, mod)
            elif mod.is_dir():
                package_file = mod / (mod.name + ".py")
                if package_file.exists():
                    add_module(to_load, package_file)
                else:
                    for file in mod.iterdir():
                        if file.is_file() and file.suffix == ".py":
                            add_module(to_load, file)

    def add_module(to_load: set[Path], new_module: Path) -> None:
        # Check if a module with the same name already exists
        existing_module = next((m for m in to_load if m.name == new_module.name),
                               None)
        if existing_module:
            # Remove the existing module
            to_load.remove(existing_module)
        # Add the new module
        to_load.add(new_module)

    try:
        add_modules_to_load(built_in_modules_path, to_load, excluded)
        add_modules_to_load(fetched_modules_path, to_load, excluded)
        add_modules_to_load(external_modules_path, to_load, excluded)
    except FileNotFoundError as e:
        _error(str(e))

    module_loader = ModuleLoader()
    module_loader.load([str(mod) for mod in to_load])

    module_handles = module_loader.handles
    disabled_modules = conf_data["modules"]["disabled"]

    for name in list(module_handles):
        has_main = lookup_symbol(module_handles[name], "main")
        # Remove module if it doesn't have the entry point
        if not has_main:
            module_handles.pop(name)
            continue

        main_signature = get_signature(module_handles[name], "main")
        valid_main_signatures = {
            "(args: list[str]) -> None",
            "(args: 'list[str]') -> 'None'",
            "(args: \"list[str]\") -> \"None\"",
        }
        # Remove module if the entry's point signature is invalid
        if main_signature not in valid_main_signatures:
            module_handles.pop(name)
            continue

        # Remove module if it's disabled
        if name in disabled_modules:
            module_handles.pop(name)

    parser = FlagParser(prog="unet", description="the unified network toolkit",
                        epilog=_usage())

    parser.add_argument(
        "tool",
        nargs="?",
        default=None,
        help="name of the tool to execute")
    parser.add_argument(
        "--version",
        action="version",
        version=f"{_NAME} {_VERSION} ({_RELEASE_DATE})")
    parser.add_argument(
        "--list-tools",
        action="store_true",
        default=False,
        help="show all available tools and exit",
        dest="lflag")
    parser.add_argument(
        "--show-history",
        action="store_true",
        default=False,
        help="show the contents of the history file and exit",
        dest="Hflag")
    parser.add_argument(
        "--show-config",
        action="store_true",
        default=False,
        help="show the contents of the config file and exit",
        dest="cflag")
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="disable colors if supported",
        dest="kflag")

    flags, remaining_args = parser.parse_known_args(args)

    if flags.kflag:
        disable_colors()

    if flags.tool == "help":
        if not len(remaining_args):
            parser.print_help()
            return

        try:
            module_handles[remaining_args[0]].main(["-h"])
            return
        except KeyError:
            _error(f"module '{remaining_args[0]}' does not exist, or was not loaded")

    if flags.lflag:
        mod_num = 1

        for name, handle in module_handles.items():
            num = Color.color(str(mod_num), "yellow")
            name = Color.color(name, "blue")
            sep = Color.color(Assets.RIGHTWARDS_ARROW, "light_gray")
            handle_path = Color.color(handle.__file__, "light_yellow")

            print(f"{num}. {name} {sep} from {handle_path}")

            mod_num += 1

        return

    if flags.Hflag:
        path = Path(conf_data["history_file_path"]).expanduser().resolve()

        with HistoryRWP(str(path), "read") as hist:
            hist.print()
            return

    if flags.cflag:
        conf.print()
        return

    if flags.tool is not None:
        # Execute requested module
        try:
            module_handles[flags.tool].main(remaining_args)
            return
        except KeyError:
            _error(f"module '{flags.tool}' does not exist, or was not loaded")
