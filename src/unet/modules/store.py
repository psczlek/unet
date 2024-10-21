"""
Simple package manager for unet.
"""


import json
import shutil
from pathlib import Path
from typing import Final

from unet.coloring import Color
from unet.confreader import ConfReader
from unet.flag import FlagParser, OptionFlag
from unet.printing import Assets, eprint, wprint

try:
    from git import GitCommandError, Repo
except ModuleNotFoundError:
    wprint("store will not be available unless you install 'GitPython'\n"
           "\n         pip install GitPython"
           "\n         pip3 install GitPython")

__all__ = ["Store", "fetch_list"]


def _print_status(msg: str, end: str = "\n") -> None:
    prefix = f"{Color.blue('unet')}: {Color.cyan('store')}:"
    line = f"{prefix} {msg}"
    print(line, end=end)


_MAX_X = shutil.get_terminal_size().columns
_BORDER_TOP = Color.gray(
    Assets.HORIZONTAL_LINE * 2
    + Assets.TOP_T_INTERSECTION
    + Assets.HORIZONTAL_LINE * (_MAX_X - 3)
)
_BORDER_MIDDLE = Color.gray(
    Assets.HORIZONTAL_LINE * 2
    + Assets.CROSS
    + Assets.HORIZONTAL_LINE * (_MAX_X - 3)
)
_EDGE_SEP = Color.gray(Assets.VERTICAL_LINE)
_BORDER_BOTTOM = Color.gray(
    Assets.HORIZONTAL_LINE * 2
    + Assets.BOTTOM_T_INTERSECTION
    + Assets.HORIZONTAL_LINE * (_MAX_X - 3)
)


def _path_print(path: str) -> None:
    fmt = f"{_BORDER_TOP}\n  {_EDGE_SEP} path: {Color.blue(path)}\n{_BORDER_MIDDLE}"
    print(fmt)


def _line_print(index: int, key: str, value: str) -> None:
    fmt = f"  {_EDGE_SEP} {Color.red(str(index))} {_EDGE_SEP} {Color.cyan(key)}: {Color.yellow(value)}"
    print(fmt)


def fetch_list() -> None:
    cr = ConfReader("~/.config/unet/config.json")
    conf_data = cr.read()
    which = conf_data["modules"]["public"]["url"]
    fetched_path = Path(conf_data["modules"]["public"]["list"]).expanduser().resolve()

    try:
        # Clone the repository into the separate folder
        Repo.clone_from(which, fetched_path)
    except Exception as e:
        eprint(f"an error occurred: {e}")


class Store:
    """
    Simple package manager for unet.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path).expanduser().resolve()

        # Ensure the repository directory exists
        self._path.mkdir(parents=True, exist_ok=True)

        # Define the path to the JSON file
        self._module_list_file = self._path / "modules.json"

        # Initialize the JSON file if it doesn't exist
        if not self._module_list_file.exists():
            with open(self._module_list_file, "w") as file:
                json.dump({}, file)

    def fetch(self, which: str, /) -> None:
        """
        Fetch a module.

        Parameters
        ----------
        which : str
            A valid git url for the module to be fetched.

        Returns
        -------
        None
        """
        try:
            # Extract the repository name from the URL
            module_name = Path(which).stem
            # Define the path for the repository folder
            module_path = self._path / module_name

            # Clone the repository into the separate folder
            Repo.clone_from(which, module_path)
            _print_status(f"repository cloned to {module_path}")

            # Add the repository name and URL to the JSON file
            with open(self._module_list_file, "r+") as file:
                data = json.load(file)
                data[module_name] = which

                file.seek(0)
                json.dump(data, file, indent=4)

            print(f"repository '{module_name}' added to {self._module_list_file}")
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def remove(self, which: str, /) -> None:
        """
        Remove a module.

        Parameters
        ----------
        which : str
            Name of a module to be removed.

        Returns
        -------
        None
        """
        try:
            with open(self._module_list_file, "r+") as file:
                data = json.load(file)

                if which in data:
                    repo_name = which
                    repo_path = self._path / repo_name

                    if repo_path.exists() and repo_path.is_dir():
                        shutil.rmtree(repo_path)
                        _print_status(f"repository '{repo_name}' removed from {repo_path}")
                    else:
                        _print_status(f"repository '{repo_name}' does not exist locally")

                    # Remove from the JSON file
                    del data[repo_name]

                    file.seek(0)
                    file.truncate()
                    json.dump(data, file, indent=4)

                    _print_status(f"repository '{repo_name}' removed from {self._module_list_file}")
                else:
                    _print_status(f"repository '{which}' not found in the list")
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def install(self, which: str, /) -> None:
        """
        Install a module from public list.

        Parameters
        ----------
        which : str
            Name of a module to install.

        Returns
        -------
        None
        """
        cr = ConfReader("~/.config/unet/config.json")
        conf_data = cr.read()
        ext_mod_list_path = Path(conf_data["modules"]["public"]["list"]).expanduser().resolve()
        ext_mod_list = ext_mod_list_path / "modules.json"
        matched_modules = {}

        try:
            with open(ext_mod_list, "r") as file:
                data = json.load(file)

                if data:
                    for key, value in data.items():
                        if which in key or key in which:
                            matched_modules[key] = value
                else:
                    _print_status("no repositories are currently installed")
        except KeyboardInterrupt:
            return
        except Exception as e:
            eprint(f"an error occurred: {e}")

        if len(matched_modules) > 1:
            print(_BORDER_BOTTOM)
            for index, item in enumerate(matched_modules.items(), start=1):
                _line_print(index, item[0], item[1])
            print(_BORDER_BOTTOM)
            mod_index = int(input('  Index of a module to install\n  '))
            print(f"  {_EDGE_SEP} INSTALLING...")
            print(_BORDER_BOTTOM)
            _line_print(1, list(matched_modules)[mod_index - 1],
                        matched_modules.get(list(matched_modules)[mod_index - 1]))
            print(_BORDER_BOTTOM)
            self.fetch(matched_modules.get(list(matched_modules)[mod_index - 1]))

        elif len(matched_modules) == 1:
            print(f"  {_EDGE_SEP} INSTALLING...")
            print(_BORDER_BOTTOM)
            _line_print(1, list(matched_modules)[0],
                        matched_modules.get(list(matched_modules)[0]))
            print(_BORDER_BOTTOM)
            self.fetch(matched_modules.get(list(matched_modules)[0]))
        else:
            _print_status("No modules corresponds, try again")

    def find(self, which: str, /) -> None:
        """
        Find a module from public list.

        Parameters
        ----------
        which : str
            Name of a module to find.

        Returns
        -------
        None
        """
        cr = ConfReader("~/.config/unet/config.json")
        conf_data = cr.read()
        ext_mod_list_path = Path(conf_data["modules"]["public"]["list"]).expanduser().resolve()
        ext_mod_list = ext_mod_list_path / "modules.json"
        matched_modules = {}

        try:
            with open(ext_mod_list, "r") as file:
                data = json.load(file)

                if data:
                    for key, value in data.items():
                        if which in key or key in which:
                            matched_modules[key] = value
                else:
                    _print_status("no repositories are currently installed")
        except KeyboardInterrupt:
            return
        except Exception as e:
            eprint(f"an error occurred: {e}")

        if matched_modules:
            _path_print(str(ext_mod_list_path))
            for index, item in enumerate(matched_modules.items(), start=1):
                _line_print(index, item[0], item[1])
            print(_BORDER_BOTTOM)
        else:
            _print_status("No matched modules")

    def update(self, which: str, /) -> None:
        """
        Update a module.

        Parameters
        ----------
        which : str
            Name of a module to be updated.

        Returns
        -------
        None
        """
        try:
            with open(self._module_list_file, "r") as file:
                data = json.load(file)

                if which in data:
                    repo_name = which
                    repo_path = self._path / repo_name

                    if repo_path.exists() and repo_path.is_dir():
                        repo = Repo(repo_path)
                        repo.remote().pull()

                        _print_status(f"repository '{repo_name}' updated")
                    else:
                        _print_status(f"repository '{repo_name}' does not exist locally")
                else:
                    _print_status(f"repository '{which}' not found in the list")
        except GitCommandError as e:
            eprint(f"an error occurred while updating: {e}")
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def peek_for_updates(self) -> None:
        """
        Check if locally installed modules are updatable.

        Returns
        -------
        None
        """
        try:
            updates = {}

            with open(self._module_list_file, "r") as file:
                data = json.load(file)

                for repo_name in data:
                    repo_path = self._path / repo_name
                    if repo_path.exists() and repo_path.is_dir():
                        repo = Repo(repo_path)
                        commits_behind = list(repo.iter_commits("master..origin/master"))

                        if commits_behind:
                            updates[repo_name] = data[repo_name]

            if updates:
                _print_status("repositories with available updates:")
                for name, url in updates.items():
                    name = Color.blue(name)
                    url = Color.yellow(url)

                    print(f"  {name}: {url}")
            else:
                _print_status("all repositories are up to date")
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def lists(self) -> None:
        """
        Show locally installed modules.

        Returns
        -------
        None
        """
        str_path = str(self._module_list_file.parent)

        def path_print(path: str) -> None:
            fmt = f"{_BORDER_TOP}\n  {_EDGE_SEP} path: {Color.blue(path)}\n{_BORDER_MIDDLE}"
            print(fmt)

        def line_print(key: str, value: str) -> None:
            fmt = f"  {_EDGE_SEP} {Color.cyan(key)}: {Color.yellow(value)}"
            print(fmt)

        try:
            with open(self._module_list_file, "r") as file:
                data = json.load(file)
                if data:
                    path_print(str_path)
                    for name, url in data.items():
                        line_print(name, url)
                    print(_BORDER_BOTTOM)
                else:
                    _print_status("no repositories are currently installed")
        except KeyboardInterrupt:
            return
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def list_public(self) -> None:
        """
        Find a module from public list.

        Parameters
        ----------
        which : str
            Name of a module to find.

        Returns
        -------
        None
        """
        cr = ConfReader("~/.config/unet/config.json")
        conf_data = cr.read()
        ext_mod_list_path = Path(conf_data["modules"]["public"]["list"]).expanduser().resolve()
        ext_mod_list = ext_mod_list_path / "modules.json"

        repo = Repo(ext_mod_list_path)
        repo.remote().pull()
        _print_status(f"Extended modules list updated")

        try:
            with open(ext_mod_list, "r") as file:
                data = json.load(file)
                if data:
                    _path_print(str(ext_mod_list_path))
                    for index, item in enumerate(data.items(), start=1):
                        _line_print(index, item[0], item[1])
                    print(_BORDER_BOTTOM)
                else:
                    _print_status("no repositories are currently installed")
        except KeyboardInterrupt:
            return
        except Exception as e:
            eprint(f"an error occurred: {e}")


STORE_FLAGS: Final = {
    "fetch": OptionFlag(
        short="-f",
        help="fetch module",
        type=str,
        required=False,
        default=None,
        metavar="<link>"
    ),
    "install": OptionFlag(
        short="-i",
        help="install public module",
        type=str,
        required=False,
        default=None,
        metavar="<rep_name>"
    ),
    "remove": OptionFlag(
        short="-r",
        help="remove module",
        type=str,
        required=False,
        default=None,
        metavar="<rep_name>"
    ),
    "update": OptionFlag(
        short="-u",
        help="update module",
        type=str,
        required=False,
        default=None,
        metavar="<rep_name>"
    ),
    "find": OptionFlag(
        short="-F",
        help="find public module",
        type=str,
        required=False,
        default="",
        metavar="<rep_name>"
    ),
    "list": OptionFlag(
        short="-l",
        help="list all modules",
        action="store_true",
        required=False,
        default=False,
    ),
    "list_public": OptionFlag(
        short="-L",
        help="list all public modules",
        action="store_true",
        required=False,
        default=False,
    ),
    "peek_for_update": OptionFlag(
        short="-U",
        help="check if installed modules are updatable",
        action="store_true",
        required=False,
        default=False,
    ),
}


def main(args: list[str]) -> None:
    parser = FlagParser(
        prog="store", description="simple package manager for unet")
    parser.add_arguments(STORE_FLAGS)
    flags = parser.parse_args(args)

    cr = ConfReader("~/.config/unet/config.json")
    conf_data = cr.read()
    fetched_path = Path(conf_data["modules"]["fetched"]["path"]).expanduser().resolve()
    store = Store(str(fetched_path))

    action_map = {
        flags.fetch: (store.fetch, True),
        flags.remove: (store.remove, True),
        flags.update: (store.update, True),
        flags.list_public: (store.list_public, False),
        flags.find: (store.find, True),
        flags.install: (store.install, True),
        flags.list: (store.lists, False),
        flags.peek_for_update: (store.peek_for_updates, False),
    }

    for action, ca_tup in action_map.items():
        if action:
            callback = ca_tup[0]
            has_arg = ca_tup[1]

            if has_arg:
                callback(action)
            else:
                callback()

            return
