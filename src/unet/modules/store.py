"""
Simple package manager for unet.
"""


import json
import shutil
from pathlib import Path
from typing import Final

from unet.coloring import Color
from unet.confreader import ConfReader
from unet.printing import Assets, eprint, wprint
from unet.flag import FlagParser, OptionFlag, PositionalFlag

try:
    from git import GitCommandError, Repo
except ModuleNotFoundError:
    wprint("store will not be available unless you install 'GitPython'\n"
           "\n         pip install GitPython"
           "\n         pip3 install GitPython")

__all__ = ["Store"]


class Store:
    """
    Simple package manager for unet.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path).expanduser().resolve()
        # ensure the repository directory exists
        self._path.mkdir(parents=True, exist_ok=True)
        # define the path to the JSON file
        self._module_list_file = self._path / "modules.json"
        # initialize the JSON file if it doesn't exist
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
            # extract the repository name from the URL
            module_name = Path(which).stem
            # define the path for the repository folder
            module_path = self._path / module_name
            # clone the repository into the separate folder
            Repo.clone_from(which, module_path)
            print(f"repository cloned to {module_path}")
            # add the repository name and URL to the JSON file
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
                        print(f"repository '{repo_name}' removed from {repo_path}")
                    else:
                        print(f"repository '{repo_name}' does not exist locally")
                    # Remove from the JSON file
                    del data[repo_name]
                    file.seek(0)
                    file.truncate()
                    json.dump(data, file, indent=4)
                    print(f"repository '{repo_name}' removed from {self._module_list_file}")
                else:
                    print(f"repository '{which}' not found in the list")
        except Exception as e:
            eprint(f"an error occurred: {e}")

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
                        print(f"repository '{repo_name}' updated")
                    else:
                        print(f"repository '{repo_name}' does not exist locally")
                else:
                    print(f"repository '{which}' not found in the list")
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
                print("repositories with available updates:")
                for name, url in updates.items():
                    print(f"{name}: {url}")
            else:
                print("all repositories are up to date")
        except Exception as e:
            eprint(f"an error occurred: {e}")

    def lists(self) -> None:
        """
        Show locally installed modules.

        Returns
        -------
        None
        """
        max_x = shutil.get_terminal_size().columns
        border_top = Color.gray(Assets.HORIZONTAL_LINE * 2
                                + Assets.TOP_T_INTERSECTION
                                + Assets.HORIZONTAL_LINE * (max_x - 3))
        border_middle = Color.gray(Assets.HORIZONTAL_LINE * 2
                                   + Assets.CROSS
                                   + Assets.HORIZONTAL_LINE * (max_x - 3))
        vline = Color.gray(Assets.VERTICAL_LINE)
        border_bottom = Color.gray(Assets.HORIZONTAL_LINE * 2
                                   + Assets.BOTTOM_T_INTERSECTION
                                   + Assets.HORIZONTAL_LINE * (max_x - 3))
        str_path = str(self._module_list_file.parent)

        def path_print(path: str) -> None:
            fmt = f"{border_top}\n  {vline} path: {Color.blue(path)}\n{border_middle}"
            print(fmt)

        def line_print(key: str, value: str) -> None:
            fmt = f"  {vline} {Color.cyan(key)}: {Color.yellow(value)}"
            print(fmt)

        try:
            with open(self._module_list_file, "r") as file:
                data = json.load(file)
                if data:
                    path_print(str_path)
                    for name, url in data.items():
                        line_print(name, url)
                    print(border_bottom)
                else:
                    print("no repositories are currently installed")
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
    "list": OptionFlag(
        short="-l",
        help="list all modules",
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
        prog="store",
        description="simple pakage manager for unet",
    )
    parser.add_arguments(STORE_FLAGS)
    flags = parser.parse_args(args)

    cr = ConfReader("~/.config/unet/config.json")
    conf_data = cr.read()
    fetched_path = Path(conf_data["modules"]["fetched"]).expanduser().resolve()
    # print(fetched_path)
    store = Store(fetched_path)

    
    if flags.fetch:
        store.fetch(flags.fetch)
    if flags.remove:
        store.remove(flags.remove)
    if flags.update:
        store.update(flags.update)
    if flags.list:
        store.lists()
    if flags.peek_for_update:
        store.peek_for_updates()
