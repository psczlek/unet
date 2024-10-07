"""
Load modules at runtime.
"""


import importlib.util
import inspect
import sys
from pathlib import Path
from types import ModuleType

__all__ = [
    "lookup_symbol",
    "lookup_signature",
    "is_package",
    "load_module",
    "ModuleLoader",
]


sys.dont_write_bytecode = True


def lookup_symbol(module: ModuleType, symbol_name: str) -> bool:
    """
    Check if a symbol in a module matches the expected signature.

    Parameters
    ----------
    module : ModuleType
        Module to look up the symbol in.
    symbol_name : str
        Name of the symbol to check.
    signature : str
        Expected signature of the symbol.

    Returns
    -------
    bool
        True if the symbol exists and its signature matches, False otherwise.
    """
    return hasattr(module, symbol_name)


def lookup_signature(
        module: ModuleType,
        symbol_name: str,
        signature: str,
) -> bool:
    """
    Check if a symbol in a module matches the expected signature.

    Parameters
    ----------
    module : ModuleType
        Module to look up the symbol in.
    symbol_name : str
        Name of the symbol to check.
    signature : str
        Expected signature of the symbol.

    Returns
    -------
    bool
        True if the symbol exists and its signature matches, False otherwise.
    """
    if lookup_symbol(module, symbol_name):
        symbol = getattr(module, symbol_name)
        sig = inspect.signature(symbol)
        return str(sig) == signature
    return False


def get_signature(module: ModuleType, symbol_name: str) -> str | None:
    """
    Retrieve the signature of a symbol from a module.

    Parameters
    ----------
    module : ModuleType
        Module to look up the symbol in.
    symbol_name : str
        Name of the symbol to retrieve the signature for.

    Returns
    -------
    str | None
        The signature of the symbol as a string, or None if the symbol doesn't exist.
    """
    if lookup_symbol(module, symbol_name):
        symbol = getattr(module, symbol_name)
        sig = inspect.signature(symbol)
        return str(sig)
    return None


def is_package(module: ModuleType) -> bool:
    # `__path__` attribute is only present when a module is a package
    #
    # from docs: (https://docs.python.org/3/reference/import.html)
    #   A package is a module with a __path__ attribute ...
    return hasattr(module, "__path__")


def load_module(source: str, module_name: str) -> ModuleType | None:
    """
    Load a module and return a handle to it using create_module.

    Parameters
    ----------
    source : str
        Path to a Python file.

    module_name : str
        Name to assign the loaded module.

    Returns
    -------
    ModuleType | None
        Handle to the loaded module, or None on failure.
    """
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        return None

    # Create the module from the spec
    module = importlib.util.module_from_spec(spec)

    # Add the module to sys.modules
    sys.modules[module_name] = module

    # Execute the module code using exec_module
    spec.loader.exec_module(module)

    return module


class ModuleLoader:
    """
    Load modules at runtime.
    """

    def __init__(
            self,
            path_or_paths: str | list[str] | None = None,
            /,
    ) -> None:
        self._loaded: list[str] = []
        self._failed: list[str] = []
        self._handles: dict[str, ModuleType] = {}
        # TODO: make that work with any interable
        self._path_or_paths = path_or_paths

    def load(
            self,
            path_or_paths: str | list[str] | None = None,
            /,
    ) -> None:
        """
        Loads modules from the specified path(s).

        Parameters
        ----------
        path_or_paths : str | list[str] | None, optional
            A path or list of paths to Python files. If not provided, uses the
            path(s) given during class initialization.

        Raises
        ------
        ValueError
            If no valid source for a module is provided.
        """
        if path_or_paths is not None and self._path_or_paths is not None:
            # Prioritize path(s) supplied to this function
            source = path_or_paths
        else:
            source = self._path_or_paths or path_or_paths

        if source is None:
            raise ValueError("No source for a module provided")

        if isinstance(source, str):
            source = [source]

        for path_str in source:
            path = Path(path_str).expanduser().resolve()
            self._process_path(path)

    def _process_path(self, path: Path, /) -> None:
        if path.is_file() and path.suffix == ".py":
            handle = load_module(str(path), path.stem)
            if handle is not None:
                self._handles[path.stem] = handle
                self._loaded.append(path.stem)
            else:
                self._failed.append(path.stem)
        elif path.is_dir():
            for item in path.iterdir():
                item = item.expanduser().resolve()
                self._process_path(item)
        else:
            # Neither a python file nor a directory, skip
            return None

    @property
    def handles(self) -> dict[str, ModuleType]:
        """
        Handles to modules that have been loaded.
        """
        return self._handles

    @property
    def loaded(self) -> list[str]:
        """
        Names of modules that have been successfully loaded.
        """
        return self._loaded

    @property
    def failed(self) -> list[str]:
        """
        Names of modules that have failed loading.
        """
        return self._failed
