import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

__all__ = ["configure", "is_configured"]


def is_configured() -> bool:
    return Path("~/.config/unet/.unetcfgok").expanduser().resolve().exists()


@dataclass(frozen=True)
class _PathSpec:
    path: str
    type: Literal["dir", "file"]


def configure(dest_dir: str | None = None) -> None:
    if dest_dir is None:
        dest_dir = "~/.config/unet"

    # Create the destination directory is it doesn't exist
    if not Path(dest_dir).expanduser().resolve().exists():
        Path(dest_dir).expanduser().resolve().mkdir(mode=0o777, exist_ok=True)

    # Directories/files to populate
    paths = [
        _PathSpec(f"{dest_dir}/", "dir"),
        _PathSpec(f"{dest_dir}/config.json", "file"),
        _PathSpec(f"{dest_dir}/modules/", "dir"),
        _PathSpec(f"{dest_dir}/modules/fetched/", "dir"),
        _PathSpec(f"{dest_dir}/modules/themes/", "dir"),
    ]

    # Default config data
    conf_data: Final = {
        "modules": {
            "external": {
                "path": "~/.config/unet/modules"
            },
            "fetched": "~/.config/unet/modules/fetched",
            "public-url": "https://github.com/theosfa/unet-ext-modules",
            "public-list": "~/.config/unet/modules/unet-ext-modules",
            "themes": {
                "path": "~/.config/unet/modules/themes",
                "theme": None
            },
            "disabled": []
        },
        "history": True,
        "history_file_path": "~/.config/unet/unet_history.txt",
        "auto_update": True,
        "colors": True
    }

    # Make directories
    for path in paths:
        if path.type == "dir":
            Path(path.path).expanduser().resolve().mkdir(mode=0o755, exist_ok=True)
        else:
            Path(path.path).expanduser().resolve().touch(mode=0o644, exist_ok=True)

    # Write config file
    with Path(f"{dest_dir}/config.json").expanduser().resolve().open("w") as f:
        json_object = json.dumps(conf_data, indent=2)
        f.write(json_object)

    Path(f"{dest_dir}/.unetcfgok").expanduser().resolve().touch(mode=0o644, exist_ok=True)
