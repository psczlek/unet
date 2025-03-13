import stat
from pathlib import Path

import pytest

from unet.configure import configure


def _rm(path: str) -> None:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return
    if p.exists() and p.is_dir():
        for item in p.iterdir():
            if item.is_dir():
                _rm(str(item))
            else:
                item.unlink()
        p.rmdir()


@pytest.mark.parametrize("dest_dir", [
    "./unet_config",
    "./config",
    "./unetcfg",
    "./unetconfig",
])
def test_configure(dest_dir: str) -> None:
    configure(dest_dir=dest_dir)
    assert Path(dest_dir).expanduser().resolve().exists()

    paths = [
        f"{dest_dir}/config.json",
        f"{dest_dir}/modules/",
        f"{dest_dir}/modules/fetched/",
    ]
    for path in paths:
        assert (Path(path).expanduser().resolve().exists()
                and stat.S_IMODE(Path(path).expanduser().resolve().stat().st_mode) in [0o644, 0o755])

    assert Path(f"{dest_dir}/.unetcfgok").expanduser().resolve().exists()

    _rm(dest_dir)
    assert not Path(dest_dir).expanduser().resolve().exists()
