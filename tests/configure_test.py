from pathlib import Path

import pytest

import unet.configure as configure


def rm(path: str) -> None:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return
    if p.exists() and p.is_dir():
        for item in p.iterdir():
            if item.is_dir():
                rm(str(item))
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
    configure.configure(dest_dir=dest_dir)
    assert Path(dest_dir).expanduser().resolve().exists()
    paths = [
        f"{dest_dir}/unet/",
        f"{dest_dir}/unet/config.json",
        f"{dest_dir}/unet/modules/",
        f"{dest_dir}/unet/modules/fetched/",
    ]
    for path in paths:
        assert Path(path).expanduser().resolve().exists()
    assert Path(f"{dest_dir}/unet/.unetcfgok").expanduser().resolve().exists()
    rm(dest_dir)
    assert not Path(dest_dir).expanduser().resolve().exists()
