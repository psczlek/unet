from unet.confreader import ConfReader


def test_confreader() -> None:
    conf_reader = ConfReader("~/.config/unet/config.json")
    conf_reader.read()
    conf_reader.print()
