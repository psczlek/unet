from coloring import Color
from printing import eprintln, wprintln, iprintln


__name__ = "unet"
__version__ = "0.0.a1"


def main() -> None:
    print(f"{Color.cyanify(__name__)} version {Color.yellowify(__version__)}")


if __name__ == "__main__":
    main()
