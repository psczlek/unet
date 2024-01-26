class Color:
    """Colorify terminal output"""
    colors = {
        "normal" : "\x1b[0m",
        "gray" : "\x1b[1;38;5;240m",
        "light_gray" : "\x1b[0;37m",
        "red" : "\x1b[31m",
        "green" : "\x1b[32m",
        "yellow" : "\x1b[33m",
        "blue" : "\x1b[34m",
        "pink" : "\x1b[35m",
        "cyan" : "\x1b[36m",
        "bold" : "\x1b[1m",
   }

    @staticmethod
    def redify(msg: str) -> str:
        return Color.colorify(msg, "red")

    @staticmethod
    def greenify(msg: str) -> str:
        return Color.colorify(msg, "green")

    @staticmethod
    def blueify(msg: str) -> str:
        return Color.colorify(msg, "blue")

    @staticmethod
    def yellowify(msg: str) -> str:
        return Color.colorify(msg, "yellow")

    @staticmethod
    def grayify(msg: str) -> str:
        return Color.colorify(msg, "gray")

    @staticmethod
    def light_grayify(msg: str) -> str:
        return Color.colorify(msg, "light_gray")
        
    @staticmethod
    def pinkify(msg: str) -> str:
        return Color.colorify(msg, "pink")

    @staticmethod
    def cyanify(msg: str) -> str:
        return Color.colorify(msg, "cyan")

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        msg.append(colors["normal"])
        return "".join(msg)
