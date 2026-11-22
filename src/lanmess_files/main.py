import sys

from .config import APP_NAME, APP_VERSION
from .tui import LanMessApp


def main():
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"{APP_NAME} {APP_VERSION}")
        return
    LanMessApp().run()


if __name__ == "__main__":
    main()