"""Kintsugi desktop app entry point:  python main.py"""
import sys

from PySide6.QtWidgets import QApplication

from gui import theme
from gui.main_window import MainWindow


def main() -> int:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Kintsugi.Desktop")
    app = QApplication(sys.argv)
    app.setApplicationName("Kintsugi")
    theme.apply(app)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
