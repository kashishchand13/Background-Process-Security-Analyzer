import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from bsa.config import Settings
from bsa.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Background Process Security Analyzer")
    app.setOrganizationName("Student Project")
    try:
        window = MainWindow(Settings())
        window.show()
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Startup error", str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
