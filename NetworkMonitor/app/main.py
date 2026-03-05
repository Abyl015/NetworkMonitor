import sys

from NetworkMonitor.core.engine import Engine
from NetworkMonitor.core.profile_manager import ProfileManager
from NetworkMonitor.reports.export import export_reports


class AppController:
    def __init__(self):
        self.engine = Engine()
        self.profile_manager = ProfileManager()

    @property
    def profiles(self) -> list[str]:
        return self.profile_manager.names()

    def apply_profile(self, profile_name: str) -> str:
        profile = self.profile_manager.set_active(profile_name)
        self.engine.apply_profile(profile)
        self.engine.reset_state()
        return f"[SYSTEM] Активный профиль: {profile.name}"

    def export_reports(self) -> tuple[str, str]:
        return export_reports(profile_manager=self.profile_manager, engine=self.engine)


def run_qt_app() -> int:
    from PyQt6.QtWidgets import (
        QApplication,
        QLabel,
        QComboBox,
        QMainWindow,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("NetworkMonitor")
            self.resize(800, 500)
            self.controller = AppController()

            root = QWidget()
            layout = QVBoxLayout(root)

            layout.addWidget(QLabel("Профиль мониторинга"))

            self.profile_combo = QComboBox()
            self.profile_combo.addItems(self.controller.profiles)
            layout.addWidget(self.profile_combo)

            self.apply_btn = QPushButton("Применить профиль")
            self.apply_btn.clicked.connect(self.apply_selected_profile)
            layout.addWidget(self.apply_btn)

            self.export_btn = QPushButton("Экспорт отчёта (CSV)")
            self.export_btn.clicked.connect(self.export_data)
            layout.addWidget(self.export_btn)

            self.log_area = QTextEdit()
            self.log_area.setReadOnly(True)
            layout.addWidget(self.log_area)

            self.setCentralWidget(root)
            self.apply_selected_profile()

        def apply_selected_profile(self):
            profile_name = self.profile_combo.currentText()
            message = self.controller.apply_profile(profile_name)
            self.log_area.append(message)

        def export_data(self):
            csv_path, summary_path = self.controller.export_reports()
            self.log_area.append(f"[EXPORT] CSV: {csv_path}")
            self.log_area.append(f"[EXPORT] Summary: {summary_path}")

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


def main() -> int:
    try:
        return run_qt_app()
    except ModuleNotFoundError as exc:
        if exc.name == "PyQt6":
            controller = AppController()
            print(controller.apply_profile("default"))
            csv_path, summary_path = controller.export_reports()
            print(f"[EXPORT] CSV: {csv_path}")
            print(f"[EXPORT] Summary: {summary_path}")
            return 0
        raise


if __name__ == "__main__":
    raise SystemExit(main())
