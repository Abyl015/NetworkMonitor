import sys

from NetworkMonitor.core.engine import Engine
from NetworkMonitor.core.profile import Profile


class AppController:
    def __init__(self):
        self.engine = Engine()
        self.profiles = {
            "default": Profile(
                name="default",
                data={
                    "sample_factor": 20,
                    "thresholds": {"burst": 10},
                    "ml": {"train_size": 500, "contamination": 0.005, "n_estimators": 50},
                },
            ),
            "strict": Profile(
                name="strict",
                data={
                    "sample_factor": 10,
                    "thresholds": {"burst": 5},
                    "ml": {"train_size": 300, "contamination": 0.01, "n_estimators": 100},
                },
            ),
        }

    def apply_profile(self, profile_name: str) -> str:
        profile = self.profiles[profile_name]
        self.engine.apply_profile(profile)
        self.engine.reset_state()
        return f"[SYSTEM] Активный профиль: {profile.name}"


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
            self.profile_combo.addItems(self.controller.profiles.keys())
            layout.addWidget(self.profile_combo)

            self.apply_btn = QPushButton("Применить профиль")
            self.apply_btn.clicked.connect(self.apply_selected_profile)
            layout.addWidget(self.apply_btn)

            self.log_area = QTextEdit()
            self.log_area.setReadOnly(True)
            layout.addWidget(self.log_area)

            self.setCentralWidget(root)
            self.apply_selected_profile()

        def apply_selected_profile(self):
            profile_name = self.profile_combo.currentText()
            message = self.controller.apply_profile(profile_name)
            self.log_area.append(message)

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
            return 0
        raise


if __name__ == "__main__":
    raise SystemExit(main())
