from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QVBoxLayout, QHBoxLayout,
    QWidget, QPushButton, QLabel, QListWidget, QMessageBox, QComboBox
)
from PyQt6.QtCore import Qt

from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager

# Экспорт отчётов (если модуль есть)
try:
    from NetworkMonitor.reports.export import export_reports
except Exception:
    export_reports = None


def load_qss(app: QApplication) -> None:
    base_dir = Path(__file__).resolve().parents[1]  # .../NetworkMonitor
    qss_path = base_dir / "assets" / "styles.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Guardian v2.0")
        self.resize(1100, 650)

        # -------- Engine / Worker --------
        self.engine = NetworkEngine(callback=None)
        self.worker: CaptureWorker | None = None
        self.is_monitoring = False

        # -------- Profile manager --------
        self.pm = ProfileManager()

        # -------- UI --------
        main_layout = QHBoxLayout()

        # Left side
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)

        title_left = QLabel("🛡️ Живой лог трафика")
        title_left.setAlignment(Qt.AlignmentFlag.AlignLeft)
        left_layout.addWidget(title_left)

        # --- Profile row (NEW) ---
        profile_row = QHBoxLayout()

        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(240)

        self.apply_profile_btn = QPushButton("ПРИМЕНИТЬ ПРОФИЛЬ")
        self.apply_profile_btn.clicked.connect(self.apply_selected_profile)

        profile_row.addWidget(QLabel("Профиль:"))
        profile_row.addWidget(self.profile_combo, stretch=1)
        profile_row.addWidget(self.apply_profile_btn)

        left_layout.addLayout(profile_row)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        left_layout.addWidget(self.log_area)

        # IB label
        self.ib_label = QLabel("ИБ: 100/100 — Высокий уровень ИБ")
        left_layout.addWidget(self.ib_label)

        # Buttons row
        btn_row = QHBoxLayout()

        self.action_btn = QPushButton("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.clicked.connect(self.toggle_monitoring)
        btn_row.addWidget(self.action_btn)

        self.export_btn = QPushButton("ЭКСПОРТ ОТЧЁТА (CSV)")
        self.export_btn.clicked.connect(self.export_report)
        btn_row.addWidget(self.export_btn)

        left_layout.addLayout(btn_row)

        # Right side
        right_layout = QVBoxLayout()
        right_layout.setSpacing(10)
        right_layout.setContentsMargins(10, 0, 10, 0)

        title_right = QLabel("⚠️ Топ угроз по IP")
        right_layout.addWidget(title_right)

        self.stats_list = QListWidget()
        right_layout.addWidget(self.stats_list)

        main_layout.addLayout(left_layout, stretch=3)
        main_layout.addLayout(right_layout, stretch=1)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # -------- Initial log --------
        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Готово. Нажми 'Запустить мониторинг'.</b>")

        # -------- Fill profiles + apply active (NEW) --------
        self.reload_profiles_to_combo()
        self.apply_profile_on_startup()

        # -------- Export availability --------
        if export_reports is None:
            self.export_btn.setEnabled(False)
            self.export_btn.setToolTip("Модуль NetworkMonitor.reports.export не найден")

    # -------- Profile UI --------
    def reload_profiles_to_combo(self) -> None:
        """Обновляет список профилей в ComboBox."""
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()

        profiles = self.pm.list_profiles()
        for p in profiles:
            # текстом показываем "name", а внутри храним filename
            self.profile_combo.addItem(p.name, p.filename)

        # ставим активный
        active = self.pm.get_active_filename() or "default.json"
        idx = self.profile_combo.findData(active)
        if idx >= 0:
            self.profile_combo.setCurrentIndex(idx)

        self.profile_combo.blockSignals(False)

    def apply_profile_on_startup(self) -> None:
        """Применяем активный профиль ПОСЛЕ инициализации UI."""
        try:
            active_name = self.pm.get_active_filename() or "default.json"
            profile = self.pm.load_profile(active_name)
            self.engine.apply_profile(profile, profile_name=active_name.replace(".json", ""))
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён: {active_name}</b>")
        except Exception as e:
            self.append_log(
                f"<span style='color:#f38ba8;'>[PROFILE] Не удалось применить профиль: "
                f"{type(e).__name__}: {e}</span>"
            )

    def apply_selected_profile(self) -> None:
        """Кнопка 'Применить профиль'."""
        if self.is_monitoring:
            QMessageBox.warning(self, "Профиль", "Останови мониторинг перед сменой профиля.")
            return

        filename = self.profile_combo.currentData()
        if not filename:
            QMessageBox.warning(self, "Профиль", "Профиль не выбран.")
            return

        try:
            profile = self.pm.load_profile(filename)

            # сохранить как активный
            self.pm.set_active_filename(filename)

            # применить к движку
            self.engine.apply_profile(profile, profile_name=filename.replace(".json", ""))

            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён: {filename}</b>")
        except Exception as e:
            self.append_log(
                f"<span style='color:#f38ba8;'>[PROFILE] Ошибка применения профиля: "
                f"{type(e).__name__}: {e}</span>"
            )
            QMessageBox.critical(self, "Профиль", f"Ошибка: {e}")

    # -------- UI Helpers --------
    def append_log(self, msg: str) -> None:
        self.log_area.append(msg)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def update_stats_display(self) -> None:
        self.stats_list.clear()
        for ip, count in self.engine.attacker_stats.most_common(10):
            self.stats_list.addItem(f"{ip} → {count} событий")

    def update_ib_label(self) -> None:
        self.ib_label.setText(f"ИБ: {self.engine.last_ib_score}/100 — {self.engine.last_ib_level}")

    # -------- Worker callbacks --------
    def on_worker_message(self, msg: str) -> None:
        self.append_log(msg)
        self.update_ib_label()
        self.update_stats_display()

    def on_worker_finished(self) -> None:
        self.is_monitoring = False
        self.action_btn.setEnabled(True)
        self.action_btn.setText("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("")
        self.action_btn.setStyle(self.action_btn.style())

        # при остановке снова разрешаем менять профиль
        self.apply_profile_btn.setEnabled(True)
        self.profile_combo.setEnabled(True)

        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Мониторинг остановлен.</b>")

    # -------- Actions --------
    def toggle_monitoring(self) -> None:
        if not self.is_monitoring:
            # START
            self.is_monitoring = True
            self.action_btn.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
            self.action_btn.setObjectName("stop_mode")
            self.action_btn.setStyle(self.action_btn.style())

            # пока мониторинг идёт — блокируем смену профиля
            self.apply_profile_btn.setEnabled(False)
            self.profile_combo.setEnabled(False)

            self.append_log("<b style='color:#a6e3a1;'>[SYSTEM] Мониторинг запущен...</b>")

            self.worker = CaptureWorker(self.engine)
            self.worker.message.connect(self.on_worker_message)
            self.worker.finished_signal.connect(self.on_worker_finished)
            self.worker.start()
        else:
            # STOP
            self.append_log("<b style='color:#f38ba8;'>[SYSTEM] Остановка мониторинга...</b>")
            self.action_btn.setEnabled(False)
            self.engine.stop_capture()

    def export_report(self) -> None:
        if export_reports is None:
            self.append_log("<span style='color:#f38ba8;'>[REPORT ERROR] export_reports не найден.</span>")
            QMessageBox.warning(self, "Экспорт", "Нет модуля NetworkMonitor.reports.export")
            return

        try:
            csv_path, summary_path = export_reports()
            self.append_log(f"<b style='color:#a6e3a1;'>[REPORT] CSV: {csv_path}</b>")
            self.append_log(f"<b style='color:#a6e3a1;'>[REPORT] Summary: {summary_path}</b>")
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[REPORT ERROR] {type(e).__name__}: {e}</span>")
            QMessageBox.critical(self, "Экспорт", f"Ошибка экспорта: {e}")

    def closeEvent(self, event):
        try:
            if self.is_monitoring:
                self.engine.stop_capture()
        except Exception:
            pass
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    load_qss(app)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()