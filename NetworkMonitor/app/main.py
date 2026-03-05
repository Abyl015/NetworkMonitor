# NetworkMonitor/app/main.py
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QVBoxLayout, QHBoxLayout,
    QWidget, QPushButton, QLabel, QListWidget, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer

from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.app.settings_dialog import SettingsDialog
from NetworkMonitor.app.plot_widget import PlotWidget

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
        self.resize(1200, 720)

        self.engine = NetworkEngine(callback=None)
        self.worker: CaptureWorker | None = None
        self.is_monitoring = False


        # -------- UI --------
        main_layout = QHBoxLayout()

        # Left
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)

        title_left = QLabel("🛡️ Живой лог трафика")
        title_left.setAlignment(Qt.AlignmentFlag.AlignLeft)
        left_layout.addWidget(title_left)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        left_layout.addWidget(self.log_area)

        self.ib_label = QLabel("ИБ: 100/100 — Высокий уровень ИБ")
        left_layout.addWidget(self.ib_label)

        # Buttons row
        btn_row = QHBoxLayout()

        self.action_btn = QPushButton("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.clicked.connect(self.toggle_monitoring)
        btn_row.addWidget(self.action_btn)

        self.settings_btn = QPushButton("ПРОФИЛИ / НАСТРОЙКИ")
        self.settings_btn.clicked.connect(self.open_settings)
        btn_row.addWidget(self.settings_btn)

        self.export_btn = QPushButton("ЭКСПОРТ ОТЧЁТА (CSV)")
        self.export_btn.clicked.connect(self.export_report)
        btn_row.addWidget(self.export_btn)

        left_layout.addLayout(btn_row)

        # Right
        right_layout = QVBoxLayout()
        right_layout.setSpacing(10)
        right_layout.setContentsMargins(10, 0, 10, 0)

        title_right = QLabel("⚠️ Топ угроз по IP")
        right_layout.addWidget(title_right)

        self.stats_list = QListWidget()
        right_layout.addWidget(self.stats_list)

        # Graphs
        self.plot = PlotWidget("📈 Метрики в реальном времени (1 точка/сек)")
        right_layout.addWidget(self.plot)

        main_layout.addLayout(left_layout, stretch=3)
        main_layout.addLayout(right_layout, stretch=2)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Готово. Нажми 'Запустить мониторинг'.</b>")

        # применяем профиль ПОСЛЕ UI
        self.apply_profile_on_startup()

        if export_reports is None:
            self.export_btn.setEnabled(False)
            self.export_btn.setToolTip("Модуль NetworkMonitor.reports.export не найден")

        # Таймер: раз в 1 сек обновляем графики из текущих значений engine
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_graphs)
        self.timer.start()


    # -------- Profile apply --------
    def apply_profile_on_startup(self) -> None:
        try:
            pm = ProfileManager()
            active_name = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active_name)  # Profile(...)
            # engine.apply_profile ожидает dict, поэтому prof.data
            self.engine.apply_profile(prof.data, profile_name=prof.filename.replace(".json", ""))
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён: {prof.name} ({prof.filename})</b>")
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[PROFILE] Ошибка: {type(e).__name__}: {e}</span>")

    def open_settings(self):
        dlg = SettingsDialog(self, self.engine)
        dlg.exec()
        # после закрытия — применим активный профиль на всякий случай
        try:
            pm = ProfileManager()
            active = pm.get_active_filename() or "default.json"
            pr = pm.load_profile(active)
            self.engine.apply_profile(pr.data, profile_name=Path(active).stem)
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Активный: {pr.name} ({active})</b>")
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[PROFILE ERROR] {type(e).__name__}: {e}</span>")

    # -------- UI helpers --------
    def append_log(self, msg: str) -> None:
        self.log_area.append(msg)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def update_stats_display(self) -> None:
        self.stats_list.clear()
        for ip, count in self.engine.attacker_stats.most_common(10):
            self.stats_list.addItem(f"{ip} → {count} событий")

    def update_ib_label(self) -> None:
        self.ib_label.setText(f"ИБ: {self.engine.last_ib_score}/100 — {self.engine.last_ib_level}")

    def refresh_graphs(self):
        # Берём “живые” метрики из RuleEngine + ML counters
        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        anom_rate = anom / seen
        self.plot.push(pps_eff=pps_eff, anom_rate=anom_rate)

    # -------- Worker callbacks --------
    def on_worker_message(self, msg: str) -> None:
        self.append_log(msg)
        self.update_ib_label()
        self.update_stats_display()

    def on_worker_finished(self) -> None:
        self.is_monitoring = False
        self.action_btn.setEnabled(True)
        self.settings_btn.setEnabled(True)
        self.action_btn.setText("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("")
        self.action_btn.setStyle(self.action_btn.style())
        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Мониторинг остановлен.</b>")

    # -------- Actions --------
    def toggle_monitoring(self) -> None:
        if not self.is_monitoring:
            self.is_monitoring = True
            self.action_btn.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
            self.action_btn.setObjectName("stop_mode")
            self.action_btn.setStyle(self.action_btn.style())
            self.settings_btn.setEnabled(False)

            self.append_log("<b style='color:#a6e3a1;'>[SYSTEM] Мониторинг запущен...</b>")

            self.worker = CaptureWorker(self.engine)
            self.worker.message.connect(self.on_worker_message)
            self.worker.finished_signal.connect(self.on_worker_finished)
            self.worker.start()
        else:
            self.append_log("<b style='color:#f38ba8;'>[SYSTEM] Остановка мониторинга...</b>")
            self.action_btn.setEnabled(False)
            self.engine.stop_capture()

    def export_report(self) -> None:
        if export_reports is None:
            self.append_log("<span style='color:#f38ba8;'>[REPORT ERROR] export_reports не найден.</span>")
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