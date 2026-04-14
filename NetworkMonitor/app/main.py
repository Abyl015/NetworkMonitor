from __future__ import annotations

import re
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from NetworkMonitor.app.plot_widget import PlotWidget
from NetworkMonitor.app.settings_dialog import SettingsDialog
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.core.engine import NetworkEngine

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


        self.engine = NetworkEngine(callback=None)
        self.worker: CaptureWorker | None = None
        self.is_monitoring = False
        self.current_mode = "idle"
        self.last_pcap_path: str | None = None


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

    # -------- UI build --------
    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        nav_layout = QVBoxLayout(sidebar)
        nav_layout.setContentsMargins(14, 16, 14, 16)
        nav_layout.setSpacing(8)

        nav_title = QLabel("SENTINEL")
        nav_title.setObjectName("nav_title")
        nav_layout.addWidget(nav_title)

        self.main_nav_btn = QPushButton("Main")
        self.main_nav_btn.setCheckable(True)
        self.main_nav_btn.clicked.connect(lambda: self.switch_page(0))
        nav_layout.addWidget(self.main_nav_btn)

        self.pcap_nav_btn = QPushButton("PCAP")
        self.pcap_nav_btn.setCheckable(True)
        self.pcap_nav_btn.clicked.connect(lambda: self.switch_page(1))
        nav_layout.addWidget(self.pcap_nav_btn)

        self.settings_nav_btn = QPushButton("Settings/Profile")
        self.settings_nav_btn.setCheckable(True)
        self.settings_nav_btn.clicked.connect(lambda: self.switch_page(2))
        nav_layout.addWidget(self.settings_nav_btn)
        nav_layout.addStretch(1)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_main_page())
        self.pages.addWidget(self._build_pcap_page())
        self.pages.addWidget(self._build_settings_page())

        root_layout.addWidget(sidebar, stretch=0)
        root_layout.addWidget(self.pages, stretch=1)

        self.setCentralWidget(root)
        self.switch_page(0)

    def _build_main_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("🛡️ Main Dashboard")
        layout.addWidget(title)

        head_row = QHBoxLayout()
        self.mode_label = QLabel("Режим: idle")
        self.profile_label = QLabel("Профиль: —")
        self.incidents_count_label = QLabel("Инциденты: 0")
        self.ioc_total_label = QLabel("IOC hits: 0")
        self.infected_hosts_count_label = QLabel("Infected hosts: 0")
        head_row.addWidget(self.mode_label)
        head_row.addWidget(self.profile_label)
        head_row.addWidget(self.incidents_count_label)
        head_row.addWidget(self.ioc_total_label)
        head_row.addWidget(self.infected_hosts_count_label)
        head_row.addStretch(1)
        layout.addLayout(head_row)

        center = QHBoxLayout()

        # LEFT BLOCK
        left_layout = QVBoxLayout()
        assessment_box = QFrame()
        assessment_box.setObjectName("assessment_box")
        assessment_layout = QGridLayout(assessment_box)

        self.status_label = QLabel("Статус: ожидание запуска")
        self.ib_label = QLabel("Индекс состояния ИБ: —")
        self.threat_label = QLabel("Уровень угрозы: —")
        self.incident_label = QLabel("Вероятность инцидента: —")
        self.confidence_label = QLabel("Достоверность: —")
        self.ioc_label = QLabel("IOC совпадения: 0")
        self.domain_ioc_label = QLabel("IOC domain совпадения: 0")
        self.infected_label = QLabel("Подозрительные хосты: 0")
        self.summary_label = QLabel("Вывод: оценка ещё не сформирована")
        self.summary_label.setWordWrap(True)

        assessment_layout.addWidget(self.status_label, 0, 0, 1, 2)
        assessment_layout.addWidget(self.ib_label, 1, 0)
        assessment_layout.addWidget(self.threat_label, 1, 1)
        assessment_layout.addWidget(self.incident_label, 2, 0)
        assessment_layout.addWidget(self.confidence_label, 2, 1)
        assessment_layout.addWidget(self.ioc_label, 3, 0)
        assessment_layout.addWidget(self.domain_ioc_label, 3, 1)
        assessment_layout.addWidget(self.infected_label, 4, 0)
        assessment_layout.addWidget(self.summary_label, 5, 0, 1, 2)
        left_layout.addWidget(assessment_box)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        left_layout.addWidget(self.log_area)

        btn_row = QHBoxLayout()
        self.action_btn = QPushButton("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("primary_btn")
        self.action_btn.clicked.connect(self.toggle_monitoring)
        btn_row.addWidget(self.action_btn)


        self.settings_btn = QPushButton("ПРОФИЛИ / НАСТРОЙКИ")
        self.settings_btn.clicked.connect(self.open_settings)
        btn_row.addWidget(self.settings_btn)

        self.export_btn = QPushButton("ЭКСПОРТ ОТЧЁТА (CSV)")
        self.export_btn.clicked.connect(self.export_report)
        btn_row.addWidget(self.export_btn)

        left_layout.addLayout(btn_row)

        # RIGHT BLOCK
        right_layout = QVBoxLayout()
        right_layout.setSpacing(10)

        right_layout.addWidget(QLabel("⚠️ Топ угроз по IP"))
        self.stats_list = QListWidget()
        right_layout.addWidget(self.stats_list)

        right_layout.addWidget(QLabel("🚨 Активные инциденты по хостам"))
        self.incidents_list = QListWidget()
        right_layout.addWidget(self.incidents_list)

        self.plot = PlotWidget("📈 Метрики в реальном времени (1 точка/сек)")
        right_layout.addWidget(self.plot)


        return page

    def _build_pcap_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)



        pcap_actions = QHBoxLayout()
        self.pcap_btn = QPushButton("ВЫБРАТЬ PCAP ФАЙЛ")
        self.pcap_btn.clicked.connect(self.open_pcap)
        pcap_actions.addWidget(self.pcap_btn)

        nav_buttons = [self.main_nav_btn, self.pcap_nav_btn, self.settings_nav_btn]
        for i, btn in enumerate(nav_buttons):
            btn.setChecked(i == index)
            btn.setObjectName("nav_btn_active" if i == index else "nav_btn")
            btn.setStyle(btn.style())

    # -------- Profile apply --------
    def apply_profile_on_startup(self) -> None:
        try:
            pm = ProfileManager()
            active_name = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active_name)
            self.engine.apply_profile(prof.data, profile_name=prof.filename.replace(".json", ""))
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён: {prof.name} ({prof.filename})</b>")
            self.refresh_profile_labels()
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[PROFILE] Ошибка: {type(e).__name__}: {e}</span>")

    def refresh_profile_labels(self) -> None:
        try:
            pm = ProfileManager()
            active = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active)
            self.profile_label.setText(f"Профиль: {prof.name}")
            self.settings_profile_label.setText(f"Активный профиль: {prof.name} ({active})")
        except Exception as e:
            self.profile_label.setText("Профиль: ошибка")
            self.settings_profile_label.setText(f"Активный профиль: ошибка ({type(e).__name__})")

    def open_settings(self):
        dlg = SettingsDialog(self, self.engine)
        dlg.exec()
        # после закрытия — применим активный профиль
        try:
            pm = ProfileManager()
            active = pm.get_active_filename() or "default.json"
            pr = pm.load_profile(active)
            self.engine.apply_profile(pr.data, profile_name=Path(active).stem)
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Активный: {pr.name} ({active})</b>")
            self.refresh_profile_labels()
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[PROFILE ERROR] {type(e).__name__}: {e}</span>")

    # -------- helpers --------
    def _set_mode(self, mode: str) -> None:
        self.current_mode = mode
        self.mode_label.setText(f"Режим: {mode}")

    def _clear_runtime_view_state(self) -> None:
        self.verdict_counts = {"anomaly": 0, "suspicious": 0, "malicious": 0}
        self.pcap_malicious_label.setText("Malicious events: 0")
        self.pcap_suspicious_label.setText("Suspicious events: 0")
        self.pcap_anomaly_label.setText("Anomaly events: 0")
        self.pcap_summary_label.setText("Summary: результат анализа ещё не сформирован")
        self.incidents_list.clear()

    def _strip_html(self, msg: str) -> str:
        return re.sub(r"<[^>]+>", "", msg)

    def append_log(self, msg: str) -> None:
        self.log_area.append(msg)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

        self.pcap_log_area.append(msg)
        self.pcap_log_area.verticalScrollBar().setValue(self.pcap_log_area.verticalScrollBar().maximum())

    def update_assessment_panel(self) -> None:
        assessment = getattr(self.engine, "last_assessment", None)
        ready = bool(getattr(self.engine, "assessment_ready", False))

        if not ready or not assessment:
            self.ib_label.setText("Индекс состояния ИБ: формируется...")
            self.threat_label.setText("Уровень угрозы: —")
            self.incident_label.setText("Вероятность инцидента: —")
            self.confidence_label.setText("Достоверность: —")
            self.summary_label.setText("Вывод: недостаточно данных для достоверной оценки")
            self.pcap_summary_label.setText("Summary: ждём завершения анализа и расчёта assessment")
        else:
            self.ib_label.setText(f"Индекс состояния ИБ: {assessment['overall_score']}/100")
            self.threat_label.setText(f"Уровень угрозы: {assessment['threat_level']}")
            self.incident_label.setText(f"Вероятность инцидента: {assessment['incident_probability']}")
            self.confidence_label.setText(f"Достоверность: {assessment['confidence']}")
            self.summary_label.setText(f"Вывод: {assessment['summary']}")
            self.pcap_summary_label.setText(f"Summary: {assessment['summary']}")

        ioc_hits = len(getattr(self.engine, "ioc_seen", set()))
        domain_hits = len(getattr(self.engine, "domain_ioc_seen", set()))
        incidents_count = len(getattr(self.engine, "incidents", {}))
        infected_count = len(getattr(self.engine, "reported_infected_hosts", set()))

        self.ioc_label.setText(f"IOC IP совпадения: {ioc_hits}")
        self.domain_ioc_label.setText(f"IOC domain совпадения: {domain_hits}")
        self.infected_label.setText(f"Подозрительные хосты: {infected_count}")

        self.ioc_total_label.setText(f"IOC hits: {ioc_hits + domain_hits}")
        self.incidents_count_label.setText(f"Инциденты: {incidents_count}")
        self.infected_hosts_count_label.setText(f"Infected hosts: {infected_count}")

        self.pcap_ioc_label.setText(f"IOC matches: {ioc_hits + domain_hits}")
        self.pcap_incidents_label.setText(f"Incidents: {incidents_count}")
        self.pcap_infected_label.setText(f"Infected hosts: {infected_count}")

    def update_incidents_display(self) -> None:
        self.incidents_list.clear()
        incidents = getattr(self.engine, "incidents", {})
        for host, inc in list(incidents.items())[:20]:
            line = (
                f"{host} | ioc_ip={inc.get('ioc_ip_hits', 0)} | ioc_domain={inc.get('ioc_domain_hits', 0)} "
                f"| ml={inc.get('ml_hits', 0)} | scan={inc.get('scan_hits', 0)} | dos={inc.get('dos_hits', 0)}"
            )
            self.incidents_list.addItem(line)

    def set_status_text(self, text: str) -> None:
        self.status_label.setText(f"Статус: {text}")


    def start_worker(self, mode: str, pcap_path: str | None = None) -> None:
        self.worker = CaptureWorker(self.engine, mode=mode, pcap_path=pcap_path)
        self.worker.message.connect(self.on_worker_message)
        self.worker.finished_signal.connect(self.on_worker_finished)
        self.worker.start()

    def _set_controls_during_run(self, running: bool) -> None:
        self.action_btn.setEnabled(not running)
        self.open_pcap_from_main_btn.setEnabled(not running)
        self.pcap_btn.setEnabled(not running)
        self.settings_btn.setEnabled(not running)
        self.settings_page_btn.setEnabled(not running)

    # -------- actions --------
    def open_pcap(self) -> None:
        if self.is_monitoring:
            QMessageBox.information(self, "PCAP", "Сначала остановите текущий мониторинг/анализ.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите PCAP файл",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)",
        )
        if not file_path:
            return

        self.switch_page(1)
        self.last_pcap_path = file_path
        self.pcap_selected_file_label.setText(f"Файл: {file_path}")
        self.is_monitoring = True


        self.set_status_text("offline-анализ PCAP")
        self.append_log(f"<b style='color:#89dceb;'>[SYSTEM] Запуск PCAP анализа: {file_path}</b>")

        self.start_worker(mode="pcap", pcap_path=file_path)


    def update_stats_display(self) -> None:
        self.stats_list.clear()
        self.pcap_stats_list.clear()
        for ip, count in self.engine.attacker_stats.most_common(10):
            line = f"{ip} → {count} событий"
            self.stats_list.addItem(line)
            self.pcap_stats_list.addItem(line)


    def refresh_graphs(self):
        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        anom_rate = anom / seen
        self.plot.push(pps_eff=pps_eff, anom_rate=anom_rate)

    def on_worker_message(self, msg: str) -> None:
        self.append_log(msg)
        self._update_verdict_counters(msg)
        self.update_assessment_panel()
        self.update_stats_display()
        self.update_incidents_display()

    def on_worker_finished(self) -> None:
        self.is_monitoring = False
        self._set_mode("idle")



        # вернём стартовую семантику кнопки live monitoring
        try:
            self.action_btn.clicked.disconnect()
        except Exception:
            pass
        self.action_btn.clicked.connect(self.toggle_monitoring)
        self.action_btn.setText("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("primary_btn")
        self.action_btn.setStyle(self.action_btn.style())

        self.set_status_text("ожидание запуска")
        self.update_assessment_panel()
        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Мониторинг / анализ остановлен.</b>")

          

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
