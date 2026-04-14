from __future__ import annotations

import re
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from NetworkMonitor.app.plot_widget import PlotWidget
from NetworkMonitor.app.settings_dialog import _model_path_for_profile
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.storage.database import get_recent_alerts
from NetworkMonitor.reports.export import export_reports


def load_qss(app: QApplication) -> None:
    base_dir = Path(__file__).resolve().parents[1]
    qss_path = base_dir / "assets" / "styles.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Guardian v2.0")
        self.resize(1320, 780)

        self.engine = NetworkEngine(callback=None)
        self.worker: CaptureWorker | None = None
        self.is_monitoring = False
        self.current_mode = "idle"
        self.last_pcap_path: str | None = None

        self.verdict_counts = {"anomaly": 0, "suspicious": 0, "malicious": 0}
        self.alert_rows_cache: list[tuple] = []

        self._build_ui()

        self.append_log("<b style='color:#89dceb;'>[SYSTEM] Готово. Нажми 'Запустить мониторинг'.</b>")
        self.apply_profile_on_startup()

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_graphs)
        self.timer.start()

        self.alerts_timer = QTimer(self)
        self.alerts_timer.setInterval(3000)
        self.alerts_timer.timeout.connect(self.refresh_recent_alerts)
        self.alerts_timer.start()
        self.refresh_recent_alerts()

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

        layout.addWidget(QLabel("🛡️ Main Dashboard"))

        head_row = QHBoxLayout()
        self.mode_label = QLabel("Режим: idle")
        self.profile_label = QLabel("Профиль: —")
        self.incidents_count_label = QLabel("Инциденты: 0")
        self.ioc_total_label = QLabel("IOC hits: 0")
        self.infected_hosts_count_label = QLabel("Infected hosts: 0")
        for w in [
            self.mode_label,
            self.profile_label,
            self.incidents_count_label,
            self.ioc_total_label,
            self.infected_hosts_count_label,
        ]:
            head_row.addWidget(w)
        head_row.addStretch(1)
        layout.addLayout(head_row)

        center = QHBoxLayout()

        left_layout = QVBoxLayout()
        assessment_box = QFrame()
        assessment_box.setObjectName("assessment_box")
        assessment_layout = QGridLayout(assessment_box)

        self.status_label = QLabel("Статус: ожидание запуска")
        self.ib_label = QLabel("Индекс состояния ИБ: —")
        self.threat_label = QLabel("Уровень угрозы: —")
        self.incident_label = QLabel("Вероятность инцидента: —")
        self.confidence_label = QLabel("Достоверность: —")
        self.ioc_label = QLabel("IOC IP совпадения: 0")
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

        self.main_tabs = QTabWidget()

        log_tab = QWidget()
        log_tab_layout = QVBoxLayout(log_tab)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        log_tab_layout.addWidget(self.log_area)
        self.main_tabs.addTab(log_tab, "Журнал")

        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(alerts_tab)
        alerts_controls = QHBoxLayout()
        self.alert_filter_combo = QComboBox()
        self.alert_filter_combo.addItems(["ALL", "INCIDENT", "IOC_MATCH", "IOC_DOMAIN_MATCH", "EVENT_VERDICT"])
        self.alert_filter_combo.currentIndexChanged.connect(self.apply_alerts_filter)
        alerts_controls.addWidget(self.alert_filter_combo)

        self.alert_search_input = QLineEdit()
        self.alert_search_input.setPlaceholderText("Поиск по alert description...")
        self.alert_search_input.textChanged.connect(self.apply_alerts_filter)
        alerts_controls.addWidget(self.alert_search_input)
        alerts_layout.addLayout(alerts_controls)

        self.alerts_list = QListWidget()
        alerts_layout.addWidget(self.alerts_list)
        self.main_tabs.addTab(alerts_tab, "Алерты")

        reports_tab = QWidget()
        reports_layout = QVBoxLayout(reports_tab)
        self.reports_info = QTextEdit()
        self.reports_info.setReadOnly(True)
        self.reports_info.setPlaceholderText("Здесь будет сводка последнего экспорта отчётов.")
        reports_layout.addWidget(self.reports_info)
        self.reports_export_btn = QPushButton("ЭКСПОРТ ОТЧЁТА (CSV + SUMMARY)")
        self.reports_export_btn.clicked.connect(self.export_report)
        reports_layout.addWidget(self.reports_export_btn)
        self.main_tabs.addTab(reports_tab, "Отчёты")

        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        settings_layout.addWidget(QLabel("Перейдите на экран Settings/Profile для управления профилями и порогами."))
        open_settings_page_btn = QPushButton("ОТКРЫТЬ SETTINGS / PROFILE")
        open_settings_page_btn.clicked.connect(lambda: self.switch_page(2))
        settings_layout.addWidget(open_settings_page_btn)
        settings_layout.addStretch(1)
        self.main_tabs.addTab(settings_tab, "Настройки")

        left_layout.addWidget(self.main_tabs)

        btn_row = QHBoxLayout()
        self.action_btn = QPushButton("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("primary_btn")
        self.action_btn.clicked.connect(self.toggle_monitoring)
        btn_row.addWidget(self.action_btn)

        self.open_pcap_from_main_btn = QPushButton("ОТКРЫТЬ PCAP")
        self.open_pcap_from_main_btn.clicked.connect(self.open_pcap)
        btn_row.addWidget(self.open_pcap_from_main_btn)

        self.settings_btn = QPushButton("ПРОФИЛИ / НАСТРОЙКИ")
        self.settings_btn.clicked.connect(lambda: self.switch_page(2))
        btn_row.addWidget(self.settings_btn)

        self.export_btn = QPushButton("ЭКСПОРТ ОТЧЁТА (CSV)")
        self.export_btn.clicked.connect(self.export_report)
        btn_row.addWidget(self.export_btn)
        left_layout.addLayout(btn_row)

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

        center.addLayout(left_layout, stretch=3)
        center.addLayout(right_layout, stretch=2)
        layout.addLayout(center)
        return page

    def _build_pcap_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        layout.addWidget(QLabel("📁 PCAP Screen"))
        self.pcap_selected_file_label = QLabel("Файл: не выбран")
        self.pcap_state_label = QLabel("Состояние анализа: ожидание файла")
        layout.addWidget(self.pcap_selected_file_label)
        layout.addWidget(self.pcap_state_label)

        pcap_actions = QHBoxLayout()
        self.pcap_btn = QPushButton("ВЫБРАТЬ PCAP ФАЙЛ")
        self.pcap_btn.clicked.connect(self.open_pcap)
        pcap_actions.addWidget(self.pcap_btn)

        self.stop_pcap_btn = QPushButton("ОСТАНОВИТЬ АНАЛИЗ")
        self.stop_pcap_btn.clicked.connect(self.stop_current_run)
        pcap_actions.addWidget(self.stop_pcap_btn)

        self.open_main_btn = QPushButton("ПЕРЕЙТИ НА MAIN")
        self.open_main_btn.clicked.connect(lambda: self.switch_page(0))
        pcap_actions.addWidget(self.open_main_btn)
        layout.addLayout(pcap_actions)

        summary_box = QFrame()
        summary_box.setObjectName("assessment_box")
        summary_layout = QGridLayout(summary_box)
        self.pcap_ioc_label = QLabel("IOC matches: 0")
        self.pcap_incidents_label = QLabel("Incidents: 0")
        self.pcap_infected_label = QLabel("Infected hosts: 0")
        self.pcap_malicious_label = QLabel("Malicious events: 0")
        self.pcap_suspicious_label = QLabel("Suspicious events: 0")
        self.pcap_anomaly_label = QLabel("Anomaly events: 0")
        self.pcap_summary_label = QLabel("Summary: результат анализа ещё не сформирован")
        self.pcap_summary_label.setWordWrap(True)

        summary_layout.addWidget(self.pcap_ioc_label, 0, 0)
        summary_layout.addWidget(self.pcap_incidents_label, 0, 1)
        summary_layout.addWidget(self.pcap_infected_label, 1, 0)
        summary_layout.addWidget(self.pcap_malicious_label, 1, 1)
        summary_layout.addWidget(self.pcap_suspicious_label, 2, 0)
        summary_layout.addWidget(self.pcap_anomaly_label, 2, 1)
        summary_layout.addWidget(self.pcap_summary_label, 3, 0, 1, 2)
        layout.addWidget(summary_box)

        bottom = QHBoxLayout()
        self.pcap_stats_list = QListWidget()
        bottom.addWidget(self.pcap_stats_list, stretch=2)
        self.pcap_log_area = QTextEdit()
        self.pcap_log_area.setReadOnly(True)
        bottom.addWidget(self.pcap_log_area, stretch=3)
        layout.addLayout(bottom)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        layout.addWidget(QLabel("⚙️ Settings / Profile"))
        self.settings_profile_label = QLabel("Активный профиль: —")
        layout.addWidget(self.settings_profile_label)

        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel("Профиль:"))
        self.settings_profile_combo = QComboBox()
        self.settings_profile_combo.currentIndexChanged.connect(self.on_settings_profile_changed)
        profile_row.addWidget(self.settings_profile_combo, stretch=1)

        self.settings_apply_btn = QPushButton("ПРИМЕНИТЬ ПРОФИЛЬ")
        self.settings_apply_btn.clicked.connect(self.apply_settings_profile)
        profile_row.addWidget(self.settings_apply_btn)
        layout.addLayout(profile_row)

        form = QFormLayout()
        self.settings_sample_factor = QSpinBox()
        self.settings_sample_factor.setRange(1, 200)
        form.addRow("Sampling (каждый N-й пакет):", self.settings_sample_factor)

        self.settings_pps_window = QSpinBox()
        self.settings_pps_window.setRange(1, 120)
        form.addRow("Окно PPS (сек):", self.settings_pps_window)

        self.settings_scan_thr = QSpinBox()
        self.settings_scan_thr.setRange(1, 10000)
        form.addRow("Порог Port-Scan (уник. порты):", self.settings_scan_thr)

        self.settings_dos_thr = QSpinBox()
        self.settings_dos_thr.setRange(1, 200000)
        form.addRow("Порог DoS (pps_eff):", self.settings_dos_thr)

        self.settings_train_size = QSpinBox()
        self.settings_train_size.setRange(50, 100000)
        form.addRow("ML train_size:", self.settings_train_size)

        self.settings_contamination = QDoubleSpinBox()
        self.settings_contamination.setRange(0.0001, 0.5)
        self.settings_contamination.setDecimals(4)
        self.settings_contamination.setSingleStep(0.001)
        form.addRow("ML contamination:", self.settings_contamination)

        self.settings_estimators = QSpinBox()
        self.settings_estimators.setRange(10, 1000)
        form.addRow("ML n_estimators:", self.settings_estimators)

        layout.addLayout(form)

        actions = QHBoxLayout()
        self.settings_save_btn = QPushButton("СОХРАНИТЬ")
        self.settings_save_btn.clicked.connect(self.save_settings_profile)
        actions.addWidget(self.settings_save_btn)

        self.settings_reset_model_btn = QPushButton("СБРОСИТЬ ML МОДЕЛЬ")
        self.settings_reset_model_btn.clicked.connect(self.reset_settings_model)
        actions.addWidget(self.settings_reset_model_btn)

        self.settings_reload_btn = QPushButton("ОБНОВИТЬ")
        self.settings_reload_btn.clicked.connect(self.reload_settings_screen_profiles)
        actions.addWidget(self.settings_reload_btn)

        layout.addLayout(actions)
        layout.addStretch(1)
        self.reload_settings_screen_profiles()
        return page

    # -------- navigation and profile --------
    def switch_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        nav_buttons = [self.main_nav_btn, self.pcap_nav_btn, self.settings_nav_btn]
        for i, btn in enumerate(nav_buttons):
            btn.setChecked(i == index)
            btn.setObjectName("nav_btn_active" if i == index else "nav_btn")
            btn.setStyle(btn.style())

    def apply_profile_on_startup(self) -> None:
        try:
            pm = ProfileManager()
            active_name = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active_name)
            self.engine.apply_profile(prof.data, profile_name=prof.filename.replace(".json", ""))
            self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён: {prof.name} ({prof.filename})</b>")
            self.refresh_profile_labels()
            self.reload_settings_screen_profiles(select_filename=active_name)
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

    def reload_settings_screen_profiles(self, select_filename: str | None = None) -> None:
        pm = ProfileManager()
        profiles = pm.list_profiles()
        self.settings_profile_combo.blockSignals(True)
        self.settings_profile_combo.clear()
        for p in profiles:
            self.settings_profile_combo.addItem(p.name, p.filename)

        target = select_filename or pm.get_active_filename() or "default.json"
        idx = self.settings_profile_combo.findData(target)
        if idx >= 0:
            self.settings_profile_combo.setCurrentIndex(idx)
        self.settings_profile_combo.blockSignals(False)
        self.on_settings_profile_changed()

    def on_settings_profile_changed(self) -> None:
        filename = self.settings_profile_combo.currentData()
        if not filename:
            return
        pm = ProfileManager()
        prof = pm.load_profile(filename)
        data = prof.data
        ml = data.get("ml", {}) if isinstance(data.get("ml"), dict) else {}

        self.settings_sample_factor.setValue(int(data.get("sample_factor", 20)))
        self.settings_pps_window.setValue(int(data.get("pps_window_sec", 10)))
        self.settings_scan_thr.setValue(int(data.get("scan_ports_threshold", 50)))
        self.settings_dos_thr.setValue(int(data.get("dos_pps_eff_threshold", 100)))
        self.settings_train_size.setValue(int(ml.get("train_size", ml.get("train_packets", 500))))
        self.settings_contamination.setValue(float(ml.get("contamination", 0.005)))
        self.settings_estimators.setValue(int(ml.get("n_estimators", 50)))

    def _build_profile_dict_from_settings_screen(self, current_name: str) -> dict:
        return {
            "name": current_name,
            "sample_factor": int(self.settings_sample_factor.value()),
            "pps_window_sec": int(self.settings_pps_window.value()),
            "scan_ports_threshold": int(self.settings_scan_thr.value()),
            "dos_pps_eff_threshold": int(self.settings_dos_thr.value()),
            "ml": {
                "train_size": int(self.settings_train_size.value()),
                "contamination": float(self.settings_contamination.value()),
                "n_estimators": int(self.settings_estimators.value()),
            },
        }

    def save_settings_profile(self) -> None:
        filename = self.settings_profile_combo.currentData()
        if not filename:
            return
        pm = ProfileManager()
        prof = pm.load_profile(filename)
        data = self._build_profile_dict_from_settings_screen(current_name=str(prof.data.get("name", prof.name)))
        path = pm.profiles_dir / filename
        path.write_text(__import__("json").dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.append_log(f"<b style='color:#a6e3a1;'>[SETTINGS] Профиль сохранён: {filename}</b>")

    def apply_settings_profile(self) -> None:
        filename = self.settings_profile_combo.currentData()
        if not filename:
            return
        pm = ProfileManager()
        prof = pm.load_profile(filename)
        self.engine.apply_profile(prof.data, profile_name=Path(filename).stem)
        pm.set_active_filename(filename)
        self.append_log(f"<b style='color:#89dceb;'>[PROFILE] Применён из Settings: {prof.name} ({filename})</b>")
        self.refresh_profile_labels()

    def reset_settings_model(self) -> None:
        filename = self.settings_profile_combo.currentData()
        if not filename:
            return
        model_path = _model_path_for_profile(Path(filename).stem)
        if model_path.exists():
            model_path.unlink()
            self.append_log(f"<b style='color:#f9e2af;'>[ML] Модель сброшена: {model_path.name}</b>")
        else:
            self.append_log(f"<i>[ML] Модель не найдена: {model_path.name}</i>")

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
        self.pcap_state_label.setText(f"Состояние анализа: {text}")

    def _update_verdict_counters(self, msg: str) -> None:
        plain = self._strip_html(msg).lower()
        if "[verdict]" not in plain:
            return

        if "malicious" in plain:
            self.verdict_counts["malicious"] += 1
        elif "suspicious" in plain:
            self.verdict_counts["suspicious"] += 1
        elif "anomaly" in plain:
            self.verdict_counts["anomaly"] += 1

        self.pcap_malicious_label.setText(f"Malicious events: {self.verdict_counts['malicious']}")
        self.pcap_suspicious_label.setText(f"Suspicious events: {self.verdict_counts['suspicious']}")
        self.pcap_anomaly_label.setText(f"Anomaly events: {self.verdict_counts['anomaly']}")

    def refresh_recent_alerts(self) -> None:
        try:
            rows = get_recent_alerts(limit=200)
        except Exception:
            return
        self.alert_rows_cache = rows
        self.apply_alerts_filter()

    def apply_alerts_filter(self) -> None:
        self.alerts_list.clear()
        alert_type_filter = self.alert_filter_combo.currentText() if hasattr(self, "alert_filter_combo") else "ALL"
        query = self.alert_search_input.text().strip().lower() if hasattr(self, "alert_search_input") else ""

        for _, ts, atype, desc in self.alert_rows_cache:
            if alert_type_filter != "ALL" and atype != alert_type_filter:
                continue
            line = f"{ts} | {atype} | {desc[:140]}"
            if query and query not in line.lower():
                continue
            self.alerts_list.addItem(line)

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
        self.settings_apply_btn.setEnabled(not running)
        self.settings_save_btn.setEnabled(not running)
        self.settings_reset_model_btn.setEnabled(not running)
        self.reports_export_btn.setEnabled(not running)

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
        self._set_mode("pcap")
        self._clear_runtime_view_state()
        self._set_controls_during_run(running=True)

        self.set_status_text("offline-анализ PCAP")
        self.append_log(f"<b style='color:#89dceb;'>[SYSTEM] Запуск PCAP анализа: {file_path}</b>")
        self.start_worker(mode="pcap", pcap_path=file_path)

    def stop_current_run(self) -> None:
        if not self.is_monitoring:
            return
        self.append_log("<b style='color:#f38ba8;'>[SYSTEM] Остановка текущего анализа...</b>")
        self.engine.stop_capture()

    def toggle_monitoring(self) -> None:
        if self.is_monitoring:
            return

        self.switch_page(0)
        self._set_mode("live")
        self._clear_runtime_view_state()
        self.is_monitoring = True

        self.action_btn.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
        self.action_btn.setObjectName("stop_mode")
        self.action_btn.setStyle(self.action_btn.style())

        self._set_controls_during_run(running=True)
        self.action_btn.setEnabled(True)

        self.set_status_text("идёт live-мониторинг")
        self.update_assessment_panel()
        self.append_log("<b style='color:#a6e3a1;'>[SYSTEM] Мониторинг запущен...</b>")

        self.action_btn.clicked.disconnect()
        self.action_btn.clicked.connect(self.stop_current_run)
        self.start_worker(mode="live")

    def export_report(self) -> None:
        try:
            csv_path, summary_path = export_reports(context=self._build_export_context())
            self.append_log(f"<b style='color:#a6e3a1;'>[REPORT] CSV: {csv_path}</b>")
            self.append_log(f"<b style='color:#a6e3a1;'>[REPORT] Summary: {summary_path}</b>")
            if hasattr(self, "reports_info"):
                self.reports_info.setPlainText(
                    "Последний экспорт:\n"
                    f"- CSV: {csv_path}\n"
                    f"- Summary: {summary_path}\n"
                    f"- Профиль: {self.profile_label.text()}\n"
                    f"- Режим: {self.mode_label.text()}\n"
                    f"- IOC: {self.ioc_total_label.text()}\n"
                    f"- Инциденты: {self.incidents_count_label.text()}\n"
                    f"- Infected hosts: {self.infected_hosts_count_label.text()}\n"
                )
        except Exception as e:
            self.append_log(f"<span style='color:#f38ba8;'>[REPORT ERROR] {type(e).__name__}: {e}</span>")
            QMessageBox.critical(self, "Экспорт", f"Ошибка экспорта: {e}")

    def _build_export_context(self) -> dict:
        top_hosts = []
        for ip, count in self.engine.attacker_stats.most_common(10):
            top_hosts.append({"ip": ip, "events": int(count)})
        return {
            "profile": getattr(self.engine, "profile_name", "default"),
            "mode": self.current_mode,
            "assessment": getattr(self.engine, "last_assessment", None),
            "ioc_hits_total": len(getattr(self.engine, "ioc_seen", set())) + len(getattr(self.engine, "domain_ioc_seen", set())),
            "incidents_total": len(getattr(self.engine, "incidents", {})),
            "infected_hosts": sorted(list(getattr(self.engine, "reported_infected_hosts", set()))),
            "top_hosts": top_hosts,
        }

    # -------- callbacks --------
    def update_stats_display(self) -> None:
        self.stats_list.clear()
        self.pcap_stats_list.clear()
        for ip, count in self.engine.attacker_stats.most_common(10):
            line = f"{ip} → {count} событий"
            self.stats_list.addItem(line)
            self.pcap_stats_list.addItem(line)

    def refresh_graphs(self) -> None:
        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        self.plot.push(pps_eff=pps_eff, anom_rate=anom / seen)

    def on_worker_message(self, msg: str) -> None:
        self.append_log(msg)
        self._update_verdict_counters(msg)
        self.update_assessment_panel()
        self.update_stats_display()
        self.update_incidents_display()

    def on_worker_finished(self) -> None:
        self.is_monitoring = False
        self._set_mode("idle")
        self._set_controls_during_run(running=False)

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
        self.refresh_recent_alerts()
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
