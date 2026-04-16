from __future__ import annotations

import html
import os
import re
import sys
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QPushButton,
    QLabel,
    QMessageBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QStackedWidget,
    QComboBox,
    QListWidget,
    QScrollArea,
    QSplitter,
    QSizePolicy, QListWidgetItem, QTableWidgetItem,
)

from NetworkMonitor.app.plot_widget import PlotWidget
from NetworkMonitor.app.settings_dialog import SettingsDialog
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.core.report_builder import build_html_report
from NetworkMonitor.storage.database import (
    get_last_session_id,
    get_session_by_id,
    get_sessions,
    init_db,
    update_session_report_path,
)


def load_qss(app: QApplication) -> None:
    base_dir = Path(__file__).resolve().parents[1]
    qss_path = base_dir / "assets" / "styles.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Guardian v2.0")
        self.resize(1440, 860)
        self.setMinimumSize(1180, 720)

        self.engine = NetworkEngine(callback=None)
        self.worker: CaptureWorker | None = None
        self.is_monitoring = False
        self.current_mode = "idle"
        self.last_pcap_path: str | None = None
        self.log_history: list[str] = []
        self.threat_counter: Counter[str] = Counter()
        self.max_event_rows = 120

        init_db()
        self._build_ui()
        self.load_interfaces_to_combo()
        self.apply_profile_on_startup()
        self.append_log("<b style='color:#2563eb;'>[SYSTEM] Готово. Нажми 'Запустить мониторинг'.</b>")
        self.update_assessment_panel()

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_graphs)
        self.timer.start()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(210)

        nav_layout = QVBoxLayout(sidebar)
        nav_layout.setContentsMargins(14, 16, 14, 16)
        nav_layout.setSpacing(10)

        nav_title = QLabel("SENTINEL")
        nav_title.setObjectName("nav_title")
        nav_layout.addWidget(nav_title)

        self.main_nav_btn = QPushButton("Dashboard")
        self.main_nav_btn.setCheckable(True)
        self.main_nav_btn.clicked.connect(lambda: self.switch_page(0))
        nav_layout.addWidget(self.main_nav_btn)

        self.pcap_nav_btn = QPushButton("PCAP")
        self.pcap_nav_btn.setCheckable(True)
        self.pcap_nav_btn.clicked.connect(lambda: self.switch_page(1))
        nav_layout.addWidget(self.pcap_nav_btn)

        self.settings_nav_btn = QPushButton("Settings / Profile")
        self.settings_nav_btn.setCheckable(True)
        self.settings_nav_btn.clicked.connect(lambda: self.switch_page(2))
        nav_layout.addWidget(self.settings_nav_btn)

        self.sessions_nav_btn = QPushButton("Sessions")
        self.sessions_nav_btn.setCheckable(True)
        self.sessions_nav_btn.clicked.connect(lambda: self.switch_page(3))
        nav_layout.addWidget(self.sessions_nav_btn)

        nav_layout.addStretch(1)

        self.pages = QStackedWidget()
        self.pages.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.pages.addWidget(self._build_main_page())
        self.pages.addWidget(self._build_pcap_page())
        self.pages.addWidget(self._build_settings_page())

        self.sessions_page = QWidget()
        self._build_sessions_page()
        self.pages.addWidget(self.sessions_page)

        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.pages)

        root_layout.setStretch(0, 0)
        root_layout.setStretch(1, 1)

        self.setCentralWidget(root)
        self.switch_page(0)
    def _make_metric_card(self, title: str, value: str, subtitle: str = "") -> tuple[QFrame, QLabel, QLabel]:
        card = QFrame()
        card.setObjectName("metric_card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("card_title")
        value_lbl = QLabel(value)
        value_lbl.setObjectName("card_value")
        subtitle_lbl = QLabel(subtitle)
        subtitle_lbl.setObjectName("card_subtitle")
        subtitle_lbl.setWordWrap(True)

        layout.addWidget(title_lbl)
        layout.addWidget(value_lbl)
        layout.addWidget(subtitle_lbl)
        return card, value_lbl, subtitle_lbl

    def _build_main_page(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(12, 12, 12, 12)
        page_layout.setSpacing(10)

        # ---------- TOP BAR ----------
        top_card = QFrame()
        top_card.setObjectName("top_card")
        top_grid = QGridLayout(top_card)
        top_grid.setContentsMargins(14, 12, 14, 12)
        top_grid.setHorizontalSpacing(10)
        top_grid.setVerticalSpacing(8)

        self.page_title = QLabel("Панель мониторинга сети")
        self.page_title.setObjectName("page_title")

        self.page_subtitle = QLabel("Live traffic, incidents, IOC и оценка ИБ в реальном времени")
        self.page_subtitle.setObjectName("page_subtitle")

        self.status_label = QLabel("Статус: ожидание запуска")
        self.status_label.setObjectName("status_chip")
        self.header_status = self.status_label

        title_box = QVBoxLayout()
        title_box.setContentsMargins(0, 0, 0, 0)
        title_box.setSpacing(2)
        title_box.addWidget(self.page_title)
        title_box.addWidget(self.page_subtitle)

        title_wrap = QWidget()
        title_wrap.setLayout(title_box)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(170)
        self.iface_combo.setMaximumWidth(260)

        self.refresh_ifaces_btn = QPushButton("Обновить интерфейс")
        self.refresh_ifaces_btn.clicked.connect(self.load_interfaces_to_combo)

        self.settings_btn = QPushButton("Профили / настройки")
        self.settings_btn.clicked.connect(self.open_settings)

        self.export_btn = QPushButton("Экспорт отчёта")
        self.export_btn.clicked.connect(self.export_report)

        self.action_btn = QPushButton("Запустить мониторинг")
        self.action_btn.setObjectName("primary_btn")
        self.action_btn.clicked.connect(self.toggle_monitoring)

        top_grid.addWidget(title_wrap, 0, 0, 1, 2)
        top_grid.addWidget(self.status_label, 0, 2)
        top_grid.addWidget(self.iface_combo, 0, 3)
        top_grid.addWidget(self.refresh_ifaces_btn, 0, 4)
        top_grid.addWidget(self.settings_btn, 0, 5)
        top_grid.addWidget(self.export_btn, 0, 6)
        top_grid.addWidget(self.action_btn, 0, 7)

        top_grid.setColumnStretch(0, 1)
        top_grid.setColumnStretch(1, 1)
        top_grid.setColumnStretch(3, 1)

        page_layout.addWidget(top_card, 0)

        # ---------- METRIC CARDS ----------
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)

        self.ib_label = QLabel("—")
        self.ib_label.setObjectName("metric_value")
        self.ib_sub = QLabel("Оценка ещё не сформирована")
        self.ib_sub.setObjectName("metric_subtitle")

        self.threat_label = QLabel("—")
        self.threat_label.setObjectName("metric_value")
        self.threat_sub = QLabel("Недостаточно данных")
        self.threat_sub.setObjectName("metric_subtitle")

        self.ioc_label = QLabel("0")
        self.ioc_label.setObjectName("metric_value")
        self.ioc_sub = QLabel("Совпадения по IP и доменам")
        self.ioc_sub.setObjectName("metric_subtitle")

        self.infected_label = QLabel("0")
        self.infected_label.setObjectName("metric_value")
        self.infected_sub = QLabel("Хосты с признаками компрометации")
        self.infected_sub.setObjectName("metric_subtitle")

        cards_row.addWidget(self._make_metric_card("IB Score", self.ib_label, self.ib_sub))
        cards_row.addWidget(self._make_metric_card("Уровень угрозы", self.threat_label, self.threat_sub))
        cards_row.addWidget(self._make_metric_card("IOC совпадения", self.ioc_label, self.ioc_sub))
        cards_row.addWidget(self._make_metric_card("Подозрительные хосты", self.infected_label, self.infected_sub))

        page_layout.addLayout(cards_row, 0)

        # ---------- SUMMARY ----------
        summary_card = QFrame()
        summary_card.setObjectName("summary_card")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(14, 10, 14, 10)

        self.summary_label = QLabel("Вывод: недостаточно данных для достоверной оценки")
        self.summary_label.setWordWrap(True)
        self.summary_label.setObjectName("summary_label")
        summary_layout.addWidget(self.summary_label)

        page_layout.addWidget(summary_card, 0)

        # ---------- CENTER ----------
        center_layout = QHBoxLayout()
        center_layout.setSpacing(10)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        events_card = QFrame()
        events_card.setObjectName("section_card")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(14, 12, 14, 12)
        events_layout.setSpacing(8)

        events_title = QLabel("Последние события безопасности")
        events_title.setObjectName("section_title")
        events_layout.addWidget(events_title)

        self.events_list = QListWidget()
        self.events_list.setMinimumHeight(180)
        self.events_list.setMaximumHeight(220)
        events_layout.addWidget(self.events_list)

        left_layout.addWidget(events_card, 0)

        log_card = QFrame()
        log_card.setObjectName("section_card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(14, 12, 14, 12)
        log_layout.setSpacing(8)

        log_top = QHBoxLayout()
        log_title = QLabel("Живой лог")
        log_title.setObjectName("section_title")
        log_top.addWidget(log_title)
        log_top.addStretch()

        from PyQt6.QtWidgets import QCheckBox
        self.debug_checkbox = QCheckBox("Показывать DEBUG")
        self.debug_checkbox.stateChanged.connect(self.rebuild_visible_log)
        log_top.addWidget(self.debug_checkbox)
        log_layout.addLayout(log_top)

        self.log_buffer = []
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMinimumHeight(120)
        self.log_area.setMaximumHeight(150)
        log_layout.addWidget(self.log_area)

        left_layout.addWidget(log_card, 0)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        threats_card = QFrame()
        threats_card.setObjectName("section_card")
        threats_layout = QVBoxLayout(threats_card)
        threats_layout.setContentsMargins(14, 12, 14, 12)
        threats_layout.setSpacing(8)

        threats_title = QLabel("Топ угроз по IP")
        threats_title.setObjectName("section_title")
        threats_layout.addWidget(threats_title)

        self.stats_list = QListWidget()
        self.stats_list.setMinimumHeight(120)
        self.stats_list.setMaximumHeight(150)
        threats_layout.addWidget(self.stats_list)

        right_layout.addWidget(threats_card, 0)

        graph_card = QFrame()
        graph_card.setObjectName("section_card")
        graph_layout = QVBoxLayout(graph_card)
        graph_layout.setContentsMargins(14, 12, 14, 12)
        graph_layout.setSpacing(8)

        self.plot = PlotWidget("Метрики в реальном времени")
        self.plot.setMinimumHeight(240)
        self.plot.setMaximumHeight(280)
        graph_layout.addWidget(self.plot)

        right_layout.addWidget(graph_card, 1)

        center_layout.addWidget(left_widget, 3)
        center_layout.addWidget(right_widget, 2)

        page_layout.addLayout(center_layout, 1)
        return page

    def _build_pcap_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("PCAP analysis")
        title.setObjectName("page_title")
        layout.addWidget(title)

        desc = QLabel("Запуск offline-анализа PCAP с выводом логов и ключевых результатов.")
        desc.setObjectName("page_subtitle")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        action_card = QFrame()
        action_card.setObjectName("panel_card")
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(14, 14, 14, 14)
        self.pcap_btn = QPushButton("Выбрать PCAP файл")
        self.pcap_btn.clicked.connect(self.open_pcap)
        action_layout.addWidget(self.pcap_btn)
        self.open_main_btn = QPushButton("Перейти на dashboard")
        self.open_main_btn.clicked.connect(lambda: self.switch_page(0))
        action_layout.addWidget(self.open_main_btn)
        layout.addWidget(action_card)

        self.pcap_state_label = QLabel("Состояние: ожидание файла")
        layout.addWidget(self.pcap_state_label)

        body = QHBoxLayout()
        self.pcap_stats_list = QListWidget()
        body.addWidget(self.pcap_stats_list, 1)
        self.pcap_log_area = QTextEdit()
        self.pcap_log_area.setReadOnly(True)
        body.addWidget(self.pcap_log_area, 2)
        layout.addLayout(body, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Settings / Profile")
        title.setObjectName("page_title")
        layout.addWidget(title)

        desc = QLabel("Управление активным профилем, sampling и параметрами ML-модуля.")
        desc.setObjectName("page_subtitle")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        info_card = QFrame()
        info_card.setObjectName("panel_card")
        info_layout = QGridLayout(info_card)
        info_layout.setContentsMargins(14, 14, 14, 14)
        info_layout.setHorizontalSpacing(20)
        info_layout.setVerticalSpacing(10)

        self.profile_name_lbl = QLabel("Профиль: —")
        self.sample_factor_lbl = QLabel("Sampling: —")
        self.ml_status_lbl = QLabel("ML: —")
        self.ioc_count_lbl = QLabel("IOC: —")

        info_layout.addWidget(self.profile_name_lbl, 0, 0)
        info_layout.addWidget(self.sample_factor_lbl, 0, 1)
        info_layout.addWidget(self.ml_status_lbl, 1, 0)
        info_layout.addWidget(self.ioc_count_lbl, 1, 1)
        layout.addWidget(info_card)

        self.settings_page_btn = QPushButton("Открыть диалог настроек")
        self.settings_page_btn.clicked.connect(self.open_settings)
        layout.addWidget(self.settings_page_btn)
        layout.addStretch(1)
        return page

    def _build_sessions_page(self):
        layout = QHBoxLayout(self.sessions_page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        left_card = QFrame()
        left_card.setObjectName("panel_card")
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(14, 14, 14, 14)
        left_layout.setSpacing(10)

        sessions_title = QLabel("История сессий")
        sessions_title.setObjectName("section_title")
        left_layout.addWidget(sessions_title)

        self.sessions_list = QListWidget()
        self.sessions_list.itemClicked.connect(self.show_session_details)
        left_layout.addWidget(self.sessions_list)

        self.refresh_sessions_btn = QPushButton("Обновить список")
        self.refresh_sessions_btn.clicked.connect(self.load_sessions)
        left_layout.addWidget(self.refresh_sessions_btn)

        right_card = QFrame()
        right_card.setObjectName("panel_card")
        right_layout = QVBoxLayout(right_card)
        right_layout.setContentsMargins(14, 14, 14, 14)
        right_layout.setSpacing(10)

        details_title = QLabel("Детали выбранной сессии")
        details_title.setObjectName("section_title")
        right_layout.addWidget(details_title)

        self.session_details = QTextEdit()
        self.session_details.setReadOnly(True)
        right_layout.addWidget(self.session_details)

        self.open_report_btn = QPushButton("Открыть HTML-отчёт")
        self.open_report_btn.clicked.connect(self.open_selected_session_report)
        right_layout.addWidget(self.open_report_btn)

        layout.addWidget(left_card, 1)
        layout.addWidget(right_card, 2)
        self.load_sessions()

    # ---------- helpers ----------
    def _refresh_widget_style(self, widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def _plain_log(self, msg: str) -> str:
        text = re.sub(r"<[^>]+>", "", msg)
        return html.unescape(text).strip()

    def _severity_color(self, severity: str) -> QColor:
        severity = severity.lower()
        if severity == "malicious":
            return QColor("#fee2e2")
        if severity == "suspicious":
            return QColor("#fef3c7")
        if severity == "anomaly":
            return QColor("#dbeafe")
        if severity == "ioc":
            return QColor("#fde68a")
        if severity == "incident":
            return QColor("#ffe4e6")
        return QColor("#f8fafc")

    def _add_event_row(self, severity: str, src: str, dst: str, reason: str) -> None:
        if self.events_table.rowCount() >= self.max_event_rows:
            self.events_table.removeRow(self.events_table.rowCount() - 1)

        self.events_table.insertRow(0)
        now = datetime.now().strftime("%H:%M:%S")
        values = [now, severity.upper(), src, dst, reason]
        color = self._severity_color(severity)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setBackground(color)
            self.events_table.setItem(0, col, item)

    def _ingest_security_event(self, msg: str) -> None:
        plain = self._plain_log(msg)

        verdict = re.search(r"\[VERDICT\]\s+(\w+)\s+\|\s+([^ ]+)\s+->\s+([^ ]+)\s+\|.*?reasons:\s*(.+)$", plain)
        if verdict:
            severity, src, dst, reason = verdict.groups()
            self._add_event_row(severity.lower(), src, dst, reason)
            self.threat_counter[src] += 1
            return

        incident = re.search(r"\[INCIDENT\]\s+(\w+)\s+\|\s+host=([^|]+)\s+\|\s+verdict=([^|]+)", plain)
        if incident:
            sev, host, verdict_level = incident.groups()
            self._add_event_row("incident", host.strip(), "—", f"incident verdict={verdict_level.strip()}")
            self.threat_counter[host.strip()] += 1
            return

        ioc = re.search(r"\[IOC(?: DOMAIN)? MATCH\]\s+([^ ]+)\s+->\s+([^| ]+).*$", plain)
        if ioc:
            src, dst = ioc.groups()
            self._add_event_row("ioc", src, dst, "IOC match")
            self.threat_counter[src] += 1

    def render_log_history(self) -> None:
        show_debug = self.debug_checkbox.isChecked()
        self.log_area.clear()
        for msg in self.log_history:
            plain = self._plain_log(msg)
            if not show_debug and plain.startswith("[DEBUG]"):
                continue
            self.log_area.append(msg)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    # -------- data / UI refresh --------
    def load_interfaces_to_combo(self):
        self.iface_combo.clear()
        interfaces = self.engine.list_interfaces()
        if not interfaces:
            self.iface_combo.addItem("Интерфейсы не найдены", None)
            return

        self.iface_combo.addItem("Автовыбор", None)
        for item in interfaces:
            text = item["label"]
            if item.get("ip"):
                text += f" | IP: {item['ip']}"
            data_value = item.get("name") or item.get("description") or item["label"]
            self.iface_combo.addItem(text, data_value)

    def update_top_ips(self) -> None:
        self.stats_list.clear()
        merged = Counter(self.threat_counter)
        merged.update(self.engine.attacker_stats)
        if not merged:
            self.stats_list.addItem("Пока нет значимых событий")
            return
        for ip, count in merged.most_common(10):
            self.stats_list.addItem(f"{ip} — {count} событий")

    def update_stats_display(self) -> None:
        self.pcap_stats_list.clear()
        merged = Counter(self.threat_counter)
        merged.update(self.engine.attacker_stats)
        for ip, count in merged.most_common(10):
            line = f"{ip} → {count} событий"
            self.pcap_stats_list.addItem(line)
        self.update_top_ips()

    def set_status_text(self, text: str) -> None:
        status_text = text if text.startswith("Статус:") else f"Статус: {text}"

        if hasattr(self, "status_label"):
            self.status_label.setText(status_text)

        if hasattr(self, "header_status"):
            self.header_status.setText(status_text)

        if hasattr(self, "pcap_state_label"):
            clean_text = text.replace("Статус: ", "")
            self.pcap_state_label.setText(f"Состояние: {clean_text}")

    def update_assessment_panel(self) -> None:
        assessment = getattr(self.engine, "last_assessment", None)
        ready = bool(getattr(self.engine, "assessment_ready", False))

        if not ready or not assessment:
            self.ib_label.setText("—")
            self.ib_sub.setText("Оценка ещё не сформирована")

            self.threat_label.setText("—")
            self.threat_sub.setText("Недостаточно данных")

            self.summary_label.setText("Вывод: недостаточно данных для достоверной оценки")
        else:
            score = assessment["overall_score"]
            self.ib_label.setText(f"{score}")
            self.ib_sub.setText(assessment["security_level"])

            self.threat_label.setText(assessment["threat_level"])
            self.threat_sub.setText(
                f"Инцидент: {assessment['incident_probability']} | Достоверность: {assessment['confidence']}"
            )

            self.summary_label.setText(f"Вывод: {assessment['summary']}")

        ioc_count = len(getattr(self.engine, "ioc_seen", set())) + len(getattr(self.engine, "domain_ioc_seen", set()))
        infected_count = len(getattr(self.engine, "reported_infected_hosts", set()))

        self.ioc_label.setText(str(ioc_count))
        self.infected_label.setText(str(infected_count))

    def refresh_graphs(self):
        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        anom_rate = anom / seen
        self.plot.push(pps_eff=pps_eff, anom_rate=anom_rate)

    def append_log(self, msg: str) -> None:
        self.log_buffer.append(msg)

        if hasattr(self, "pcap_log_area"):
            self.pcap_log_area.append(msg)
            self.pcap_log_area.verticalScrollBar().setValue(
                self.pcap_log_area.verticalScrollBar().maximum()
            )

        self._append_to_events_if_needed(msg)
        self.rebuild_visible_log()

    def rebuild_visible_log(self):
        if not hasattr(self, "log_area"):
            return

        show_debug = hasattr(self, "debug_checkbox") and self.debug_checkbox.isChecked()

        self.log_area.clear()
        for msg in self.log_buffer[-500:]:
            if "[DEBUG]" in msg and not show_debug:
                continue
            self.log_area.append(msg)

        self.log_area.verticalScrollBar().setValue(
            self.log_area.verticalScrollBar().maximum()
        )

    def _append_to_events_if_needed(self, msg: str):
        if not hasattr(self, "events_list"):
            return

        important_tags = ["[VERDICT]", "[INCIDENT]", "[IOC]", "[SYSTEM]"]
        if any(tag in msg for tag in important_tags):
            plain = msg.replace("<b style='color:#89dceb;'>", "").replace("</b>", "")
            plain = plain.replace("<b style='color:#a6e3a1;'>", "")
            plain = plain.replace("<b style='color:#f38ba8;'>", "")
            plain = plain.replace("<span style='color:#f38ba8;'>", "")
            plain = plain.replace("<span style='color:#f9e2af;'>", "")
            plain = plain.replace("</span>", "")
            self.events_list.insertItem(0, plain)

            while self.events_list.count() > 100:
                self.events_list.takeItem(self.events_list.count() - 1)

    # -------- sessions --------
    def load_sessions(self):
        init_db()
        self.sessions_list.clear()
        sessions = get_sessions()
        if not sessions:
            self.sessions_list.addItem("Сессий пока нет")
            return

        for s in sessions:
            session_id, started, duration, profile, iface, score = s
            started = started or "-"
            profile = profile or "-"
            iface = iface or "-"
            duration = duration or 0
            score = score if score is not None else "-"
            text = f"{started} | {profile} | {iface} | {duration}s | IB={score}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, session_id)
            self.sessions_list.addItem(item)

    def show_session_details(self, item):
        session_id = item.data(Qt.ItemDataRole.UserRole)
        if session_id is None:
            self.session_details.setText("Нет данных.")
            return

        s = get_session_by_id(session_id)
        if not s:
            self.session_details.setText("Сессия не найдена.")
            return

        text = f"""
ID: {s[0]}
Start: {s[1]}
Stop: {s[2]}
Duration: {s[3]} sec

Profile: {s[4]}
Interface: {s[5]}

Packets: {s[6]}
Anomalies: {s[7]}
Incidents: {s[8]}
IB Score: {s[9]}

Summary:
{s[10] or '-'}

Report path:
{s[11] or '-'}
"""
        self.session_details.setText(text)

    def open_selected_session_report(self):
        item = self.sessions_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Нет выбора", "Сначала выберите сессию.")
            return

        session_id = item.data(Qt.ItemDataRole.UserRole)
        if session_id is None:
            QMessageBox.warning(self, "Нет данных", "У этой строки нет данных сессии.")
            return

        s = get_session_by_id(session_id)
        if not s:
            QMessageBox.warning(self, "Ошибка", "Сессия не найдена.")
            return

        report_path = s[11]
        if not report_path:
            QMessageBox.information(self, "Нет отчёта", "Для этой сессии HTML-отчёт ещё не сохранён.")
            return
        if not os.path.exists(report_path):
            QMessageBox.warning(self, "Файл не найден", f"HTML-отчёт не найден:\n{report_path}")
            return
        webbrowser.open(report_path)

    # -------- profile --------
    def apply_profile_on_startup(self) -> None:
        try:
            pm = ProfileManager()
            active_name = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active_name)
            self.engine.apply_profile(prof.data, profile_name=prof.filename.replace(".json", ""))
            self.append_log(f"<b style='color:#2563eb;'>[PROFILE] Применён: {prof.name} ({prof.filename})</b>")
            self.update_assessment_panel()
        except Exception as e:
            self.append_log(f"<span style='color:#dc2626;'>[PROFILE] Ошибка: {type(e).__name__}: {e}</span>")

    def open_settings(self):
        dlg = SettingsDialog(self, self.engine)
        dlg.exec()
        try:
            pm = ProfileManager()
            active = pm.get_active_filename() or "default.json"
            pr = pm.load_profile(active)
            self.engine.apply_profile(pr.data, profile_name=Path(active).stem)
            self.append_log(f"<b style='color:#2563eb;'>[PROFILE] Активный: {pr.name} ({active})</b>")
            self.update_assessment_panel()
        except Exception as e:
            self.append_log(f"<span style='color:#dc2626;'>[PROFILE ERROR] {type(e).__name__}: {e}</span>")

    # -------- worker --------
    def start_worker(self, mode: str, pcap_path: str | None = None) -> None:
        self.worker = CaptureWorker(self.engine, mode=mode, pcap_path=pcap_path)
        self.worker.message.connect(self.on_worker_message)
        self.worker.finished_signal.connect(self.on_worker_finished)
        self.worker.start()

    def on_worker_message(self, msg: str) -> None:
        self.append_log(msg)
        self.update_assessment_panel()
        self.update_stats_display()

    def on_worker_finished(self) -> None:
        self.is_monitoring = False
        self.current_mode = "idle"

        self.action_btn.setEnabled(True)
        self.pcap_btn.setEnabled(True)
        self.settings_btn.setEnabled(True)
        self.settings_page_btn.setEnabled(True)

        self.action_btn.setText("Запустить мониторинг")
        self.action_btn.setObjectName("primary_btn")
        self._refresh_widget_style(self.action_btn)

        self.set_status_text("Статус: ожидание запуска")
        self.update_assessment_panel()
        self.append_log("<b style='color:#2563eb;'>[SYSTEM] Мониторинг / анализ остановлен.</b>")

    # -------- actions --------
    def open_pcap(self) -> None:
        if self.is_monitoring:
            QMessageBox.information(self, "PCAP", "Сначала остановите текущий мониторинг.")
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
        self.is_monitoring = True
        self.current_mode = "pcap"

        self.action_btn.setEnabled(False)
        self.settings_btn.setEnabled(False)
        self.pcap_btn.setEnabled(False)
        self.settings_page_btn.setEnabled(False)

        self.set_status_text("Статус: offline-анализ PCAP")
        self.append_log(f"<b style='color:#2563eb;'>[SYSTEM] Запуск PCAP анализа: {file_path}</b>")
        self.start_worker(mode="pcap", pcap_path=file_path)

    def toggle_monitoring(self) -> None:
        if not self.is_monitoring:
            self.switch_page(0)
            self.is_monitoring = True
            self.current_mode = "live"
            self.action_btn.setText("Остановить мониторинг")
            self.action_btn.setObjectName("stop_mode")
            self._refresh_widget_style(self.action_btn)

            self.settings_btn.setEnabled(False)
            self.pcap_btn.setEnabled(False)
            self.settings_page_btn.setEnabled(False)

            self.set_status_text("Статус: live-мониторинг")
            self.update_assessment_panel()
            self.append_log("<b style='color:#16a34a;'>[SYSTEM] Мониторинг запущен...</b>")

            selected_iface = self.iface_combo.currentData()
            self.engine.set_selected_interface(selected_iface)
            self.start_worker(mode="live")
        else:
            self.append_log("<b style='color:#dc2626;'>[SYSTEM] Остановка мониторинга...</b>")
            self.action_btn.setEnabled(False)
            self.engine.stop_capture()

    def _make_metric_card(self, title: str, value_label: QLabel, subtitle_label: QLabel) -> QFrame:
        card = QFrame()
        card.setObjectName("metric_card")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setObjectName("metric_title")

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(subtitle_label)

        return card

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.apply_responsive_layout()

    def apply_responsive_layout(self):
        w = self.width()

        if hasattr(self, "dashboard_splitter"):
            if w < 1500:
                self.dashboard_splitter.setOrientation(Qt.Orientation.Vertical)
                self.iface_combo.setMinimumWidth(160)
            else:
                self.dashboard_splitter.setOrientation(Qt.Orientation.Horizontal)
                self.iface_combo.setMinimumWidth(220)

    def export_report(self):
        if not hasattr(self.engine, "current_session") or self.engine.current_session.started_at is None:
            QMessageBox.warning(self, "Нет данных", "Сначала выполните мониторинг или анализ.")
            return
        if self.is_monitoring:
            QMessageBox.warning(self, "Мониторинг активен", "Сначала остановите мониторинг, затем экспортируйте отчёт.")
            return

        html_report = build_html_report(self.engine.current_session, self.engine)
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчёт",
            "network_report.html",
            "HTML Files (*.html)",
        )
        if not file_path:
            return

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_report)

        session_id = get_last_session_id()
        if session_id is not None:
            update_session_report_path(session_id, file_path)
        self.load_sessions()
        QMessageBox.information(self, "Готово", "Отчёт успешно сохранён.")

    def switch_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        nav_buttons = [self.main_nav_btn, self.pcap_nav_btn, self.settings_nav_btn, self.sessions_nav_btn]
        for i, btn in enumerate(nav_buttons):
            btn.setChecked(i == index)
            btn.setObjectName("nav_btn_active" if i == index else "nav_btn")
            self._refresh_widget_style(btn)

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
