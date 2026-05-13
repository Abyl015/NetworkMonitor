from __future__ import annotations

import html
import json
import os
import re
import sys
import time
import webbrowser
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import QDateTime, Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
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
    QCheckBox,
    QDateTimeEdit,
    QLineEdit,
    QListWidget,
    QScrollArea,
    QSplitter,
    QSizePolicy, QListWidgetItem, QTableWidget, QTableWidgetItem,
)

from NetworkMonitor.app.plot_widget import PlotWidget
from NetworkMonitor.app.settings_dialog import SettingsDialog
from NetworkMonitor.app.worker import CaptureWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.core.report_builder import build_html_report, build_html_report_for_session
from NetworkMonitor.storage.database import (
    get_last_session_id,
    get_alert_types,
    get_previous_session_record,
    get_session_record,
    query_alerts,
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
        self.max_log_messages = 500
        self._live_ui_dirty = False
        self._last_live_ui_flush = 0.0

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

        self.live_ui_timer = QTimer(self)
        self.live_ui_timer.setInterval(500)
        self.live_ui_timer.timeout.connect(self.flush_live_ui_updates)
        self.live_ui_timer.start()

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

        nav_title = QLabel("NETGUARD")
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

        self.alerts_nav_btn = QPushButton("Alerts")
        self.alerts_nav_btn.setCheckable(True)
        self.alerts_nav_btn.clicked.connect(lambda: self.switch_page(4))
        nav_layout.addWidget(self.alerts_nav_btn)

        nav_layout.addStretch(1)

        self.pages = QStackedWidget()
        self.pages.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.pages.addWidget(self._build_main_page())
        self.pages.addWidget(self._build_pcap_page())
        self.pages.addWidget(self._build_settings_page())

        self.sessions_page = QWidget()
        self._build_sessions_page()
        self.pages.addWidget(self.sessions_page)

        self.alerts_page = self._build_alerts_page()
        self.pages.addWidget(self.alerts_page)

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
        summary_layout.setContentsMargins(14, 12, 14, 12)
        summary_layout.setSpacing(10)

        assessment_top = QHBoxLayout()
        assessment_top.setSpacing(10)

        score_panel = QFrame()
        score_panel.setObjectName("assessment_score_panel")
        score_layout = QVBoxLayout(score_panel)
        score_layout.setContentsMargins(14, 12, 14, 12)
        score_layout.setSpacing(4)

        score_title = QLabel("IB Score")
        score_title.setObjectName("assessment_fact_label")
        self.assessment_score_value = QLabel("N/A")
        self.assessment_score_value.setObjectName("assessment_score_value")
        self.assessment_score_level = QLabel("Недостаточно данных")
        self.assessment_score_level.setWordWrap(True)
        self.assessment_score_level.setObjectName("assessment_score_level")
        score_layout.addWidget(score_title)
        score_layout.addWidget(self.assessment_score_value)
        score_layout.addWidget(self.assessment_score_level)
        assessment_top.addWidget(score_panel, 2)

        facts_panel = QFrame()
        facts_panel.setObjectName("assessment_facts_panel")
        facts_grid = QGridLayout(facts_panel)
        facts_grid.setContentsMargins(14, 12, 14, 12)
        facts_grid.setHorizontalSpacing(16)
        facts_grid.setVerticalSpacing(8)

        self.assessment_threat_value = QLabel("N/A")
        self.assessment_incident_value = QLabel("N/A")
        self.assessment_confidence_value = QLabel("N/A")
        fact_items = [
            ("Угроза", self.assessment_threat_value),
            ("Инцидент", self.assessment_incident_value),
            ("Достоверность", self.assessment_confidence_value),
        ]
        for row, (label_text, value_label) in enumerate(fact_items):
            label = QLabel(label_text)
            label.setObjectName("assessment_fact_label")
            value_label.setObjectName("assessment_fact_value")
            value_label.setWordWrap(True)
            facts_grid.addWidget(label, row, 0)
            facts_grid.addWidget(value_label, row, 1)
        facts_grid.setColumnStretch(1, 1)
        assessment_top.addWidget(facts_panel, 3)
        summary_layout.addLayout(assessment_top)

        self.summary_label = QLabel("Вывод: недостаточно данных для достоверной оценки")
        self.summary_label.setWordWrap(True)
        self.summary_label.setObjectName("summary_label")
        summary_layout.addWidget(self.summary_label)

        analysis_layout = QHBoxLayout()
        analysis_layout.setSpacing(10)

        risk_panel = QFrame()
        risk_panel.setObjectName("assessment_subpanel")
        risk_layout = QVBoxLayout(risk_panel)
        risk_layout.setContentsMargins(12, 10, 12, 10)
        risk_layout.setSpacing(5)
        risk_title = QLabel("Risk breakdown")
        risk_title.setObjectName("assessment_subtitle")
        risk_layout.addWidget(risk_title)
        self.risk_labels: list[QLabel] = []
        for _ in range(4):
            lbl = QLabel("N/A")
            lbl.setWordWrap(True)
            lbl.setObjectName("risk_row")
            self.risk_labels.append(lbl)
            risk_layout.addWidget(lbl)
        analysis_layout.addWidget(risk_panel, 1)

        findings_panel = QFrame()
        findings_panel.setObjectName("assessment_subpanel")
        findings_layout = QVBoxLayout(findings_panel)
        findings_layout.setContentsMargins(12, 10, 12, 10)
        findings_layout.setSpacing(5)
        findings_title = QLabel("Key findings")
        findings_title.setObjectName("assessment_subtitle")
        findings_layout.addWidget(findings_title)
        self.finding_labels: list[QLabel] = []
        for _ in range(4):
            lbl = QLabel("N/A")
            lbl.setWordWrap(True)
            lbl.setObjectName("finding_item")
            self.finding_labels.append(lbl)
            findings_layout.addWidget(lbl)
        analysis_layout.addWidget(findings_panel, 1)
        summary_layout.addLayout(analysis_layout)

        compare_card = QFrame()
        compare_card.setObjectName("comparison_card")
        compare_layout = QVBoxLayout(compare_card)
        compare_layout.setContentsMargins(12, 8, 12, 8)
        self.assessment_compare_label = QLabel("Нет данных для сравнения")
        self.assessment_compare_label.setWordWrap(True)
        self.assessment_compare_label.setObjectName("comparison_text")
        compare_layout.addWidget(self.assessment_compare_label)
        summary_layout.addWidget(compare_card)

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
        self.log_area.document().setMaximumBlockCount(self.max_log_messages)
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
        self.pcap_log_area.document().setMaximumBlockCount(self.max_log_messages)
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

        self.open_report_btn = QPushButton("Открыть / сгенерировать HTML-отчет")
        self.open_report_btn.clicked.connect(self.open_selected_session_report)
        right_layout.addWidget(self.open_report_btn)

        layout.addWidget(left_card, 1)
        layout.addWidget(right_card, 2)
        self.load_sessions()

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Alerts history")
        title.setObjectName("page_title")
        layout.addWidget(title)

        filters_card = QFrame()
        filters_card.setObjectName("panel_card")
        filters = QGridLayout(filters_card)
        filters.setContentsMargins(14, 14, 14, 14)
        filters.setHorizontalSpacing(10)
        filters.setVerticalSpacing(8)

        self.alert_session_filter = QComboBox()
        self.alert_type_filter = QComboBox()
        self.alert_verdict_filter = QComboBox()
        self.alert_search_input = QLineEdit()
        self.alert_search_input.setPlaceholderText("IP, текст причины или описание")

        self.alert_period_checkbox = QCheckBox("Период")
        self.alert_from_dt = QDateTimeEdit()
        self.alert_from_dt.setCalendarPopup(True)
        self.alert_to_dt = QDateTimeEdit()
        self.alert_to_dt.setCalendarPopup(True)

        now = datetime.now()
        self.alert_from_dt.setDateTime(QDateTime(now - timedelta(days=7)))
        self.alert_to_dt.setDateTime(QDateTime(now))
        self.alert_from_dt.setEnabled(False)
        self.alert_to_dt.setEnabled(False)
        self.alert_period_checkbox.stateChanged.connect(self._toggle_alert_period_filters)

        self.alert_refresh_btn = QPushButton("Обновить")
        self.alert_refresh_btn.clicked.connect(self.load_alerts_history)
        self.alert_reset_btn = QPushButton("Сбросить")
        self.alert_reset_btn.clicked.connect(self.reset_alert_filters)

        filters.addWidget(QLabel("Session"), 0, 0)
        filters.addWidget(self.alert_session_filter, 0, 1)
        filters.addWidget(QLabel("Type"), 0, 2)
        filters.addWidget(self.alert_type_filter, 0, 3)
        filters.addWidget(QLabel("Verdict"), 0, 4)
        filters.addWidget(self.alert_verdict_filter, 0, 5)
        filters.addWidget(self.alert_period_checkbox, 1, 0)
        filters.addWidget(self.alert_from_dt, 1, 1)
        filters.addWidget(self.alert_to_dt, 1, 2)
        filters.addWidget(QLabel("Search"), 1, 3)
        filters.addWidget(self.alert_search_input, 1, 4, 1, 2)
        filters.addWidget(self.alert_refresh_btn, 0, 6)
        filters.addWidget(self.alert_reset_btn, 1, 6)
        filters.setColumnStretch(4, 1)
        layout.addWidget(filters_card, 0)

        body = QHBoxLayout()
        body.setSpacing(12)

        table_card = QFrame()
        table_card.setObjectName("panel_card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(14, 14, 14, 14)
        table_layout.setSpacing(8)

        self.alerts_count_label = QLabel("Alerts: 0")
        self.alerts_count_label.setObjectName("section_title")
        table_layout.addWidget(self.alerts_count_label)

        self.alerts_table = QTableWidget(0, 5)
        self.alerts_table.setHorizontalHeaderLabels(["ID", "Time", "Session", "Type", "Description"])
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        self.alerts_table.itemSelectionChanged.connect(self.show_selected_alert_details)
        table_layout.addWidget(self.alerts_table, 1)

        details_card = QFrame()
        details_card.setObjectName("panel_card")
        details_layout = QVBoxLayout(details_card)
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(8)

        details_title = QLabel("Детализация события")
        details_title.setObjectName("section_title")
        details_layout.addWidget(details_title)

        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        details_layout.addWidget(self.alert_details, 1)

        body.addWidget(table_card, 3)
        body.addWidget(details_card, 2)
        layout.addLayout(body, 1)

        self.alert_rows: list[tuple] = []
        self.populate_alert_filters()
        self.load_alerts_history()
        return page

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

    def _parse_json_value(self, value, fallback):
        if not value:
            return fallback
        if isinstance(value, (dict, list)):
            return value
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return fallback
        return parsed if parsed is not None else fallback

    def _format_delta(self, current, previous) -> str:
        if current is None or previous is None:
            return "N/A"
        delta = current - previous
        sign = "+" if delta > 0 else ""
        return f"{sign}{delta}"

    def _assessment_text(self, assessment: dict | None) -> str:
        if not assessment:
            return "Risk breakdown: N/A\nFindings: N/A"

        components = assessment.get("components") or {}
        findings = assessment.get("findings") or []
        lines = ["Risk breakdown:"]
        if components:
            for name, value in components.items():
                lines.append(f"- {name}: {value}")
        else:
            lines.append("- N/A")

        lines.append("")
        lines.append("Key findings:")
        if findings:
            for finding in findings[:6]:
                lines.append(f"- {finding}")
        else:
            lines.append("- N/A")
        return "\n".join(lines)

    def _stored_assessment_text(self, session_data: dict) -> str:
        components = self._parse_json_value(session_data.get("risk_components_json"), {})
        findings = self._parse_json_value(session_data.get("findings_json"), [])
        assessment = {
            "components": components if isinstance(components, dict) else {},
            "findings": findings if isinstance(findings, list) else [],
        }
        return self._assessment_text(assessment)

    def _comparison_text(self, current: dict, previous: dict | None) -> str:
        if not previous:
            return "Сравнение с предыдущей сессией: N/A"

        return (
            f"Сравнение с предыдущей сессией #{previous.get('id')}: "
            f"IB Score {self._format_delta(current.get('final_ib_score'), previous.get('final_ib_score'))}; "
            f"Incidents {self._format_delta(current.get('total_incidents'), previous.get('total_incidents'))}; "
            f"Anomalies {self._format_delta(current.get('total_anomalies'), previous.get('total_anomalies'))}; "
            f"IOC {self._format_delta(current.get('total_ioc_matches'), previous.get('total_ioc_matches'))}"
        )

    def _set_label_list(self, labels: list[QLabel], values: list[str], empty_text: str) -> None:
        visible_values = values[:len(labels)] if values else [empty_text]
        for idx, label in enumerate(labels):
            if idx < len(visible_values):
                label.setText(visible_values[idx])
                label.setVisible(True)
            else:
                label.setText("")
                label.setVisible(False)

    def _set_dashboard_empty_assessment(self) -> None:
        self.assessment_score_value.setText("N/A")
        self.assessment_score_level.setText("Недостаточно данных")
        self.assessment_threat_value.setText("N/A")
        self.assessment_incident_value.setText("N/A")
        self.assessment_confidence_value.setText("N/A")
        self.summary_label.setText("Вывод: недостаточно данных для достоверной оценки")
        self._set_label_list(self.risk_labels, [], "N/A")
        self._set_label_list(self.finding_labels, [], "Недостаточно данных")

    def _set_dashboard_assessment_details(self, assessment: dict) -> None:
        components = assessment.get("components") or {}
        risk_values = [f"{name}: {value}" for name, value in components.items()]
        self._set_label_list(self.risk_labels, risk_values, "N/A")

        findings = assessment.get("findings") or []
        finding_values = [str(item) for item in findings[:4]]
        self._set_label_list(self.finding_labels, finding_values, "Нет ключевых findings")

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

    def flush_live_ui_updates(self) -> None:
        if not self._live_ui_dirty:
            return

        self._live_ui_dirty = False
        self._last_live_ui_flush = time.monotonic()
        self.update_assessment_panel()
        self.update_stats_display()

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

            self._set_dashboard_empty_assessment()
        else:
            score = assessment["overall_score"]
            self.ib_label.setText(f"{score}")
            self.ib_sub.setText(assessment["security_level"])
            self.assessment_score_value.setText(f"{score}")
            self.assessment_score_level.setText(assessment["security_level"])

            self.threat_label.setText(assessment["threat_level"])
            self.threat_sub.setText(
                f"Инцидент: {assessment['incident_probability']} | Достоверность: {assessment['confidence']}"
            )
            self.assessment_threat_value.setText(assessment["threat_level"])
            self.assessment_incident_value.setText(assessment["incident_probability"])
            self.assessment_confidence_value.setText(assessment["confidence"])

            self.summary_label.setText(f"Вывод: {assessment['summary']}")
            self._set_dashboard_assessment_details(assessment)

        ioc_count = len(getattr(self.engine, "ioc_seen", set())) + len(getattr(self.engine, "domain_ioc_seen", set()))
        infected_count = len(getattr(self.engine, "reported_infected_hosts", set()))

        self.ioc_label.setText(str(ioc_count))
        self.infected_label.setText(str(infected_count))
        self._update_dashboard_comparison()

    def _update_dashboard_comparison(self):
        session_id = getattr(self.engine, "current_session_db_id", None)
        if not session_id:
            self.assessment_compare_label.setText("Нет данных для сравнения")
            return

        current = {
            "final_ib_score": getattr(self.engine, "last_ib_score", None),
            "total_incidents": len(getattr(self.engine, "incidents", {})),
            "total_anomalies": getattr(self.engine, "total_anom", None),
            "total_ioc_matches": len(getattr(self.engine, "ioc_seen", set())) + len(getattr(self.engine, "domain_ioc_seen", set())),
        }
        previous = get_previous_session_record(session_id)
        if not previous:
            self.assessment_compare_label.setText("Нет данных для сравнения")
            return
        self.assessment_compare_label.setText(self._comparison_text(current, previous))

    def refresh_graphs(self):
        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        anom_rate = anom / seen
        self.plot.push(pps_eff=pps_eff, anom_rate=anom_rate)

    def append_log(self, msg: str) -> None:
        self.log_buffer.append(msg)
        if len(self.log_buffer) > self.max_log_messages:
            del self.log_buffer[: len(self.log_buffer) - self.max_log_messages]

        if hasattr(self, "pcap_log_area"):
            self.pcap_log_area.append(msg)
            self.pcap_log_area.verticalScrollBar().setValue(
                self.pcap_log_area.verticalScrollBar().maximum()
            )

        self._append_to_events_if_needed(msg)
        if self._is_log_message_visible(msg):
            self.log_area.append(msg)
            self.log_area.verticalScrollBar().setValue(
                self.log_area.verticalScrollBar().maximum()
            )

    def _is_log_message_visible(self, msg: str) -> bool:
        show_debug = hasattr(self, "debug_checkbox") and self.debug_checkbox.isChecked()
        return show_debug or "[DEBUG]" not in msg

    def rebuild_visible_log(self):
        if not hasattr(self, "log_area"):
            return

        self.log_area.clear()
        for msg in self.log_buffer[-self.max_log_messages:]:
            if not self._is_log_message_visible(msg):
                continue
            self.log_area.append(msg)

        self.log_area.verticalScrollBar().setValue(
            self.log_area.verticalScrollBar().maximum()
        )

    def _append_to_events_if_needed(self, msg: str):
        if not hasattr(self, "events_list"):
            return

        important_tags = ["[VERDICT]", "[INCIDENT]", "[IOC]", "[IOC MATCH]", "[IOC DOMAIN MATCH]", "[SYSTEM]"]
        if any(tag in msg for tag in important_tags):
            plain = self._plain_log(msg)
            self.events_list.insertItem(0, plain)

            while self.events_list.count() > 100:
                self.events_list.takeItem(self.events_list.count() - 1)

    # -------- alerts history --------
    def _toggle_alert_period_filters(self):
        enabled = self.alert_period_checkbox.isChecked()
        self.alert_from_dt.setEnabled(enabled)
        self.alert_to_dt.setEnabled(enabled)

    def populate_alert_filters(self):
        self.alert_session_filter.clear()
        self.alert_session_filter.addItem("Все сессии", None)
        for session_id, started, duration, profile, iface, score in get_sessions(limit=200):
            label = f"#{session_id} | {started or '-'} | {profile or '-'} | IB={score if score is not None else '-'}"
            self.alert_session_filter.addItem(label, session_id)

        self.alert_type_filter.clear()
        self.alert_type_filter.addItem("Все типы", None)
        for alert_type in get_alert_types():
            self.alert_type_filter.addItem(alert_type, alert_type)

        self.alert_verdict_filter.clear()
        self.alert_verdict_filter.addItem("Любой verdict", None)
        for verdict in ("malicious", "suspicious", "anomaly", "normal"):
            self.alert_verdict_filter.addItem(verdict.upper(), verdict)

    def reset_alert_filters(self):
        self.populate_alert_filters()
        self.alert_period_checkbox.setChecked(False)
        self._toggle_alert_period_filters()
        self.alert_search_input.clear()
        now = datetime.now()
        self.alert_from_dt.setDateTime(QDateTime(now - timedelta(days=7)))
        self.alert_to_dt.setDateTime(QDateTime(now))
        self.load_alerts_history()

    def _alert_filter_datetime(self, widget: QDateTimeEdit) -> str:
        return widget.dateTime().toString("yyyy-MM-dd HH:mm:ss")

    def load_alerts_history(self):
        session_id = self.alert_session_filter.currentData()
        alert_type = self.alert_type_filter.currentData()
        verdict = self.alert_verdict_filter.currentData()
        search_text = self.alert_search_input.text().strip() or None

        started_from = None
        started_to = None
        if self.alert_period_checkbox.isChecked():
            started_from = self._alert_filter_datetime(self.alert_from_dt)
            started_to = self._alert_filter_datetime(self.alert_to_dt)

        self.alert_rows = query_alerts(
            session_id=session_id,
            started_from=started_from,
            started_to=started_to,
            alert_type=alert_type,
            verdict=verdict,
            search_text=search_text,
            limit=500,
        )
        self.render_alert_rows()

    def render_alert_rows(self):
        self.alerts_table.setRowCount(0)
        self.alerts_count_label.setText(f"Alerts: {len(self.alert_rows)}")
        self.alert_details.clear()

        for row_idx, row in enumerate(self.alert_rows):
            alert_id, timestamp, session_id, alert_type, description = row
            self.alerts_table.insertRow(row_idx)
            values = [
                str(alert_id),
                timestamp or "-",
                str(session_id) if session_id is not None else "-",
                alert_type or "-",
                description or "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, row_idx)
                self.alerts_table.setItem(row_idx, col, item)

        self.alerts_table.resizeColumnsToContents()

    def _extract_alert_verdict(self, alert_type: str, description: str) -> str:
        text = description or ""
        verdict = re.search(r"verdict=([A-Za-z_]+)", text, flags=re.IGNORECASE)
        if verdict:
            return verdict.group(1).upper()

        verdict = re.search(r"\[VERDICT\]\s+([A-Za-z_]+)", text, flags=re.IGNORECASE)
        if verdict:
            return verdict.group(1).upper()

        if alert_type == "INCIDENT":
            incident = re.search(r"\|\s*verdict=([^|]+)", text, flags=re.IGNORECASE)
            if incident:
                return incident.group(1).strip().upper()
        return "-"

    def _extract_alert_ips(self, description: str) -> str:
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", description or "")
        return ", ".join(dict.fromkeys(ips)) if ips else "-"

    def show_selected_alert_details(self):
        selected = self.alerts_table.selectedItems()
        if not selected:
            self.alert_details.clear()
            return

        row_idx = selected[0].data(Qt.ItemDataRole.UserRole)
        if row_idx is None or row_idx >= len(self.alert_rows):
            self.alert_details.clear()
            return

        alert_id, timestamp, session_id, alert_type, description = self.alert_rows[row_idx]
        verdict = self._extract_alert_verdict(alert_type or "", description or "")
        ips = self._extract_alert_ips(description or "")
        session_context = ""
        if session_id is not None:
            session_data = get_session_record(session_id)
            if session_data:
                session_context = f"""

Linked session assessment:
IB Score: {session_data.get('final_ib_score') if session_data.get('final_ib_score') is not None else '-'}
IB Level: {session_data.get('final_ib_level') or '-'}
Threat Level: {session_data.get('threat_level') or '-'}
Confidence: {session_data.get('confidence') or '-'}
Summary: {session_data.get('summary_text') or '-'}
"""
        detail = f"""ID: {alert_id}
Time: {timestamp or '-'}
Session ID: {session_id if session_id is not None else '-'}
Type: {alert_type or '-'}
Verdict: {verdict}
IPs: {ips}

Description:
{description or '-'}
{session_context}
"""
        self.alert_details.setText(detail)

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

        s = get_session_record(session_id)
        if not s:
            self.session_details.setText("Сессия не найдена.")
            return

        previous = get_previous_session_record(session_id)
        comparison = self._comparison_text(s, previous)
        assessment_details = self._stored_assessment_text(s)
        text = f"""
SESSION
ID: {s.get('id')}
Start: {s.get('started_at') or '-'}
Stop: {s.get('stopped_at') or '-'}
Duration: {s.get('duration_sec') or 0} sec

Profile: {s.get('profile_name') or '-'}
Interface: {s.get('interface_name') or '-'}

SECURITY ASSESSMENT
IB Score: {s.get('final_ib_score') if s.get('final_ib_score') is not None else '-'}
IB Level: {s.get('final_ib_level') or '-'}
Threat Level: {s.get('threat_level') or '-'}
Incident Probability: {s.get('incident_probability') or '-'}
Confidence: {s.get('confidence') or '-'}
Total Risk: {s.get('total_risk') if s.get('total_risk') is not None else '-'}

Summary:
{s.get('summary_text') or '-'}

EXPLANATION
{assessment_details}

STATISTICS
Packets: {s.get('total_packets') or 0}
Anomalies: {s.get('total_anomalies') or 0}
Incidents: {s.get('total_incidents') or 0}
IOC matches: {s.get('total_ioc_matches') or 0}

COMPARISON
{comparison}

Report path:
{s.get('report_path') or '-'}
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
        if report_path and os.path.exists(report_path):
            webbrowser.open(report_path)
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить HTML-отчёт по сессии",
            f"network_session_{session_id}_report.html",
            "HTML Files (*.html)",
        )
        if not file_path:
            return

        try:
            html_report = build_html_report_for_session(session_id)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            update_session_report_path(session_id, file_path)
            self.load_sessions()
            for row in range(self.sessions_list.count()):
                refreshed_item = self.sessions_list.item(row)
                if refreshed_item.data(Qt.ItemDataRole.UserRole) == session_id:
                    self.sessions_list.setCurrentItem(refreshed_item)
                    self.show_session_details(refreshed_item)
                    break
            QMessageBox.information(self, "Готово", "HTML-отчёт по выбранной сессии сформирован.")
            webbrowser.open(file_path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Ошибка отчёта",
                f"Не удалось сформировать HTML-отчёт:\n{type(e).__name__}: {e}",
            )

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
        self._live_ui_dirty = True
        if time.monotonic() - self._last_live_ui_flush >= 0.5:
            self.flush_live_ui_updates()

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

        session_id = getattr(self.engine, "current_session_db_id", None) or get_last_session_id()
        if session_id is not None:
            update_session_report_path(session_id, file_path)
        self.load_sessions()
        QMessageBox.information(self, "Готово", "Отчёт успешно сохранён.")

    def switch_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        if index == 4 and hasattr(self, "alerts_table"):
            self.populate_alert_filters()
            self.load_alerts_history()
        nav_buttons = [
            self.main_nav_btn,
            self.pcap_nav_btn,
            self.settings_nav_btn,
            self.sessions_nav_btn,
            self.alerts_nav_btn,
        ]
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
