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

from PyQt6.QtCore import QDateTime, QSize, Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QDialog,
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
from NetworkMonitor.app.worker import CaptureWorker, EnrichmentWorker
from NetworkMonitor.config.profile_manager import ProfileManager
from NetworkMonitor.config.secrets import delete_secret, has_local_secret, has_secret, set_secret
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.core.enrichment import is_public_ip
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
        self.enrichment_worker: EnrichmentWorker | None = None
        self.is_monitoring = False
        self.current_mode = "idle"
        self.last_pcap_path: str | None = None
        self.log_history: list[str] = []
        self.threat_counter: Counter[str] = Counter()
        self.max_event_rows = 120
        self.max_log_messages = 500
        self._live_ui_dirty = False
        self._last_live_ui_flush = 0.0
        self._pending_worker_logs: list[str] = []
        self._last_stats_refresh = 0.0
        self._last_graph_refresh = 0.0
        self._force_graph_refresh = False

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

        self.sidebar_expanded_width = 220
        self.sidebar_collapsed_width = 64
        self.sidebar_collapsed = False
        self.nav_icon_size = QSize(20, 20)
        self.nav_icons_dir = Path(__file__).resolve().parents[1] / "assets" / "icons"

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(self.sidebar_expanded_width)
        self.sidebar = sidebar

        nav_layout = QVBoxLayout(sidebar)
        nav_layout.setContentsMargins(14, 16, 14, 14)
        nav_layout.setSpacing(9)
        self.nav_layout = nav_layout

        self.sidebar_toggle_btn = QPushButton("☰")
        self.sidebar_toggle_btn.setObjectName("sidebar_toggle_btn")
        self.sidebar_toggle_btn.setText("<<")
        self.sidebar_toggle_btn.setToolTip("Свернуть или развернуть меню")
        self.sidebar_toggle_btn.clicked.connect(self.toggle_sidebar)
        nav_layout.addWidget(self.sidebar_toggle_btn)

        nav_brand_block = QFrame()
        nav_brand_block.setObjectName("nav_brand_block")
        brand_layout = QVBoxLayout(nav_brand_block)
        brand_layout.setContentsMargins(12, 10, 12, 10)
        brand_layout.setSpacing(2)
        self.nav_brand_block = nav_brand_block

        nav_title = QLabel("AI Network Guardian")
        nav_title.setObjectName("nav_title")
        self.nav_title = nav_title
        brand_layout.addWidget(nav_title)

        nav_subtitle = QLabel("v2.0 Security Monitor")
        nav_subtitle.setObjectName("nav_subtitle")
        self.nav_subtitle = nav_subtitle
        brand_layout.addWidget(nav_subtitle)

        nav_layout.addWidget(nav_brand_block)
        nav_layout.addSpacing(12)

        self.main_nav_btn = QPushButton("Мониторинг")
        self.main_nav_btn.setCheckable(True)
        self.main_nav_btn.clicked.connect(lambda: self.switch_page(0))
        self._configure_nav_button(self.main_nav_btn, "dashboard.svg")
        nav_layout.addWidget(self.main_nav_btn)

        self.pcap_nav_btn = QPushButton("PCAP-анализ")
        self.pcap_nav_btn.setCheckable(True)
        self.pcap_nav_btn.clicked.connect(lambda: self.switch_page(1))
        self._configure_nav_button(self.pcap_nav_btn, "pcap.svg")
        nav_layout.addWidget(self.pcap_nav_btn)

        self.sessions_nav_btn = QPushButton("Сессии")
        self.sessions_nav_btn.setCheckable(True)
        self.sessions_nav_btn.clicked.connect(lambda: self.switch_page(3))
        self._configure_nav_button(self.sessions_nav_btn, "sessions.svg")
        nav_layout.addWidget(self.sessions_nav_btn)

        self.alerts_nav_btn = QPushButton("Алерты")
        self.alerts_nav_btn.setCheckable(True)
        self.alerts_nav_btn.clicked.connect(lambda: self.switch_page(4))
        self._configure_nav_button(self.alerts_nav_btn, "alerts.svg")
        nav_layout.addWidget(self.alerts_nav_btn)

        nav_layout.addStretch(1)

        self.settings_nav_btn = QPushButton("Настройки")
        self.settings_nav_btn.setCheckable(True)
        self.settings_nav_btn.clicked.connect(lambda: self.switch_page(2))
        self._configure_nav_button(self.settings_nav_btn, "settings.svg")
        self.settings_nav_btn.setProperty("secondary", True)
        nav_layout.addWidget(self.settings_nav_btn)

        self._apply_sidebar_state(refresh_styles=False)

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
        scroll = QScrollArea()
        scroll.setObjectName("dashboard_scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        page = QWidget()
        scroll.setWidget(page)
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(18, 18, 18, 18)
        page_layout.setSpacing(14)

        # ---------- TOP BAR ----------
        top_card = QFrame()
        top_card.setObjectName("top_card")
        top_grid = QGridLayout(top_card)
        top_grid.setContentsMargins(18, 14, 18, 14)
        top_grid.setHorizontalSpacing(8)
        top_grid.setVerticalSpacing(8)

        self.page_title = QLabel("Операционный мониторинг")
        self.page_title.setObjectName("page_title")

        self.page_subtitle = QLabel("Живой трафик, инциденты, IOC и оценка ИБ в реальном времени")
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

        iface_box = QVBoxLayout()
        iface_box.setContentsMargins(0, 0, 0, 0)
        iface_box.setSpacing(2)
        iface_label = QLabel("Интерфейс:")
        iface_label.setObjectName("control_label")
        iface_box.addWidget(iface_label)
        iface_box.addWidget(self.iface_combo)

        iface_wrap = QWidget()
        iface_wrap.setLayout(iface_box)

        self.refresh_ifaces_btn = QPushButton("Обновить")
        self.refresh_ifaces_btn.clicked.connect(self.load_interfaces_to_combo)

        self.settings_btn = QPushButton("Профили")
        self.settings_btn.clicked.connect(self.open_settings)

        self.export_btn = QPushButton("Отчёт")
        self.export_btn.clicked.connect(self.export_report)

        self.action_btn = QPushButton("Старт")
        self.action_btn.setObjectName("primary_btn")
        self.action_btn.clicked.connect(self.toggle_monitoring)

        top_grid.addWidget(title_wrap, 0, 0, 1, 2)
        top_grid.addWidget(self.status_label, 0, 2)
        top_grid.addWidget(iface_wrap, 0, 3)
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
        cards_row.setSpacing(12)

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

        # ---------- SECURITY ASSESSMENT ----------
        assessment_title = QLabel("Оценка безопасности")
        assessment_title.setObjectName("dashboard_section_title")
        page_layout.addWidget(assessment_title, 0)

        summary_card = QFrame()
        summary_card.setObjectName("dashboard_assessment_section")
        summary_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(16, 14, 16, 14)
        summary_layout.setSpacing(10)

        assessment_body = QHBoxLayout()
        assessment_body.setContentsMargins(0, 0, 0, 0)
        assessment_body.setSpacing(12)

        score_panel = QFrame()
        score_panel.setObjectName("assessment_score_card")
        score_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        score_layout = QVBoxLayout(score_panel)
        score_layout.setContentsMargins(26, 22, 26, 22)
        score_layout.setSpacing(6)

        score_title = QLabel("IB Score")
        score_title.setObjectName("assessment_fact_label")
        score_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.assessment_score_value = QLabel("N/A")
        self.assessment_score_value.setObjectName("assessment_score_value")
        self.assessment_score_value.setWordWrap(True)
        self.assessment_score_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.assessment_score_level = QLabel("Недостаточно данных")
        self.assessment_score_level.setWordWrap(True)
        self.assessment_score_level.setObjectName("assessment_score_level")
        self.assessment_score_level.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_panel.setMinimumHeight(230)
        score_layout.addStretch(1)
        score_layout.addWidget(score_title)
        score_layout.addWidget(self.assessment_score_value)
        score_layout.addWidget(self.assessment_score_level)
        score_layout.addStretch(1)
        assessment_body.addWidget(score_panel, 33)

        assessment_right = QWidget()
        assessment_right_layout = QVBoxLayout(assessment_right)
        assessment_right_layout.setContentsMargins(0, 0, 0, 0)
        assessment_right_layout.setSpacing(10)

        self.assessment_threat_value = QLabel("N/A")
        self.assessment_incident_value = QLabel("N/A")
        self.assessment_confidence_value = QLabel("N/A")
        fact_items = [
            ("Угроза", self.assessment_threat_value),
            ("Инцидент", self.assessment_incident_value),
            ("Достоверность", self.assessment_confidence_value),
        ]
        facts_row = QHBoxLayout()
        facts_row.setContentsMargins(0, 0, 0, 0)
        facts_row.setSpacing(10)
        for label_text, value_label in fact_items:
            fact_card = QFrame()
            fact_card.setObjectName("assessment_metric_card")
            fact_card.setMinimumHeight(82)
            fact_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            fact_layout = QVBoxLayout(fact_card)
            fact_layout.setContentsMargins(14, 10, 14, 10)
            fact_layout.setSpacing(4)
            label = QLabel(label_text)
            label.setObjectName("assessment_fact_label")
            value_label.setObjectName("assessment_fact_value")
            value_label.setWordWrap(True)
            fact_layout.addWidget(label)
            fact_layout.addWidget(value_label)
            facts_row.addWidget(fact_card, 1)
        assessment_right_layout.addLayout(facts_row, 0)

        summary_text_card = QFrame()
        summary_text_card.setObjectName("assessment_summary_card")
        summary_text_card.setMinimumHeight(54)
        summary_text_layout = QVBoxLayout(summary_text_card)
        summary_text_layout.setContentsMargins(12, 10, 12, 10)
        self.summary_label = QLabel("Вывод: недостаточно данных для достоверной оценки")
        self.summary_label.setWordWrap(True)
        self.summary_label.setObjectName("summary_label")
        self.summary_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        summary_text_layout.addWidget(self.summary_label)
        assessment_right_layout.addWidget(summary_text_card, 0)

        analysis_layout = QHBoxLayout()
        analysis_layout.setContentsMargins(0, 0, 0, 0)
        analysis_layout.setSpacing(10)

        risk_panel = QFrame()
        risk_panel.setObjectName("assessment_detail_card")
        risk_panel.setMinimumHeight(118)
        risk_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        risk_layout = QVBoxLayout(risk_panel)
        risk_layout.setContentsMargins(12, 10, 12, 10)
        risk_layout.setSpacing(6)
        risk_title = QLabel("Состав риска")
        risk_title.setObjectName("assessment_subtitle")
        risk_layout.addWidget(risk_title)
        self.risk_labels: list[QLabel] = []
        for _ in range(5):
            lbl = QLabel("N/A")
            lbl.setWordWrap(True)
            lbl.setObjectName("risk_row")
            self.risk_labels.append(lbl)
            risk_layout.addWidget(lbl)
        analysis_layout.addWidget(risk_panel, 1)

        findings_panel = QFrame()
        findings_panel.setObjectName("assessment_detail_card")
        findings_panel.setMinimumHeight(118)
        findings_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        findings_layout = QVBoxLayout(findings_panel)
        findings_layout.setContentsMargins(12, 10, 12, 10)
        findings_layout.setSpacing(6)
        findings_title = QLabel("Ключевые выводы")
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
        assessment_right_layout.addLayout(analysis_layout, 1)
        assessment_body.addWidget(assessment_right, 67)
        summary_layout.addLayout(assessment_body)

        compare_card = QFrame()
        compare_card.setObjectName("comparison_card")
        compare_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        compare_layout = QVBoxLayout(compare_card)
        compare_layout.setContentsMargins(12, 9, 12, 9)
        self.assessment_compare_label = QLabel("Нет данных для сравнения")
        self.assessment_compare_label.setWordWrap(True)
        self.assessment_compare_label.setObjectName("comparison_text")
        compare_layout.addWidget(self.assessment_compare_label)
        summary_layout.addWidget(compare_card, 0)

        page_layout.addWidget(summary_card, 0)

        operational_title = QLabel("Операционный мониторинг")
        operational_title.setObjectName("dashboard_section_title")
        page_layout.addWidget(operational_title, 0)

        # ---------- CENTER ----------
        center_layout = QGridLayout()
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setHorizontalSpacing(12)
        center_layout.setVerticalSpacing(12)

        events_card = QFrame()
        events_card.setObjectName("section_card")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(16, 14, 16, 14)
        events_layout.setSpacing(8)

        events_title = QLabel("Последние события безопасности")
        events_title.setObjectName("section_title")
        events_layout.addWidget(events_title)

        self.events_list = QListWidget()
        self.events_list.setMinimumHeight(120)
        events_layout.addWidget(self.events_list)

        log_card = QFrame()
        log_card.setObjectName("section_card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(16, 14, 16, 14)
        log_layout.setSpacing(8)

        log_top = QHBoxLayout()
        log_top.setContentsMargins(0, 0, 0, 0)
        log_top.setSpacing(8)
        log_title = QLabel("Живой лог")
        log_title.setObjectName("section_title")
        log_title.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        log_top.addWidget(log_title)

        from PyQt6.QtWidgets import QCheckBox
        self.debug_checkbox = QCheckBox("Показывать DEBUG")
        self.debug_checkbox.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.debug_checkbox.stateChanged.connect(self.rebuild_visible_log)
        log_top.addWidget(
            self.debug_checkbox,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
        log_layout.addLayout(log_top)

        self.log_buffer = []
        self.log_area = QTextEdit()
        self.log_area.setObjectName("log_panel")
        self.log_area.setReadOnly(True)
        self.log_area.document().setMaximumBlockCount(self.max_log_messages)
        self.log_area.setMinimumHeight(220)
        log_layout.addWidget(self.log_area)

        threats_card = QFrame()
        threats_card.setObjectName("section_card")
        threats_layout = QVBoxLayout(threats_card)
        threats_layout.setContentsMargins(16, 14, 16, 14)
        threats_layout.setSpacing(8)

        threats_title = QLabel("Топ угроз по IP")
        threats_title.setObjectName("section_title")
        threats_layout.addWidget(threats_title)

        self.stats_list = QListWidget()
        self.stats_list.setMinimumHeight(110)
        threats_layout.addWidget(self.stats_list)

        graph_card = QFrame()
        graph_card.setObjectName("section_card")
        graph_layout = QVBoxLayout(graph_card)
        graph_layout.setContentsMargins(16, 14, 16, 14)
        graph_layout.setSpacing(8)

        self.plot = PlotWidget("Метрики в реальном времени")
        self.plot.setMinimumHeight(220)
        graph_layout.addWidget(self.plot)

        center_layout.addWidget(events_card, 0, 0)
        center_layout.addWidget(threats_card, 0, 1)
        center_layout.addWidget(log_card, 1, 0)
        center_layout.addWidget(graph_card, 1, 1)
        center_layout.setColumnStretch(0, 3)
        center_layout.setColumnStretch(1, 2)
        center_layout.setRowStretch(0, 1)
        center_layout.setRowStretch(1, 2)

        page_layout.addLayout(center_layout, 1)
        return scroll

    def _build_pcap_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("pcap_scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        page = QWidget()
        scroll.setWidget(page)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 16)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(12)

        title = QLabel("PCAP-анализ")
        title.setObjectName("pcap_page_title")
        header.addWidget(title, 1)

        self.pcap_btn = QPushButton("Открыть PCAP")
        self.pcap_btn.setObjectName("pcap_action_btn")
        self.pcap_btn.clicked.connect(self.open_pcap)
        header.addWidget(self.pcap_btn)

        self.open_main_btn = QPushButton("Анализ")
        self.open_main_btn.setObjectName("pcap_action_btn")
        self.open_main_btn.clicked.connect(self.open_pcap)
        header.addWidget(self.open_main_btn)

        self.pcap_export_btn = QPushButton("Экспорт отчёта")
        self.pcap_export_btn.setObjectName("pcap_action_btn")
        self.pcap_export_btn.clicked.connect(self.export_report)
        header.addWidget(self.pcap_export_btn)

        self.pcap_clear_btn = QPushButton("Очистить")
        self.pcap_clear_btn.setObjectName("pcap_action_btn")
        self.pcap_clear_btn.clicked.connect(self.clear_pcap_view)
        header.addWidget(self.pcap_clear_btn)

        self.pcap_enrichment_btn = QPushButton("Проверить public IP")
        self.pcap_enrichment_btn.setObjectName("pcap_action_btn")
        self.pcap_enrichment_btn.clicked.connect(self.start_pcap_enrichment)
        header.addWidget(self.pcap_enrichment_btn)
        layout.addLayout(header)

        summary_card = QFrame()
        summary_card.setObjectName("pcap_detail_card")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(14, 11, 14, 12)
        summary_layout.setSpacing(8)
        summary_title = QLabel("Сводка PCAP-файла")
        summary_title.setObjectName("pcap_card_title")
        summary_layout.addWidget(summary_title)

        summary_grid = QGridLayout()
        summary_grid.setContentsMargins(0, 0, 0, 0)
        summary_grid.setHorizontalSpacing(24)
        summary_grid.setVerticalSpacing(3)
        self.pcap_file_name_label = QLabel("-")
        self.pcap_file_size_label = QLabel("-")
        self.pcap_packet_count_label = QLabel("0")
        self.pcap_duration_label = QLabel("00:00:00")
        summary_items = [
            ("Имя файла:", self.pcap_file_name_label),
            ("Размер:", self.pcap_file_size_label),
            ("Пакеты:", self.pcap_packet_count_label),
            ("Длительность:", self.pcap_duration_label),
        ]
        for col, (label_text, value_label) in enumerate(summary_items):
            label = QLabel(label_text)
            label.setObjectName("pcap_field_label")
            value_label.setObjectName("pcap_field_value")
            value_label.setWordWrap(True)
            value_label.setMinimumHeight(20)
            summary_grid.addWidget(label, 0, col)
            summary_grid.addWidget(value_label, 1, col)
            summary_grid.setColumnStretch(col, 1)
        summary_layout.addLayout(summary_grid)
        layout.addWidget(summary_card)

        assessment_card = QFrame()
        assessment_card.setObjectName("pcap_detail_card")
        assessment_layout = QVBoxLayout(assessment_card)
        assessment_layout.setContentsMargins(14, 10, 14, 10)
        assessment_layout.setSpacing(8)
        assessment_title = QLabel("Оценка безопасности")
        assessment_title.setObjectName("pcap_card_title")
        assessment_layout.addWidget(assessment_title)

        assessment_body = QHBoxLayout()
        assessment_body.setContentsMargins(0, 0, 0, 0)
        assessment_body.setSpacing(12)
        self.pcap_score_label = QLabel("-")
        self.pcap_score_label.setObjectName("pcap_score_badge")
        self.pcap_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        assessment_body.addWidget(self.pcap_score_label, 0)

        assessment_text = QVBoxLayout()
        assessment_text.setContentsMargins(0, 0, 0, 0)
        assessment_text.setSpacing(3)
        self.pcap_assessment_level_label = QLabel("Нет данных")
        self.pcap_assessment_level_label.setObjectName("pcap_assessment_level")
        self.pcap_assessment_summary_label = QLabel("Откройте PCAP-файл для анализа")
        self.pcap_assessment_summary_label.setObjectName("pcap_body_text")
        self.pcap_assessment_summary_label.setWordWrap(True)
        assessment_text.addWidget(self.pcap_assessment_level_label)
        assessment_text.addWidget(self.pcap_assessment_summary_label)
        assessment_text.addStretch(1)
        assessment_body.addLayout(assessment_text, 1)
        assessment_layout.addLayout(assessment_body)
        layout.addWidget(assessment_card)

        analysis_grid = QGridLayout()
        analysis_grid.setContentsMargins(0, 0, 0, 0)
        analysis_grid.setHorizontalSpacing(12)
        analysis_grid.setVerticalSpacing(12)

        protocol_card = QFrame()
        protocol_card.setObjectName("pcap_detail_card")
        protocol_card.setMinimumHeight(126)
        protocol_layout = QVBoxLayout(protocol_card)
        protocol_layout.setContentsMargins(14, 11, 14, 12)
        protocol_layout.setSpacing(7)
        protocol_title = QLabel("Распределение протоколов")
        protocol_title.setObjectName("pcap_card_title")
        protocol_layout.addWidget(protocol_title)
        self.pcap_protocol_list = QListWidget()
        self.pcap_protocol_list.setObjectName("pcap_compact_list")
        self.pcap_protocol_list.setMinimumHeight(74)
        protocol_empty = QListWidgetItem("Откройте PCAP-файл для анализа")
        protocol_empty.setData(Qt.ItemDataRole.UserRole, "empty")
        self.pcap_protocol_list.addItem(protocol_empty)
        protocol_layout.addWidget(self.pcap_protocol_list)
        analysis_grid.addWidget(protocol_card, 0, 0)

        top_ips_card = QFrame()
        top_ips_card.setObjectName("pcap_detail_card")
        top_ips_card.setMinimumHeight(126)
        top_ips_layout = QVBoxLayout(top_ips_card)
        top_ips_layout.setContentsMargins(14, 11, 14, 12)
        top_ips_layout.setSpacing(7)
        top_ips_title = QLabel("Топ IP источников/назначений")
        top_ips_title.setObjectName("pcap_card_title")
        top_ips_layout.addWidget(top_ips_title)
        self.pcap_stats_list = QListWidget()
        self.pcap_stats_list.setObjectName("pcap_compact_list")
        self.pcap_stats_list.setMinimumHeight(74)
        stats_empty = QListWidgetItem("Данные появятся после анализа")
        stats_empty.setData(Qt.ItemDataRole.UserRole, "empty")
        self.pcap_stats_list.addItem(stats_empty)
        top_ips_layout.addWidget(self.pcap_stats_list)
        analysis_grid.addWidget(top_ips_card, 0, 1)

        conversations_card = QFrame()
        conversations_card.setObjectName("pcap_detail_card")
        conversations_card.setMinimumHeight(126)
        conversations_layout = QVBoxLayout(conversations_card)
        conversations_layout.setContentsMargins(14, 11, 14, 12)
        conversations_layout.setSpacing(7)
        conversations_title = QLabel("Подозрительные соединения")
        conversations_title.setObjectName("pcap_card_title")
        conversations_layout.addWidget(conversations_title)
        self.pcap_conversations_list = QListWidget()
        self.pcap_conversations_list.setObjectName("pcap_compact_list")
        self.pcap_conversations_list.setMinimumHeight(74)
        conversations_empty = QListWidgetItem("Данные появятся после анализа")
        conversations_empty.setData(Qt.ItemDataRole.UserRole, "empty")
        self.pcap_conversations_list.addItem(conversations_empty)
        conversations_layout.addWidget(self.pcap_conversations_list)
        analysis_grid.addWidget(conversations_card, 0, 2)
        analysis_grid.setColumnStretch(0, 1)
        analysis_grid.setColumnStretch(1, 1)
        analysis_grid.setColumnStretch(2, 1)
        layout.addLayout(analysis_grid)

        alerts_card = QFrame()
        alerts_card.setObjectName("pcap_detail_card")
        alerts_layout = QVBoxLayout(alerts_card)
        alerts_layout.setContentsMargins(14, 11, 14, 12)
        alerts_layout.setSpacing(8)
        alerts_title = QLabel("Детальные алерты")
        alerts_title.setObjectName("pcap_card_title")
        alerts_layout.addWidget(alerts_title)
        self.pcap_alerts_empty_label = QLabel("Нет данных")
        self.pcap_alerts_empty_label.setObjectName("pcap_empty_label")
        self.pcap_alerts_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        alerts_layout.addWidget(self.pcap_alerts_empty_label)
        self.pcap_alerts_table = QTableWidget(0, 4)
        self.pcap_alerts_table.setObjectName("pcap_alerts_table")
        self.pcap_alerts_table.setHorizontalHeaderLabels(["Время", "Тип", "Вердикт", "Описание"])
        self.pcap_alerts_table.verticalHeader().setVisible(False)
        self.pcap_alerts_table.verticalHeader().setDefaultSectionSize(28)
        self.pcap_alerts_table.horizontalHeader().setStretchLastSection(True)
        self.pcap_alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pcap_alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pcap_alerts_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pcap_alerts_table.setAlternatingRowColors(True)
        self.pcap_alerts_table.setShowGrid(False)
        self.pcap_alerts_table.setWordWrap(True)
        self.pcap_alerts_table.setMinimumHeight(150)
        self.pcap_alerts_table.setColumnWidth(0, 170)
        self.pcap_alerts_table.setColumnWidth(1, 128)
        self.pcap_alerts_table.setColumnWidth(2, 112)
        alerts_layout.addWidget(self.pcap_alerts_table)
        layout.addWidget(alerts_card)

        enrichment_card = QFrame()
        enrichment_card.setObjectName("pcap_detail_card")
        enrichment_layout = QVBoxLayout(enrichment_card)
        enrichment_layout.setContentsMargins(14, 11, 14, 12)
        enrichment_layout.setSpacing(8)
        enrichment_title = QLabel("AbuseIPDB context")
        enrichment_title.setObjectName("pcap_card_title")
        enrichment_layout.addWidget(enrichment_title)
        self.pcap_enrichment_status_label = QLabel("Enrichment запускается вручную и не влияет на IB Score.")
        self.pcap_enrichment_status_label.setObjectName("pcap_body_text")
        self.pcap_enrichment_status_label.setWordWrap(True)
        enrichment_layout.addWidget(self.pcap_enrichment_status_label)
        self.pcap_enrichment_table = QTableWidget(0, 8)
        self.pcap_enrichment_table.setObjectName("pcap_alerts_table")
        self.pcap_enrichment_table.setHorizontalHeaderLabels([
            "IP",
            "Status",
            "Abuse score",
            "Reports",
            "Country",
            "Usage type",
            "ISP / Domain",
            "Last reported",
        ])
        self.pcap_enrichment_table.verticalHeader().setVisible(False)
        self.pcap_enrichment_table.verticalHeader().setDefaultSectionSize(28)
        self.pcap_enrichment_table.horizontalHeader().setStretchLastSection(True)
        self.pcap_enrichment_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pcap_enrichment_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pcap_enrichment_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pcap_enrichment_table.setAlternatingRowColors(True)
        self.pcap_enrichment_table.setShowGrid(False)
        self.pcap_enrichment_table.setWordWrap(True)
        self.pcap_enrichment_table.setMinimumHeight(118)
        self.pcap_enrichment_table.setColumnWidth(0, 132)
        self.pcap_enrichment_table.setColumnWidth(1, 108)
        self.pcap_enrichment_table.setColumnWidth(2, 96)
        self.pcap_enrichment_table.setColumnWidth(3, 82)
        self.pcap_enrichment_table.setColumnWidth(4, 82)
        self.pcap_enrichment_table.setColumnWidth(5, 132)
        self.pcap_enrichment_table.setColumnWidth(6, 220)
        enrichment_layout.addWidget(self.pcap_enrichment_table)
        layout.addWidget(enrichment_card)

        bottom_grid = QGridLayout()
        bottom_grid.setContentsMargins(0, 0, 0, 0)
        bottom_grid.setHorizontalSpacing(12)
        bottom_grid.setVerticalSpacing(12)

        log_card = QFrame()
        log_card.setObjectName("pcap_detail_card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(14, 11, 14, 12)
        log_layout.setSpacing(8)
        log_title = QLabel("Лог анализа")
        log_title.setObjectName("pcap_card_title")
        log_layout.addWidget(log_title)
        self.pcap_log_area = QTextEdit()
        self.pcap_log_area.setObjectName("pcap_log_panel")
        self.pcap_log_area.setReadOnly(True)
        self.pcap_log_area.document().setMaximumBlockCount(self.max_log_messages)
        self.pcap_log_area.setMinimumHeight(168)
        log_layout.addWidget(self.pcap_log_area)
        bottom_grid.addWidget(log_card, 0, 0)

        timeline_card = QFrame()
        timeline_card.setObjectName("pcap_detail_card")
        timeline_layout = QVBoxLayout(timeline_card)
        timeline_layout.setContentsMargins(14, 11, 14, 12)
        timeline_layout.setSpacing(8)
        timeline_title = QLabel("Хронология трафика")
        timeline_title.setObjectName("pcap_card_title")
        timeline_layout.addWidget(timeline_title)
        self.pcap_plot = PlotWidget("Пакеты/сек")
        self.pcap_plot.setMinimumHeight(168)
        timeline_layout.addWidget(self.pcap_plot)
        bottom_grid.addWidget(timeline_card, 0, 1)
        bottom_grid.setColumnStretch(0, 1)
        bottom_grid.setColumnStretch(1, 1)
        layout.addLayout(bottom_grid)

        self.pcap_state_label = QLabel("Состояние: ожидание файла")
        self.pcap_state_label.setObjectName("pcap_state_label")
        layout.addWidget(self.pcap_state_label)
        return scroll

    def _make_settings_card(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("settings_card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        title_label = QLabel(title)
        title_label.setObjectName("settings_card_title")
        layout.addWidget(title_label)
        return card, layout

    def _settings_value_row(self, label_text: str, value_label: QLabel) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        label = QLabel(label_text)
        label.setObjectName("settings_label")
        value_label.setObjectName("settings_value")
        value_label.setWordWrap(True)
        value_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(label, 1)
        layout.addWidget(value_label, 1)
        return row

    def _settings_field_label(self, text: str = "-") -> QLabel:
        label = QLabel(text)
        label.setObjectName("settings_field")
        label.setWordWrap(True)
        return label

    def _settings_toggle_label(self, text: str, enabled: bool = True) -> QLabel:
        label = QLabel(text)
        label.setObjectName("settings_toggle" if enabled else "settings_toggle_off")
        label.setEnabled(enabled)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return label

    def _settings_slider_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("settings_slider")
        return label

    def _provider_status_label(self, text: str, enabled: bool = True) -> QLabel:
        label = QLabel(text)
        label.setObjectName("threat_provider_status" if enabled else "threat_provider_status_off")
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return label

    def _make_provider_row(
            self,
            provider: str,
            status_label: QLabel,
            action_widget: QWidget | None = None,
    ) -> QWidget:
        row = QWidget()
        row.setObjectName("threat_provider_row")
        row.setMinimumHeight(42)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(12)

        provider_label = QLabel(provider)
        provider_label.setObjectName("threat_provider_name")
        provider_label.setMinimumWidth(92)

        if action_widget is None:
            action_widget = QLabel("Недоступно")
            action_widget.setObjectName("threat_provider_unavailable")
            action_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_widget.setMinimumWidth(84)

        layout.addWidget(provider_label, 2)
        layout.addWidget(status_label, 3)
        layout.addWidget(action_widget, 0)
        return row

    def _refresh_threat_intel_settings(self) -> None:
        if not hasattr(self, "abuseipdb_status_lbl"):
            return

        env_configured = bool(os.environ.get("ABUSEIPDB_API_KEY", "").strip())
        if env_configured:
            self.abuseipdb_status_lbl.setText("Настроен через переменную окружения")
            self.abuseipdb_status_lbl.setToolTip("ABUSEIPDB_API_KEY")
        elif has_local_secret("ABUSEIPDB_API_KEY"):
            self.abuseipdb_status_lbl.setText("Настроен локально")
            self.abuseipdb_status_lbl.setToolTip("********")
        else:
            self.abuseipdb_status_lbl.setText("Не настроен")
            self.abuseipdb_status_lbl.setToolTip("")

    def open_abuseipdb_key_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("AbuseIPDB API Key")
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        intro = QLabel("AbuseIPDB enrichment используется только как внешний контекст.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        if os.environ.get("ABUSEIPDB_API_KEY", "").strip():
            env_note = QLabel("Ключ задан через переменную окружения ABUSEIPDB_API_KEY.")
            env_note.setWordWrap(True)
            env_note.setObjectName("settings_checks")
            layout.addWidget(env_note)

        key_input = QLineEdit()
        key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_input.setPlaceholderText("********" if has_local_secret("ABUSEIPDB_API_KEY") else "Введите API key")
        layout.addWidget(key_input)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)

        save_btn = QPushButton("Сохранить")
        delete_btn = QPushButton("Удалить")
        cancel_btn = QPushButton("Отмена")

        save_btn.setObjectName("settings_primary_action")
        delete_btn.setObjectName("settings_secondary_action")
        cancel_btn.setObjectName("settings_secondary_action")

        def save_key() -> None:
            value = key_input.text().strip()
            if value:
                set_secret("ABUSEIPDB_API_KEY", value)
            self._refresh_threat_intel_settings()
            dialog.accept()

        def delete_key() -> None:
            delete_secret("ABUSEIPDB_API_KEY")
            self._refresh_threat_intel_settings()
            dialog.accept()

        save_btn.clicked.connect(save_key)
        delete_btn.clicked.connect(delete_key)
        cancel_btn.clicked.connect(dialog.reject)

        buttons.addStretch(1)
        buttons.addWidget(save_btn)
        buttons.addWidget(delete_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)

        dialog.exec()

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Настройки системы и профили")
        title.setObjectName("settings_page_title")
        layout.addWidget(title)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        profiles_card, profiles_layout = self._make_settings_card("Профили мониторинга")
        profiles_card.setMinimumWidth(340)
        self.settings_profiles_list = QListWidget()
        self.settings_profiles_list.setObjectName("settings_profile_list")
        profiles_layout.addWidget(self.settings_profiles_list, 1)

        self.settings_page_btn = QPushButton("Управление профилями")
        self.settings_page_btn.setObjectName("settings_primary_action")
        self.settings_page_btn.clicked.connect(self.open_settings)
        profiles_layout.addWidget(self.settings_page_btn)
        left_column = QWidget()
        left_column.setMinimumWidth(340)
        left_layout = QVBoxLayout(left_column)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left_layout.addWidget(profiles_card, 1)

        threat_card, threat_layout = self._make_settings_card("API ключи / Threat Intelligence")
        threat_card.setObjectName("threat_intel_card")
        threat_card.setMinimumHeight(300)
        self.abuseipdb_status_lbl = self._provider_status_label("Не настроен")
        self.abuseipdb_configure_btn = QPushButton("Настроить")
        self.abuseipdb_configure_btn.setObjectName("threat_provider_action")
        self.abuseipdb_configure_btn.clicked.connect(self.open_abuseipdb_key_dialog)
        threat_layout.addWidget(
            self._make_provider_row("AbuseIPDB", self.abuseipdb_status_lbl, self.abuseipdb_configure_btn)
        )

        self.virustotal_status_lbl = self._provider_status_label("Скоро", False)
        threat_layout.addWidget(self._make_provider_row("VirusTotal", self.virustotal_status_lbl))
        self.otx_status_lbl = self._provider_status_label("Скоро", False)
        threat_layout.addWidget(self._make_provider_row("AlienVault OTX", self.otx_status_lbl))
        self.greynoise_status_lbl = self._provider_status_label("Скоро", False)
        threat_layout.addWidget(self._make_provider_row("GreyNoise", self.greynoise_status_lbl))
        self.shodan_status_lbl = self._provider_status_label("Скоро", False)
        threat_layout.addWidget(self._make_provider_row("Shodan", self.shodan_status_lbl))
        left_layout.addWidget(threat_card, 0)
        body.addWidget(left_column, 1)

        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(10)

        monitoring_card, monitoring_layout = self._make_settings_card("Профиль мониторинга")
        monitoring_grid = QGridLayout()
        monitoring_grid.setContentsMargins(0, 0, 0, 0)
        monitoring_grid.setHorizontalSpacing(18)
        monitoring_grid.setVerticalSpacing(8)
        self.settings_interface_lbl = self._settings_field_label("-")
        self.sample_factor_lbl = self._settings_field_label("-")
        self.settings_live_lbl = self._settings_toggle_label("Вкл.", True)
        self.settings_dpi_lbl = self._settings_toggle_label("Вкл.", True)
        monitoring_grid.addWidget(self._settings_value_row("Сетевой интерфейс", self.settings_interface_lbl), 0, 0)
        monitoring_grid.addWidget(self._settings_value_row("Частота выборки", self.sample_factor_lbl), 0, 1)
        monitoring_grid.addWidget(self._settings_value_row("Живой мониторинг", self.settings_live_lbl), 1, 0)
        monitoring_grid.addWidget(self._settings_value_row("Глубокая проверка пакетов", self.settings_dpi_lbl), 1, 1)
        monitoring_layout.addLayout(monitoring_grid)
        center_layout.addWidget(monitoring_card)

        detection_card, detection_layout = self._make_settings_card("Настройки обнаружения")
        self.settings_rule_lbl = QLabel("Стандартный      Расширенный      Экспериментальный")
        self.settings_rule_lbl.setObjectName("settings_segmented")
        self.ml_status_lbl = self._settings_slider_label("Чувствительность ML")
        self.settings_anom_lbl = self._settings_slider_label("Порог аномалий")
        detection_layout.addWidget(self._settings_value_row("Rule Engine", self.settings_rule_lbl))
        detection_layout.addWidget(self._settings_value_row("Чувствительность ML", self.ml_status_lbl))
        detection_layout.addWidget(self._settings_value_row("Порог аномалий", self.settings_anom_lbl))
        center_layout.addWidget(detection_card)

        ioc_card, ioc_layout = self._make_settings_card("Источники IOC")
        self.settings_ioc_path_lbl = self._settings_field_label("локальные списки IOC")
        self.ioc_count_lbl = self._settings_field_label("IOC: -")
        self.settings_feeds_lbl = QLabel("AlienVault   MISP")
        self.settings_feeds_lbl.setObjectName("settings_tags")
        ioc_source_row = QWidget()
        ioc_source_layout = QHBoxLayout(ioc_source_row)
        ioc_source_layout.setContentsMargins(0, 0, 0, 0)
        ioc_source_layout.setSpacing(10)
        ioc_source_label = QLabel("Блоклист IP/доменов")
        ioc_source_label.setObjectName("settings_label")
        self.settings_ioc_import_btn = QPushButton("Импорт")
        self.settings_ioc_import_btn.setObjectName("settings_secondary_action")
        self.settings_ioc_import_btn.setEnabled(False)
        ioc_source_layout.addWidget(ioc_source_label, 1)
        ioc_source_layout.addWidget(self.settings_ioc_path_lbl, 2)
        ioc_source_layout.addWidget(self.settings_ioc_import_btn, 0)
        ioc_layout.addWidget(ioc_source_row)
        ioc_layout.addWidget(self._settings_value_row("Счётчики IOC", self.ioc_count_lbl))
        ioc_layout.addWidget(self._settings_value_row("Источники Threat Intelligence", self.settings_feeds_lbl))
        center_layout.addWidget(ioc_card)

        report_card, report_layout = self._make_settings_card("Настройки отчёта")
        self.settings_report_lbl = self._settings_field_label("HTML")
        self.settings_report_options_lbl = QLabel("Инциденты включены  |  IOC совпадения включены  |  Сырые логи выкл.")
        self.settings_report_options_lbl.setObjectName("settings_checks")
        report_layout.addWidget(self._settings_value_row("Формат по умолчанию", self.settings_report_lbl))
        report_layout.addWidget(self._settings_value_row("Разделы отчёта", self.settings_report_options_lbl))
        center_layout.addWidget(report_card)

        storage_card, storage_layout = self._make_settings_card("База данных и хранилище")
        self.settings_db_path_lbl = self._settings_field_label("-")
        self.settings_db_counts_lbl = self._settings_slider_label("-")
        storage_layout.addWidget(self._settings_value_row("Путь к базе", self.settings_db_path_lbl))
        storage_layout.addWidget(self._settings_value_row("Записи", self.settings_db_counts_lbl))
        center_layout.addWidget(storage_card)
        body.addWidget(center, 2)

        summary_card, summary_layout = self._make_settings_card("Статус активного профиля")
        summary_card.setObjectName("settings_status_card")
        summary_card.setMinimumWidth(260)
        self.settings_status_title_lbl = summary_layout.itemAt(0).widget()
        self.profile_name_lbl = QLabel("-")
        self.settings_profile_file_lbl = QLabel("-")
        self.settings_rules_count_lbl = QLabel("-")
        self.settings_model_lbl = QLabel("-")
        self.settings_updated_lbl = QLabel("-")
        self.active_profile_status_lbl = QLabel("Статус:\nАктивен и стабилен")
        self.active_profile_status_lbl.setObjectName("settings_status_good")

        summary_layout.addWidget(self._settings_value_row("Интерфейс", self.profile_name_lbl))
        summary_layout.addWidget(self._settings_value_row("Файл профиля", self.settings_profile_file_lbl))
        summary_layout.addWidget(self._settings_value_row("Правила", self.settings_rules_count_lbl))
        summary_layout.addWidget(self._settings_value_row("ML-модель", self.settings_model_lbl))
        summary_layout.addWidget(self._settings_value_row("Последнее обновление", self.settings_updated_lbl))
        summary_layout.addWidget(self.active_profile_status_lbl)
        summary_layout.addStretch(1)
        body.addWidget(summary_card, 1)

        layout.addLayout(body, 1)
        self.refresh_settings_profile_page()
        return page

        desc = QLabel("Управление активным профилем, sampling и параметрами ML-модуля.")
        return page

        info_card = QFrame()
        info_card.setObjectName("panel_card")
        info_layout = QGridLayout(info_card)
        info_layout.setContentsMargins(16, 14, 16, 14)
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

        self.settings_page_btn = QPushButton("Профили")
        self.settings_page_btn.clicked.connect(self.open_settings)
        layout.addWidget(self.settings_page_btn)
        layout.addStretch(1)
        return page

    def _build_sessions_page(self):
        layout = QVBoxLayout(self.sessions_page)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(18)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(12)

        sessions_title = QLabel()
        sessions_title.setText("Сессии")
        sessions_title.setObjectName("sessions_page_title")

        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(3)
        header_text.addWidget(sessions_title)

        sessions_subtitle = QLabel("История сессий захвата и анализа трафика")
        sessions_subtitle.setObjectName("sessions_page_subtitle")
        header_text.addWidget(sessions_subtitle)
        header.addLayout(header_text, 1)

        self.open_report_btn = QPushButton("Отчёт")
        self.open_report_btn.setObjectName("primary_btn")
        self.open_report_btn.setToolTip("Открыть существующий отчёт или сформировать новый для выбранной сессии")
        self.open_report_btn.setMinimumSize(118, 42)
        self.open_report_btn.clicked.connect(self.open_selected_session_report)
        header.addWidget(self.open_report_btn, 0, Qt.AlignmentFlag.AlignRight)
        layout.addLayout(header)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        left_card = QWidget()
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        search_row = QHBoxLayout()
        search_row.setContentsMargins(0, 0, 0, 0)
        search_row.setSpacing(10)

        self.sessions_search = QLineEdit()
        self.sessions_search.setObjectName("sessions_search")
        self.sessions_search.setPlaceholderText("Поиск сессий")
        self.sessions_search.textChanged.connect(self.apply_session_filter)
        search_row.addWidget(self.sessions_search, 1)

        self.refresh_sessions_btn = QPushButton("Обновить")
        self.refresh_sessions_btn.setObjectName("sessions_filter_btn")
        self.refresh_sessions_btn.clicked.connect(self.load_sessions)
        search_row.addWidget(self.refresh_sessions_btn, 0)
        left_layout.addLayout(search_row)

        self.sessions_list = QListWidget()
        self.sessions_list.setObjectName("sessions_list")
        self.sessions_list.itemClicked.connect(self.show_session_details)
        left_layout.addWidget(self.sessions_list)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        assessment_card = QFrame()
        assessment_card.setObjectName("session_detail_card")
        assessment_layout = QVBoxLayout(assessment_card)
        assessment_layout.setContentsMargins(18, 16, 18, 16)
        assessment_layout.setSpacing(12)

        assessment_title = QLabel("Оценка безопасности")
        assessment_title.setObjectName("session_card_title")
        assessment_layout.addWidget(assessment_title)

        assessment_body = QHBoxLayout()
        assessment_body.setContentsMargins(0, 0, 0, 0)
        assessment_body.setSpacing(28)

        score_box = QVBoxLayout()
        score_box.setContentsMargins(0, 0, 0, 0)
        score_box.setSpacing(4)
        self.session_score_value = QLabel("-")
        self.session_score_value.setObjectName("session_score_value")
        self.session_score_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_score_level = QLabel("-")
        self.session_score_level.setObjectName("session_score_level")
        self.session_score_level.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_score_level.setWordWrap(True)
        score_box.addStretch(1)
        score_box.addWidget(self.session_score_value)
        score_box.addWidget(self.session_score_level)
        score_box.addStretch(1)

        score_frame = QFrame()
        score_frame.setObjectName("session_score_ring")
        score_frame.setMinimumSize(148, 148)
        score_frame.setMaximumSize(148, 148)
        score_frame.setLayout(score_box)
        assessment_body.addWidget(score_frame, 0)

        divider = QFrame()
        divider.setObjectName("session_vertical_divider")
        divider.setFrameShape(QFrame.Shape.VLine)
        assessment_body.addWidget(divider)

        badge_col = QVBoxLayout()
        badge_col.setContentsMargins(0, 0, 0, 0)
        badge_col.setSpacing(10)
        self.session_threat_badge = QLabel("Угроза: -")
        self.session_incident_badge = QLabel("Инцидент: -")
        self.session_confidence_badge = QLabel("Достоверность: -")
        for badge in (self.session_threat_badge, self.session_incident_badge, self.session_confidence_badge):
            badge.setObjectName("session_assessment_badge")
            badge.setWordWrap(True)
            badge_col.addWidget(badge)
        badge_col.addStretch(1)
        assessment_body.addLayout(badge_col, 1)
        assessment_layout.addLayout(assessment_body)
        right_layout.addWidget(assessment_card)

        explanation_card = QFrame()
        explanation_card.setObjectName("session_detail_card")
        explanation_layout = QVBoxLayout(explanation_card)
        explanation_layout.setContentsMargins(18, 16, 18, 16)
        explanation_layout.setSpacing(10)
        explanation_title = QLabel("Объяснение")
        explanation_title.setObjectName("session_card_title")
        self.session_explanation_label = QLabel("Выберите сессию слева.")
        self.session_explanation_label.setObjectName("session_body_text")
        self.session_explanation_label.setWordWrap(True)
        explanation_layout.addWidget(explanation_title)
        explanation_layout.addWidget(self.session_explanation_label)
        right_layout.addWidget(explanation_card)

        stats_card = QFrame()
        stats_card.setObjectName("session_detail_card")
        stats_layout = QVBoxLayout(stats_card)
        stats_layout.setContentsMargins(18, 16, 18, 16)
        stats_layout.setSpacing(12)
        stats_title = QLabel("Статистика")
        stats_title.setObjectName("session_card_title")
        stats_layout.addWidget(stats_title)

        stats_grid = QGridLayout()
        stats_grid.setContentsMargins(0, 0, 0, 0)
        stats_grid.setHorizontalSpacing(18)
        stats_grid.setVerticalSpacing(8)
        self.session_stat_labels: dict[str, QLabel] = {}
        stat_specs = [
            ("packets", "Пакеты:"),
            ("duration", "Длительность:"),
            ("anomalies", "Аномалии:"),
            ("ioc", "IOC совпадения:"),
        ]
        for col, (key, title) in enumerate(stat_specs):
            stat_wrap = QVBoxLayout()
            stat_wrap.setContentsMargins(0, 0, 0, 0)
            stat_wrap.setSpacing(2)
            title_label = QLabel(title)
            title_label.setObjectName("session_stat_title")
            value_label = QLabel("-")
            value_label.setObjectName("session_stat_value")
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.session_stat_labels[key] = value_label
            stat_wrap.addWidget(title_label, 0, Qt.AlignmentFlag.AlignCenter)
            stat_wrap.addWidget(value_label, 0, Qt.AlignmentFlag.AlignCenter)
            stat_widget = QWidget()
            stat_widget.setLayout(stat_wrap)
            stats_grid.addWidget(stat_widget, 0, col)
            stats_grid.setColumnStretch(col, 1)
        stats_layout.addLayout(stats_grid)
        right_layout.addWidget(stats_card)

        comparison_card = QFrame()
        comparison_card.setObjectName("session_detail_card")
        comparison_layout = QVBoxLayout(comparison_card)
        comparison_layout.setContentsMargins(18, 16, 18, 16)
        comparison_layout.setSpacing(10)
        comparison_title = QLabel("Сравнение")
        comparison_title.setObjectName("session_card_title")
        self.session_comparison_label = QLabel("Нет данных для сравнения")
        self.session_comparison_label.setObjectName("session_body_text")
        self.session_comparison_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_comparison_label.setWordWrap(True)
        comparison_layout.addWidget(comparison_title)
        comparison_layout.addWidget(self.session_comparison_label, 1)
        right_layout.addWidget(comparison_card, 1)

        body.addWidget(left_card, 1)
        body.addWidget(right_panel, 2)
        layout.addLayout(body, 1)
        self._session_rows: list[tuple] = []
        self.load_sessions()

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(14)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(12)
        header_text = QVBoxLayout()
        header_text.setContentsMargins(0, 0, 0, 0)
        header_text.setSpacing(2)
        title = QLabel("Алерты")
        title.setObjectName("alerts_page_title")
        subtitle = QLabel("Все зафиксированные события безопасности")
        subtitle.setObjectName("alerts_page_subtitle")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header.addLayout(header_text, 1)
        layout.addLayout(header)

        filters_card = QFrame()
        filters_card.setObjectName("alerts_filter_bar")
        filters = QGridLayout(filters_card)
        filters.setContentsMargins(16, 12, 16, 12)
        filters.setHorizontalSpacing(12)
        filters.setVerticalSpacing(8)

        self.alert_session_filter = QComboBox()
        self.alert_session_filter.setObjectName("alerts_filter_combo")
        self.alert_session_filter.setMinimumWidth(240)
        self.alert_session_filter.setMaximumWidth(260)
        self.alert_type_filter = QComboBox()
        self.alert_type_filter.setObjectName("alerts_filter_combo")
        self.alert_type_filter.setMinimumWidth(190)
        self.alert_type_filter.setMaximumWidth(220)
        self.alert_verdict_filter = QComboBox()
        self.alert_verdict_filter.setObjectName("alerts_filter_combo")
        self.alert_verdict_filter.setMinimumWidth(160)
        self.alert_verdict_filter.setMaximumWidth(180)
        self.alert_search_input = QLineEdit()
        self.alert_search_input.setObjectName("alerts_search_input")
        self.alert_search_input.setMinimumWidth(220)
        self.alert_search_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.alert_search_input.setPlaceholderText("Поиск алертов, IP или описаний...")

        self.alert_period_checkbox = QCheckBox("Период")
        self.alert_period_checkbox.setObjectName("alerts_period_checkbox")
        self.alert_from_dt = QDateTimeEdit()
        self.alert_from_dt.setObjectName("alerts_datetime")
        self.alert_from_dt.setCalendarPopup(True)
        self.alert_from_dt.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.alert_from_dt.setFixedWidth(150)
        self.alert_to_dt = QDateTimeEdit()
        self.alert_to_dt.setObjectName("alerts_datetime")
        self.alert_to_dt.setCalendarPopup(True)
        self.alert_to_dt.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.alert_to_dt.setFixedWidth(150)

        now = datetime.now()
        self.alert_from_dt.setDateTime(QDateTime(now - timedelta(days=7)))
        self.alert_to_dt.setDateTime(QDateTime(now))
        self.alert_from_dt.setEnabled(False)
        self.alert_to_dt.setEnabled(False)
        self.alert_period_checkbox.stateChanged.connect(self._toggle_alert_period_filters)

        self.alert_refresh_btn = QPushButton("Обновить")
        self.alert_refresh_btn.setObjectName("alerts_filter_button")
        self.alert_refresh_btn.setFixedWidth(96)
        self.alert_refresh_btn.clicked.connect(self.load_alerts_history)
        self.alert_reset_btn = QPushButton("Сбросить")
        self.alert_reset_btn.setObjectName("alerts_reset_button")
        self.alert_reset_btn.setFixedWidth(96)
        self.alert_reset_btn.clicked.connect(self.reset_alert_filters)

        period_wrap = QWidget()
        period_wrap.setObjectName("alerts_period_wrap")
        period_layout = QHBoxLayout(period_wrap)
        period_layout.setContentsMargins(0, 0, 0, 0)
        period_layout.setSpacing(8)
        period_layout.addWidget(self.alert_period_checkbox)
        period_layout.addWidget(self.alert_from_dt)
        period_layout.addWidget(self.alert_to_dt)

        filters.addWidget(self.alert_session_filter, 0, 0)
        filters.addWidget(self.alert_type_filter, 0, 1)
        filters.addWidget(self.alert_verdict_filter, 0, 2)
        filters.addWidget(self.alert_search_input, 0, 3)
        filters.addWidget(self.alert_refresh_btn, 0, 4)
        filters.addWidget(self.alert_reset_btn, 0, 5)
        filters.addWidget(period_wrap, 1, 0, 1, 6, Qt.AlignmentFlag.AlignLeft)
        filters.setColumnMinimumWidth(0, 240)
        filters.setColumnMinimumWidth(1, 190)
        filters.setColumnMinimumWidth(2, 160)
        filters.setColumnMinimumWidth(3, 220)
        filters.setColumnStretch(0, 0)
        filters.setColumnStretch(1, 0)
        filters.setColumnStretch(2, 0)
        filters.setColumnStretch(3, 1)
        filters.setColumnStretch(4, 0)
        filters.setColumnStretch(5, 0)
        layout.addWidget(filters_card, 0)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(16)

        table_card = QFrame()
        table_card.setObjectName("alerts_table_card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(16, 14, 16, 16)
        table_layout.setSpacing(10)

        self.alerts_count_label = QLabel("Алерты: 0")
        self.alerts_count_label.setObjectName("alerts_table_title")
        table_layout.addWidget(self.alerts_count_label)

        self.alerts_empty_label = QLabel("Нет алертов по выбранным фильтрам")
        self.alerts_empty_label.setObjectName("empty_state_label")
        self.alerts_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.alerts_empty_label.setVisible(False)
        table_layout.addWidget(self.alerts_empty_label)

        self.alerts_table = QTableWidget(0, 4)
        self.alerts_table.setObjectName("alerts_table")
        self.alerts_table.setHorizontalHeaderLabels(["Время", "Тип", "Вердикт", "Источник"])
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.verticalHeader().setDefaultSectionSize(62)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setShowGrid(False)
        self.alerts_table.setMinimumHeight(420)
        self._configure_alerts_table_columns()
        self.alerts_table.itemSelectionChanged.connect(self.show_selected_alert_details)
        table_layout.addWidget(self.alerts_table, 1)

        details_panel = QWidget()
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(12)

        summary_card = QFrame()
        summary_card.setObjectName("alerts_summary_card")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(16, 14, 16, 14)
        summary_layout.setSpacing(8)
        self.alert_summary_title = QLabel("Детали алерта")
        self.alert_summary_title.setObjectName("alerts_card_title")
        self.alert_summary_verdict = QLabel("UNKNOWN")
        self.alert_summary_verdict.setObjectName("verdict_badge_unknown")
        self.alert_summary_time = QLabel("-")
        self.alert_summary_time.setObjectName("alerts_body_text")
        self.alert_summary_type = QLabel("-")
        self.alert_summary_type.setObjectName("alerts_body_text")
        self.alert_summary_source = QLabel("Источник: -")
        self.alert_summary_source.setObjectName("alerts_body_text")
        self.alert_summary_destination = QLabel("Назначение: -")
        self.alert_summary_destination.setObjectName("alerts_body_text")
        self.alert_summary_description = QLabel("-")
        self.alert_summary_description.setObjectName("alerts_body_text")
        self.alert_summary_description.setWordWrap(True)
        summary_header = QHBoxLayout()
        summary_header.setContentsMargins(0, 0, 0, 0)
        summary_header.setSpacing(8)
        summary_header.addWidget(self.alert_summary_title, 1)
        summary_header.addWidget(self.alert_summary_verdict, 0, Qt.AlignmentFlag.AlignRight)
        summary_layout.addLayout(summary_header)
        summary_layout.addWidget(self.alert_summary_time)
        summary_layout.addWidget(self.alert_summary_description)
        summary_layout.addWidget(self.alert_summary_type)
        summary_layout.addWidget(self.alert_summary_source)
        summary_layout.addWidget(self.alert_summary_destination)
        details_layout.addWidget(summary_card)

        detail_section = QFrame()
        detail_section.setObjectName("alerts_detail_section")
        detail_section_layout = QVBoxLayout(detail_section)
        detail_section_layout.setContentsMargins(16, 14, 16, 14)
        detail_section_layout.setSpacing(8)
        details_title = QLabel("Подробности")
        details_title.setObjectName("alerts_card_title")
        detail_section_layout.addWidget(details_title)

        self.alert_details = QTextEdit()
        self.alert_details.setObjectName("alerts_details_text")
        self.alert_details.setReadOnly(True)
        self.alert_details.setMinimumHeight(190)
        detail_section_layout.addWidget(self.alert_details, 1)
        details_layout.addWidget(detail_section, 1)

        linked_card = QFrame()
        linked_card.setObjectName("linked_session_card")
        linked_layout = QVBoxLayout(linked_card)
        linked_layout.setContentsMargins(16, 14, 16, 14)
        linked_layout.setSpacing(8)
        linked_title = QLabel("Связанная оценка сессии")
        linked_title.setObjectName("alerts_card_title")
        self.linked_session_label = QLabel("Нет связанной оценки сессии")
        self.linked_session_label.setObjectName("alerts_body_text")
        self.linked_session_label.setWordWrap(True)
        linked_layout.addWidget(linked_title)
        linked_layout.addWidget(self.linked_session_label)
        details_layout.addWidget(linked_card)

        body.addWidget(table_card, 2)
        body.addWidget(details_panel, 1)
        layout.addLayout(body, 1)

        self.alert_rows: list[tuple] = []
        self._alerts_loaded = False
        self._alerts_dirty = False
        self._alert_filters_loaded = False
        self._last_alert_query_params = None
        self._alert_session_context_cache = {}
        self._clear_alert_details_panel()
        return page

    # ---------- helpers ----------
    def _configure_nav_button(self, button: QPushButton, icon_name: str) -> None:
        icon_path = self.nav_icons_dir / icon_name
        button.setObjectName("nav_btn")
        button.setIcon(QIcon(str(icon_path)))
        button.setIconSize(self.nav_icon_size)
        button.setMinimumHeight(38)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        button.setCursor(Qt.CursorShape.PointingHandCursor)

    def _refresh_widget_style(self, widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def _nav_button_specs(self):
        return [
            (self.main_nav_btn, "Мониторинг", "М", "Мониторинг"),
            (self.pcap_nav_btn, "PCAP-анализ", "P", "PCAP-анализ"),
            (self.sessions_nav_btn, "Сессии", "С", "Сессии"),
            (self.alerts_nav_btn, "Алерты", "А", "Алерты"),
            (self.settings_nav_btn, "Настройки", "Н", "Настройки"),
        ]

    def toggle_sidebar(self) -> None:
        self.sidebar_collapsed = not self.sidebar_collapsed
        self._apply_sidebar_state()

    def _apply_sidebar_state(self, refresh_styles: bool = True) -> None:
        collapsed = self.sidebar_collapsed
        width = self.sidebar_collapsed_width if collapsed else self.sidebar_expanded_width
        self.sidebar.setFixedWidth(width)
        self.nav_brand_block.setVisible(not collapsed)
        self.nav_title.setVisible(not collapsed)
        self.nav_subtitle.setVisible(not collapsed)
        self.sidebar_toggle_btn.setText(">>" if collapsed else "<<")
        self.sidebar_toggle_btn.setProperty("collapsed", collapsed)
        self.nav_layout.setContentsMargins(8 if collapsed else 14, 16, 8 if collapsed else 14, 14)
        self.nav_layout.setSpacing(8 if collapsed else 9)

        for btn, expanded_text, collapsed_text, tooltip in self._nav_button_specs():
            btn.setText(collapsed_text if collapsed else expanded_text)
            btn.setToolTip(tooltip)
            btn.setIconSize(QSize(18, 18) if collapsed else self.nav_icon_size)
            btn.setMinimumWidth(0)
            btn.setProperty("collapsed", collapsed)
            if refresh_styles:
                self._refresh_widget_style(btn)

        if refresh_styles:
            self._refresh_widget_style(self.sidebar)
            self._refresh_widget_style(self.sidebar_toggle_btn)

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
            return "Состав риска: N/A\nКлючевые выводы: N/A"

        components = assessment.get("components") or {}
        findings = assessment.get("findings") or []
        lines = ["Состав риска:"]
        if components:
            for name, value in components.items():
                lines.append(f"- {name}: {value}")
        else:
            lines.append("- N/A")

        lines.append("")
        lines.append("Ключевые выводы:")
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

    def _format_bytes(self, size: int) -> str:
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{size} B"

    def _update_pcap_file_summary(self, file_path: str | None = None) -> None:
        if not hasattr(self, "pcap_file_name_label"):
            return

        path_text = file_path or self.last_pcap_path
        if path_text:
            path = Path(path_text)
            self.pcap_file_name_label.setText(path.name)
            try:
                self.pcap_file_size_label.setText(self._format_bytes(path.stat().st_size))
            except OSError:
                self.pcap_file_size_label.setText("-")
        else:
            self.pcap_file_name_label.setText("-")
            self.pcap_file_size_label.setText("-")

        packets = int(getattr(self.engine, "packet_count", 0) or 0)
        self.pcap_packet_count_label.setText(f"{packets:,}")
        current_session = getattr(self.engine, "current_session", None)
        duration = current_session.duration_seconds() if current_session else 0
        self.pcap_duration_label.setText(self._format_session_duration(duration))

    def _refresh_pcap_assessment(self, assessment: dict | None, ready: bool) -> None:
        if not hasattr(self, "pcap_score_label"):
            return

        if not ready or not assessment:
            self.pcap_score_label.setText("-")
            self.pcap_assessment_level_label.setText("Нет данных")
            self.pcap_assessment_summary_label.setText("Откройте PCAP-файл для анализа")
            return

        self.pcap_score_label.setText(str(assessment.get("overall_score", "-")))
        self.pcap_assessment_level_label.setText(assessment.get("security_level") or "-")
        summary = assessment.get("summary") or "-"
        threat = assessment.get("threat_level") or "-"
        incident = assessment.get("incident_probability") or "-"
        confidence = assessment.get("confidence") or "-"
        self.pcap_assessment_summary_label.setText(
            f"{summary}\nУгроза: {threat} | Инцидент: {incident} | Достоверность: {confidence}"
        )

    def _pcap_alert_from_log(self, msg: str, plain: str | None = None) -> tuple[str, str, str] | None:
        plain = plain if plain is not None else self._plain_log(msg)
        verdict = re.search(r"\[VERDICT\]\s+(\w+)\s+\|\s+([^|]+)\|\s*(.+)$", plain)
        incident = re.search(r"\[INCIDENT\]\s+(\w+)\s+\|\s+host=([^|]+)\|\s*(.+)$", plain)
        ioc = re.search(r"\[IOC(?: DOMAIN)? MATCH\]\s+(.+)$", plain)

        if verdict:
            severity, flow, detail = verdict.groups()
            alert_type = "VERDICT"
            description = f"{flow.strip()} | {detail.strip()}"
        elif incident:
            severity, host, detail = incident.groups()
            alert_type = "INCIDENT"
            description = f"{host.strip()} | {detail.strip()}"
        elif ioc:
            severity = "IOC"
            alert_type = "IOC"
            description = ioc.group(1).strip()
        else:
            return None

        return alert_type, severity.upper(), description

    def _append_pcap_alert_rows(self, rows: list[tuple[str, str, str]]) -> None:
        if not rows or not hasattr(self, "pcap_alerts_table"):
            return

        table = self.pcap_alerts_table
        updates_enabled = table.updatesEnabled()
        table.setUpdatesEnabled(False)
        try:
            start_row = table.rowCount()
            table.setRowCount(start_row + len(rows))
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for offset, (alert_type, severity, description) in enumerate(rows):
                row = start_row + offset
                values = [timestamp, alert_type, severity, description]
                for col, value in enumerate(values):
                    table.setItem(row, col, QTableWidgetItem(value))
        finally:
            table.setUpdatesEnabled(updates_enabled)
            table.viewport().update()

        if hasattr(self, "pcap_alerts_empty_label"):
            self.pcap_alerts_empty_label.setVisible(False)

        if hasattr(self, "pcap_conversations_list"):
            conv = self.pcap_conversations_list
            updates_enabled = conv.updatesEnabled()
            conv.setUpdatesEnabled(False)
            try:
                if conv.count() == 1 and conv.item(0).data(Qt.ItemDataRole.UserRole) == "empty":
                    conv.clear()
                for _alert_type, _severity, description in rows:
                    conv.insertItem(0, description)
                while conv.count() > 20:
                    conv.takeItem(conv.count() - 1)
            finally:
                conv.setUpdatesEnabled(updates_enabled)

    def _append_pcap_alert_from_log(self, msg: str) -> None:
        parsed = self._pcap_alert_from_log(msg)
        if parsed:
            self._append_pcap_alert_rows([parsed])

    def clear_pcap_view(self) -> None:
        if hasattr(self, "pcap_log_area"):
            self.pcap_log_area.clear()
        if hasattr(self, "pcap_alerts_table"):
            self.pcap_alerts_table.setRowCount(0)
        if hasattr(self, "pcap_alerts_empty_label"):
            self.pcap_alerts_empty_label.setVisible(True)
        if hasattr(self, "pcap_protocol_list"):
            self.pcap_protocol_list.clear()
            item = QListWidgetItem("Откройте PCAP-файл для анализа")
            item.setData(Qt.ItemDataRole.UserRole, "empty")
            self.pcap_protocol_list.addItem(item)
        if hasattr(self, "pcap_stats_list"):
            self.pcap_stats_list.clear()
            item = QListWidgetItem("Данные появятся после анализа")
            item.setData(Qt.ItemDataRole.UserRole, "empty")
            self.pcap_stats_list.addItem(item)
        if hasattr(self, "pcap_conversations_list"):
            self.pcap_conversations_list.clear()
            item = QListWidgetItem("Данные появятся после анализа")
            item.setData(Qt.ItemDataRole.UserRole, "empty")
            self.pcap_conversations_list.addItem(item)

        if hasattr(self, "pcap_enrichment_table"):
            self.pcap_enrichment_table.setRowCount(0)
        if hasattr(self, "pcap_enrichment_status_label"):
            self.pcap_enrichment_status_label.setText("Enrichment запускается вручную и не влияет на IB Score.")

    def _extract_ips_from_text(self, text: str) -> list[str]:
        return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")

    def _collect_pcap_enrichment_ips(self, limit: int = 25) -> list[str]:
        candidates: list[str] = []

        def add_ip(ip: str) -> None:
            if len(candidates) >= limit:
                return
            if ip and ip not in candidates and is_public_ip(ip):
                candidates.append(ip)

        for ip in getattr(self.engine, "attacker_stats", Counter()).keys():
            add_ip(str(ip))

        if hasattr(self, "pcap_alerts_table"):
            for row in range(self.pcap_alerts_table.rowCount()):
                for col in range(self.pcap_alerts_table.columnCount()):
                    item = self.pcap_alerts_table.item(row, col)
                    if item:
                        for ip in self._extract_ips_from_text(item.text()):
                            add_ip(ip)

        if hasattr(self, "pcap_conversations_list"):
            for idx in range(self.pcap_conversations_list.count()):
                item = self.pcap_conversations_list.item(idx)
                if item and item.data(Qt.ItemDataRole.UserRole) != "empty":
                    for ip in self._extract_ips_from_text(item.text()):
                        add_ip(ip)

        return candidates[:limit]

    def _set_pcap_enrichment_busy(self, busy: bool) -> None:
        if hasattr(self, "pcap_enrichment_btn"):
            self.pcap_enrichment_btn.setEnabled(not busy and not self.is_monitoring)

    def _set_pcap_enrichment_message(self, text: str) -> None:
        if hasattr(self, "pcap_enrichment_status_label"):
            self.pcap_enrichment_status_label.setText(text)

    def _format_enrichment_value(self, value) -> str:
        if value is None or value == "":
            return "-"
        return str(value)

    def _render_enrichment_result(self, ip: str, result: dict) -> None:
        if not hasattr(self, "pcap_enrichment_table"):
            return

        table = self.pcap_enrichment_table
        row_idx = None
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item and item.text() == ip:
                row_idx = row
                break

        if row_idx is None:
            row_idx = table.rowCount()
            table.insertRow(row_idx)

        isp_domain = " / ".join(
            part for part in (
                self._format_enrichment_value(result.get("isp")),
                self._format_enrichment_value(result.get("domain")),
            )
            if part != "-"
        ) or "-"

        values = [
            ip,
            self._format_enrichment_value(result.get("status")),
            self._format_enrichment_value(result.get("abuseConfidenceScore")),
            self._format_enrichment_value(result.get("totalReports")),
            self._format_enrichment_value(result.get("countryCode")),
            self._format_enrichment_value(result.get("usageType")),
            isp_domain,
            self._format_enrichment_value(result.get("lastReportedAt")),
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            table.setItem(row_idx, col, item)

    def start_pcap_enrichment(self) -> None:
        if self.is_monitoring:
            self._set_pcap_enrichment_message("Дождитесь завершения анализа перед enrichment.")
            return

        if self.enrichment_worker is not None:
            return

        if not has_secret("ABUSEIPDB_API_KEY"):
            if hasattr(self, "pcap_enrichment_table"):
                self.pcap_enrichment_table.setRowCount(0)
            self._set_pcap_enrichment_message("ABUSEIPDB_API_KEY не настроен. Enrichment пропущен.")
            return

        candidates = self._collect_pcap_enrichment_ips(limit=25)
        if not candidates:
            if hasattr(self, "pcap_enrichment_table"):
                self.pcap_enrichment_table.setRowCount(0)
            self._set_pcap_enrichment_message("Публичные IP-адреса для проверки не найдены.")
            return

        self.pcap_enrichment_table.setRowCount(0)
        self._set_pcap_enrichment_message(f"AbuseIPDB enrichment: проверка {len(candidates)} public IP...")
        self._set_pcap_enrichment_busy(True)

        self.enrichment_worker = EnrichmentWorker(candidates, max_requests=25)
        self.enrichment_worker.progress.connect(self.on_enrichment_progress)
        self.enrichment_worker.finished_signal.connect(self.on_enrichment_finished)
        self.enrichment_worker.start()

    def on_enrichment_progress(self, ip: str, result: dict) -> None:
        self._render_enrichment_result(ip, result)

    def on_enrichment_finished(self, results: dict) -> None:
        count = len(results or {})
        self.enrichment_worker = None
        self._set_pcap_enrichment_busy(False)
        self._set_pcap_enrichment_message(
            f"AbuseIPDB enrichment завершён: {count} IP. Это внешний контекст, IB Score не изменён."
        )

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
        if hasattr(self, "pcap_stats_list"):
            self.pcap_stats_list.clear()
        merged = Counter(self.threat_counter)
        merged.update(self.engine.attacker_stats)
        if hasattr(self, "pcap_stats_list"):
            if not merged:
                item = QListWidgetItem("Нет данных")
                item.setData(Qt.ItemDataRole.UserRole, "empty")
                self.pcap_stats_list.addItem(item)
            for ip, count in merged.most_common(10):
                line = f"{ip} -> {count} events"
                self.pcap_stats_list.addItem(line)
        if hasattr(self, "pcap_protocol_list"):
            packets = int(getattr(self.engine, "packet_count", 0) or 0)
            self.pcap_protocol_list.clear()
            if packets:
                item = QListWidgetItem("Нет данных")
            else:
                item = QListWidgetItem("Откройте PCAP-файл для анализа")
            item.setData(Qt.ItemDataRole.UserRole, "empty")
            self.pcap_protocol_list.addItem(item)
        self._update_pcap_file_summary()
        self.update_top_ips()

    def flush_live_ui_updates(self, force: bool = False) -> None:
        if not force and not self._live_ui_dirty and not self._pending_worker_logs:
            return

        self._flush_pending_worker_logs()
        self._live_ui_dirty = False
        now = time.monotonic()
        self._last_live_ui_flush = now

        stats_interval = 1.0 if getattr(self, "current_mode", "") == "pcap" else 0.5
        if force or now - getattr(self, "_last_stats_refresh", 0.0) >= stats_interval:
            self._last_stats_refresh = now
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
        self._refresh_pcap_assessment(assessment, ready)
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
        now = time.monotonic()
        force = getattr(self, "_force_graph_refresh", False)
        if getattr(self, "is_monitoring", False) and getattr(self, "current_mode", "") == "pcap" and not force:
            if now - getattr(self, "_last_graph_refresh", 0.0) < 2.0:
                return
        self._last_graph_refresh = now
        self._force_graph_refresh = False

        pps_eff = float(getattr(self.engine.rules, "last_pps_eff", 0.0))
        seen = max(1, int(getattr(self.engine, "total_seen", 0)))
        anom = int(getattr(self.engine, "total_anom", 0))
        anom_rate = anom / seen

        current_index = self.pages.currentIndex() if hasattr(self, "pages") else 0
        if force or current_index == 0 or getattr(self, "current_mode", "") != "pcap":
            self.plot.push(pps_eff=pps_eff, anom_rate=anom_rate)
        if hasattr(self, "pcap_plot") and (force or current_index == 1):
            self.pcap_plot.push(pps_eff=pps_eff, anom_rate=anom_rate)

    def _remember_log_message(self, msg: str) -> None:
        self.log_buffer.append(msg)
        if len(self.log_buffer) > self.max_log_messages:
            del self.log_buffer[: len(self.log_buffer) - self.max_log_messages]

        if getattr(self, "is_monitoring", False):
            self._mark_alerts_dirty()

    def _append_log_batch_to_widget(self, widget: QTextEdit, messages: list[str]) -> None:
        if not messages:
            return

        updates_enabled = widget.updatesEnabled()
        widget.setUpdatesEnabled(False)
        try:
            for msg in messages:
                widget.append(msg)
        finally:
            widget.setUpdatesEnabled(updates_enabled)
            widget.verticalScrollBar().setValue(widget.verticalScrollBar().maximum())

    def _queue_worker_log(self, msg: str) -> None:
        self._remember_log_message(msg)
        self._pending_worker_logs.append(msg)
        self._live_ui_dirty = True

    def _flush_pending_worker_logs(self) -> None:
        if not self._pending_worker_logs:
            return

        messages = self._pending_worker_logs
        self._pending_worker_logs = []

        if hasattr(self, "pcap_log_area"):
            self._append_log_batch_to_widget(self.pcap_log_area, messages)

        parsed_pcap_rows: list[tuple[str, str, str]] = []
        if hasattr(self, "events_list"):
            updates_enabled = self.events_list.updatesEnabled()
            self.events_list.setUpdatesEnabled(False)
        else:
            updates_enabled = True
        try:
            for msg in messages:
                plain = self._plain_log(msg)
                parsed = self._pcap_alert_from_log(msg, plain)
                if parsed:
                    parsed_pcap_rows.append(parsed)
                self._append_to_events_if_needed(msg, plain)
        finally:
            if hasattr(self, "events_list"):
                self.events_list.setUpdatesEnabled(updates_enabled)

        self._append_pcap_alert_rows(parsed_pcap_rows)

        if hasattr(self, "log_area"):
            visible_messages = [msg for msg in messages if self._is_log_message_visible(msg)]
            self._append_log_batch_to_widget(self.log_area, visible_messages)

    def append_log(self, msg: str) -> None:
        self._remember_log_message(msg)

        if hasattr(self, "pcap_log_area"):
            self.pcap_log_area.append(msg)
            self.pcap_log_area.verticalScrollBar().setValue(
                self.pcap_log_area.verticalScrollBar().maximum()
            )
            self._append_pcap_alert_from_log(msg)

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

    def _append_to_events_if_needed(self, msg: str, plain: str | None = None):
        if not hasattr(self, "events_list"):
            return

        important_tags = ["[VERDICT]", "[INCIDENT]", "[IOC]", "[IOC MATCH]", "[IOC DOMAIN MATCH]", "[SYSTEM]"]
        if any(tag in msg for tag in important_tags):
            plain = plain if plain is not None else self._plain_log(msg)
            self.events_list.insertItem(0, plain)

            while self.events_list.count() > 100:
                self.events_list.takeItem(self.events_list.count() - 1)

    # -------- alerts history --------
    def _mark_alerts_dirty(self) -> None:
        if hasattr(self, "_alerts_dirty"):
            self._alerts_dirty = True

    def _configure_alerts_table_columns(self) -> None:
        if not hasattr(self, "alerts_table"):
            return
        self.alerts_table.setColumnWidth(0, 170)
        self.alerts_table.setColumnWidth(1, 150)
        self.alerts_table.setColumnWidth(2, 128)
        self.alerts_table.setColumnWidth(3, 260)

    def _ensure_alert_filters_loaded(self) -> None:
        if not getattr(self, "_alert_filters_loaded", False):
            self.populate_alert_filters()

    def _current_alert_query_params(self) -> tuple:
        session_id = self.alert_session_filter.currentData()
        alert_type = self.alert_type_filter.currentData()
        verdict = self.alert_verdict_filter.currentData()
        search_text = self.alert_search_input.text().strip() or None

        started_from = None
        started_to = None
        if self.alert_period_checkbox.isChecked():
            started_from = self._alert_filter_datetime(self.alert_from_dt)
            started_to = self._alert_filter_datetime(self.alert_to_dt)

        return session_id, started_from, started_to, alert_type, verdict, search_text

    def ensure_alerts_loaded(self) -> None:
        self._ensure_alert_filters_loaded()
        query_params = self._current_alert_query_params()
        if (
            not getattr(self, "_alerts_loaded", False)
            or getattr(self, "_alerts_dirty", False)
            or query_params != getattr(self, "_last_alert_query_params", None)
        ):
            self.load_alerts_history()

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
        self.alert_verdict_filter.addItem("Любой вердикт", None)
        for verdict in ("malicious", "suspicious", "anomaly", "normal"):
            self.alert_verdict_filter.addItem(verdict.upper(), verdict)
        self._alert_filters_loaded = True

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
        self._ensure_alert_filters_loaded()
        query_params = self._current_alert_query_params()
        session_id, started_from, started_to, alert_type, verdict, search_text = query_params

        self.alert_rows = query_alerts(
            session_id=session_id,
            started_from=started_from,
            started_to=started_to,
            alert_type=alert_type,
            verdict=verdict,
            search_text=search_text,
            limit=500,
        )
        self._last_alert_query_params = query_params
        self._alerts_loaded = True
        self._alerts_dirty = False
        self._alert_session_context_cache = {}
        self.render_alert_rows()

    def _verdict_badge_object(self, verdict: str) -> str:
        text = (verdict or "").upper()
        if text in {"INFO", "LOW", "NORMAL", "ANOMALY"}:
            return "verdict_badge_info"
        if text in {"WARNING", "WARN", "MEDIUM"}:
            return "verdict_badge_warning"
        if text in {"SUSPICIOUS"}:
            return "verdict_badge_suspicious"
        if text in {"CRITICAL", "HIGH", "MALICIOUS", "INCIDENT"}:
            return "verdict_badge_critical"
        return "verdict_badge_unknown"

    def _set_verdict_badge(self, label: QLabel, verdict: str) -> None:
        label.setText(verdict or "UNKNOWN")
        label.setObjectName(self._verdict_badge_object(verdict))
        self._refresh_widget_style(label)

    def _verdict_item_colors(self, verdict: str) -> tuple[QColor, QColor]:
        text = (verdict or "").upper()
        if text in {"INFO", "LOW", "NORMAL", "ANOMALY"}:
            return QColor("#dbeafe"), QColor("#1d4ed8")
        if text in {"WARNING", "WARN", "MEDIUM"}:
            return QColor("#fef3c7"), QColor("#b45309")
        if text in {"SUSPICIOUS"}:
            return QColor("#ffedd5"), QColor("#c2410c")
        if text in {"CRITICAL", "HIGH", "MALICIOUS", "INCIDENT"}:
            return QColor("#fee2e2"), QColor("#b91c1c")
        return QColor("#f1f5f9"), QColor("#475569")

    def _style_alert_verdict_item(self, item: QTableWidgetItem, verdict: str) -> None:
        background, foreground = self._verdict_item_colors(verdict)
        item.setBackground(QBrush(background))
        item.setForeground(QBrush(foreground))
        font = item.font()
        font.setBold(True)
        item.setFont(font)

    def _extract_alert_endpoints(self, description: str) -> tuple[str, str]:
        text = description or ""
        src = re.search(r"\bsrc=([^|\s]+)", text, flags=re.IGNORECASE)
        dst = re.search(r"\bdst=([^|\s]+)", text, flags=re.IGNORECASE)
        if src or dst:
            return (src.group(1) if src else "-", dst.group(1) if dst else "-")

        flow = re.search(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)\s*(?:->|→)\s*(\b(?:\d{1,3}\.){3}\d{1,3}\b)", text)
        if flow:
            return flow.group(1), flow.group(2)

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        unique_ips = list(dict.fromkeys(ips))
        if len(unique_ips) >= 2:
            return unique_ips[0], unique_ips[1]
        if len(unique_ips) == 1:
            return unique_ips[0], "-"
        return "-", "-"

    def _clear_alert_details_panel(self) -> None:
        if hasattr(self, "alert_summary_title"):
            self.alert_summary_title.setText("Детали алерта")
            self._set_verdict_badge(self.alert_summary_verdict, "UNKNOWN")
            self.alert_summary_time.setText("-")
            self.alert_summary_type.setText("-")
            self.alert_summary_source.setText("Источник: -")
            self.alert_summary_destination.setText("Назначение: -")
            self.alert_summary_description.setText("-")
            self.linked_session_label.setText(self._linked_alert_session_context(None))
        if hasattr(self, "alert_details"):
            self.alert_details.clear()

    def render_alert_rows(self):
        table = self.alerts_table
        updates_enabled = table.updatesEnabled()
        signals_blocked = table.blockSignals(True)
        table.setUpdatesEnabled(False)
        try:
            table.clearSelection()
            table.setRowCount(0)
            self.alerts_count_label.setText(f"Алерты: {len(self.alert_rows)}")
            self._clear_alert_details_panel()
            if hasattr(self, "alerts_empty_label"):
                self.alerts_empty_label.setVisible(not bool(self.alert_rows))
                table.setVisible(bool(self.alert_rows))

            table.setRowCount(len(self.alert_rows))
            for row_idx, row in enumerate(self.alert_rows):
                _alert_id, timestamp, _session_id, alert_type, description = row
                verdict = self._extract_alert_verdict(alert_type or "", description or "")
                display_verdict = verdict if verdict != "-" else "UNKNOWN"
                src, dst = self._extract_alert_endpoints(description or "")
                source_text = src if src != "-" else self._extract_alert_ips(description or "")
                if dst != "-":
                    source_text = f"{source_text} -> {dst}" if source_text != "-" else dst

                table.setRowHeight(row_idx, 62)
                values = [
                    timestamp or "-",
                    alert_type or "-",
                    display_verdict,
                    source_text,
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.ItemDataRole.UserRole, row_idx)
                    item.setToolTip(value)
                    if col == 2:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        self._style_alert_verdict_item(item, display_verdict)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    table.setItem(row_idx, col, item)
            self._configure_alerts_table_columns()
        finally:
            table.blockSignals(signals_blocked)
            table.setUpdatesEnabled(updates_enabled)
            table.viewport().update()

        if self.alert_rows:
            signals_blocked = table.blockSignals(True)
            try:
                table.setCurrentCell(0, 0)
            finally:
                table.blockSignals(signals_blocked)
            self.show_selected_alert_details()

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

    def _linked_alert_session_context(self, session_id) -> str:
        empty_text = "Нет связанной оценки сессии"
        if session_id is None:
            return empty_text

        cache = getattr(self, "_alert_session_context_cache", {})
        if session_id in cache:
            return cache[session_id]

        session_data = get_session_record(session_id)
        if session_data:
            session_context = f"""
ID сессии: {session_id}
IB Score: {session_data.get('final_ib_score') if session_data.get('final_ib_score') is not None else '-'}
Уровень IB: {session_data.get('final_ib_level') or '-'}
Уровень угрозы: {session_data.get('threat_level') or '-'}
Вероятность инцидента: {session_data.get('incident_probability') or '-'}
Достоверность: {session_data.get('confidence') or '-'}
Сводка: {session_data.get('summary_text') or '-'}
""".strip()
        else:
            session_context = empty_text

        cache[session_id] = session_context
        self._alert_session_context_cache = cache
        return session_context

    def show_selected_alert_details(self):
        row_idx = self.alerts_table.currentRow()
        if row_idx < 0:
            self._clear_alert_details_panel()
            return

        row_item = self.alerts_table.item(row_idx, 0)
        if row_item is not None:
            row_idx = row_item.data(Qt.ItemDataRole.UserRole)
        if row_idx is None or row_idx < 0 or row_idx >= len(self.alert_rows):
            self._clear_alert_details_panel()
            return

        alert_id, timestamp, session_id, alert_type, description = self.alert_rows[row_idx]
        verdict = self._extract_alert_verdict(alert_type or "", description or "")
        display_verdict = verdict if verdict != "-" else "UNKNOWN"
        ips = self._extract_alert_ips(description or "")
        src, dst = self._extract_alert_endpoints(description or "")
        session_context = self._linked_alert_session_context(session_id)
        if hasattr(self, "alert_summary_title"):
            self.alert_summary_title.setText(f"Детали алерта: ALR-{int(alert_id):03d}" if str(alert_id).isdigit() else f"Детали алерта: {alert_id}")
            self._set_verdict_badge(self.alert_summary_verdict, display_verdict)
            self.alert_summary_time.setText(timestamp or "-")
            self.alert_summary_type.setText(f"Тип: {alert_type or '-'}")
            self.alert_summary_source.setText(f"Источник: {src}")
            self.alert_summary_destination.setText(f"Назначение: {dst}")
            self.alert_summary_description.setText(description or "-")
            self.linked_session_label.setText(session_context)
        detail = f"""ID: {alert_id}
Время: {timestamp or '-'}
ID сессии: {session_id if session_id is not None else '-'}
Тип: {alert_type or '-'}
Вердикт: {display_verdict}
Источник: {src}
Назначение: {dst}
IPs: {ips}

Описание:
{description or '-'}
"""
        self.alert_details.setText(detail)

    # -------- sessions --------
    def _format_session_duration(self, duration) -> str:
        try:
            seconds = int(duration or 0)
        except (TypeError, ValueError):
            seconds = 0
        minutes, sec = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours:02d}:{minutes:02d}:{sec:02d}"

    def _format_session_date(self, started) -> str:
        text = str(started or "-")
        return text[:10] if len(text) >= 10 else text

    def _session_list_text(self, row: tuple) -> str:
        session_id, started, duration, profile, iface, score = row
        score_text = score if score is not None else "-"
        return f"sess-{int(session_id):03d}     {self._format_session_date(started)}\nДлительность: {self._format_session_duration(duration)} | IB Score: {score_text}"

    def apply_session_filter(self) -> None:
        self.render_sessions_list()

    def render_sessions_list(self) -> None:
        self.sessions_list.clear()
        rows = getattr(self, "_session_rows", [])
        query = ""
        if hasattr(self, "sessions_search"):
            query = self.sessions_search.text().strip().lower()

        visible_rows = []
        for row in rows:
            session_id, started, duration, profile, iface, score = row
            haystack = " ".join(str(part or "") for part in (session_id, started, duration, profile, iface, score)).lower()
            if not query or query in haystack:
                visible_rows.append(row)

        if not visible_rows:
            item = QListWidgetItem("Сессий пока нет")
            item.setData(Qt.ItemDataRole.UserRole, None)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.sessions_list.addItem(item)
            self._clear_session_details()
            return

        for row in visible_rows:
            session_id = row[0]
            item = QListWidgetItem(self._session_list_text(row))
            item.setData(Qt.ItemDataRole.UserRole, session_id)
            item.setSizeHint(QSize(0, 76))
            self.sessions_list.addItem(item)

        self.sessions_list.setCurrentRow(0)
        self.show_session_details(self.sessions_list.item(0))

    def _clear_session_details(self) -> None:
        if hasattr(self, "session_score_value"):
            self.session_score_value.setText("-")
            self.session_score_level.setText("-")
            self.session_threat_badge.setText("Угроза: -")
            self.session_incident_badge.setText("Инцидент: -")
            self.session_confidence_badge.setText("Достоверность: -")
            self.session_explanation_label.setText("Выберите сессию слева.")
            self.session_comparison_label.setText("Нет данных для сравнения")
            for label in self.session_stat_labels.values():
                label.setText("-")

    def load_sessions(self):
        init_db()
        self._session_rows = get_sessions()
        self.render_sessions_list()

    def show_session_details(self, item):
        session_id = item.data(Qt.ItemDataRole.UserRole)
        if hasattr(self, "session_score_value"):
            if session_id is None:
                self._clear_session_details()
                return

            s = get_session_record(session_id)
            if not s:
                self._clear_session_details()
                return

            previous = get_previous_session_record(session_id)
            comparison = self._comparison_text(s, previous)
            assessment_details = self._stored_assessment_text(s)
            score = s.get("final_ib_score")

            self.session_score_value.setText(str(score) if score is not None else "-")
            self.session_score_level.setText(s.get("final_ib_level") or "-")
            self.session_threat_badge.setText(f"Угроза: {s.get('threat_level') or '-'}")
            self.session_incident_badge.setText(f"Инцидент: {s.get('incident_probability') or '-'}")
            self.session_confidence_badge.setText(f"Достоверность: {s.get('confidence') or '-'}")
            self.session_explanation_label.setText(s.get("summary_text") or assessment_details or "-")
            self.session_comparison_label.setText(comparison or "Нет данных для сравнения")
            self.session_stat_labels["packets"].setText(f"{int(s.get('total_packets') or 0):,}")
            self.session_stat_labels["duration"].setText(self._format_session_duration(s.get("duration_sec")))
            self.session_stat_labels["anomalies"].setText(f"{int(s.get('total_anomalies') or 0):,}")
            self.session_stat_labels["ioc"].setText(f"{int(s.get('total_ioc_matches') or 0):,}")
            return
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
СЕССИЯ
ID: {s.get('id')}
Старт: {s.get('started_at') or '-'}
Стоп: {s.get('stopped_at') or '-'}
Длительность: {s.get('duration_sec') or 0} сек.

Профиль: {s.get('profile_name') or '-'}
Интерфейс: {s.get('interface_name') or '-'}

ОЦЕНКА БЕЗОПАСНОСТИ
IB Score: {s.get('final_ib_score') if s.get('final_ib_score') is not None else '-'}
Уровень IB: {s.get('final_ib_level') or '-'}
Уровень угрозы: {s.get('threat_level') or '-'}
Вероятность инцидента: {s.get('incident_probability') or '-'}
Достоверность: {s.get('confidence') or '-'}
Общий риск: {s.get('total_risk') if s.get('total_risk') is not None else '-'}

Сводка:
{s.get('summary_text') or '-'}

ОБЪЯСНЕНИЕ
{assessment_details}

СТАТИСТИКА
Пакеты: {s.get('total_packets') or 0}
Аномалии: {s.get('total_anomalies') or 0}
Инциденты: {s.get('total_incidents') or 0}
IOC совпадения: {s.get('total_ioc_matches') or 0}

СРАВНЕНИЕ
{comparison}

Путь к отчёту:
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
            "HTML report (*.html)",
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

    def refresh_settings_profile_page(self) -> None:
        if not hasattr(self, "settings_profiles_list"):
            return

        pm = ProfileManager()
        active_filename = pm.get_active_filename() or "default.json"
        profiles = pm.list_profiles()
        active_profile = pm.load_profile(active_filename)
        data = active_profile.data or {}
        ml = data.get("ml") or {}

        self.settings_profiles_list.clear()
        active_row = 0
        for idx, profile in enumerate(profiles):
            display_name = profile.name or profile.filename
            item = QListWidgetItem(display_name)
            item.setToolTip(profile.filename)
            item.setData(Qt.ItemDataRole.UserRole, profile.filename)
            if profile.filename == active_profile.filename:
                active_row = idx
            self.settings_profiles_list.addItem(item)
        if self.settings_profiles_list.count():
            self.settings_profiles_list.setCurrentRow(active_row)

        profile_path = pm.profiles_dir / active_profile.filename
        try:
            updated = datetime.fromtimestamp(profile_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            updated = "-"

        iface = self.iface_combo.currentText() if hasattr(self, "iface_combo") and self.iface_combo.count() else "Автовыбор"
        sample_factor = int(data.get("sample_factor", getattr(self.engine, "sample_factor", 1)) or 1)
        pps_window = data.get("pps_window_sec", "-")
        scan_threshold = data.get("scan_ports_threshold", "-")
        dos_threshold = data.get("dos_pps_eff_threshold", "-")
        contamination = float(ml.get("contamination", 0.0) or 0.0)
        train_size = ml.get("train_size", ml.get("train_packets", "-"))
        estimators = ml.get("n_estimators", "-")
        ioc_count = len(getattr(self.engine, "malicious_ips", [])) + len(getattr(self.engine, "malicious_domains", []))
        sessions_count = len(get_sessions(limit=200))
        alerts_count = len(query_alerts(limit=200))
        db_path = Path(__file__).resolve().parents[1] / "storage" / "traffic_data.db"
        short_db_path = f".../{db_path.parent.name}/{db_path.name}"
        ml_percent = min(100, max(0, int(contamination * 10000)))
        anomaly_percent = min(100, max(0, int(int(scan_threshold or 0) / 100 * 100))) if str(scan_threshold).isdigit() else 0

        self.settings_status_title_lbl.setText(f"Статус активного профиля: {active_profile.name}")
        self.profile_name_lbl.setText(iface)
        self.settings_profile_file_lbl.setText(active_profile.filename)
        self.settings_profile_file_lbl.setToolTip(str(profile_path))
        self.settings_rules_count_lbl.setText(f"{scan_threshold} scan / {dos_threshold} pps")
        self.settings_model_lbl.setText(f"Isolation Forest, {estimators} деревьев")
        self.settings_updated_lbl.setText(updated)

        self.settings_interface_lbl.setText(iface)
        self.settings_interface_lbl.setToolTip(iface)
        self.sample_factor_lbl.setText(f"1 / {sample_factor} пакетов")
        self.settings_live_lbl.setText("Вкл.")
        self.settings_dpi_lbl.setText("Вкл.")
        self.settings_rule_lbl.setText(f"Стандартный выбран   |   окно {pps_window}s")
        self.ml_status_lbl.setText(f"{ml_percent}%  | обучение {train_size}, contamination {contamination:.3f}")
        self.settings_anom_lbl.setText(f"{anomaly_percent}%  | scan {scan_threshold}, DoS {dos_threshold}")
        self.settings_ioc_path_lbl.setText(short_db_path)
        self.settings_ioc_path_lbl.setToolTip(str(db_path))
        self.ioc_count_lbl.setText(f"{ioc_count} индикаторов загружено")
        self.settings_feeds_lbl.setText("AlienVault   MISP")
        self._refresh_threat_intel_settings()
        self.settings_report_lbl.setText("HTML")
        self.settings_report_options_lbl.setText("Инциденты вкл.  |  IOC совпадения вкл.  |  Сырые логи выкл.")
        self.settings_db_path_lbl.setText(short_db_path)
        self.settings_db_path_lbl.setToolTip(str(db_path))
        self.settings_db_counts_lbl.setText(f"{sessions_count} сессий  |  {alerts_count} алертов")

    # -------- profile --------
    def apply_profile_on_startup(self) -> None:
        try:
            pm = ProfileManager()
            active_name = pm.get_active_filename() or "default.json"
            prof = pm.load_profile(active_name)
            self.engine.apply_profile(prof.data, profile_name=prof.filename.replace(".json", ""))
            self.append_log(f"<b style='color:#2563eb;'>[PROFILE] Применён: {prof.name} ({prof.filename})</b>")
            self.update_assessment_panel()
            self.refresh_settings_profile_page()
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
            self.refresh_settings_profile_page()
        except Exception as e:
            self.append_log(f"<span style='color:#dc2626;'>[PROFILE ERROR] {type(e).__name__}: {e}</span>")

    # -------- worker --------
    def start_worker(self, mode: str, pcap_path: str | None = None) -> None:
        self.worker = CaptureWorker(self.engine, mode=mode, pcap_path=pcap_path)
        self.worker.message.connect(self.on_worker_message)
        self.worker.finished_signal.connect(self.on_worker_finished)
        self.worker.start()

    def on_worker_message(self, msg: str) -> None:
        self._queue_worker_log(msg)
        if time.monotonic() - self._last_live_ui_flush >= 0.5:
            self.flush_live_ui_updates()

    def on_worker_finished(self) -> None:
        self._force_graph_refresh = True
        self.flush_live_ui_updates(force=True)
        self.refresh_graphs()

        self.is_monitoring = False
        self.current_mode = "idle"

        self.action_btn.setEnabled(True)
        self.pcap_btn.setEnabled(True)
        self._set_pcap_enrichment_busy(False)
        if hasattr(self, "open_main_btn"):
            self.open_main_btn.setEnabled(True)
        self.settings_btn.setEnabled(True)
        self.settings_page_btn.setEnabled(True)

        self.action_btn.setText("Старт")
        self.action_btn.setObjectName("primary_btn")
        self._refresh_widget_style(self.action_btn)

        self.set_status_text("Статус: ожидание запуска")
        self.update_assessment_panel()
        self._update_pcap_file_summary()
        self.append_log("<b style='color:#2563eb;'>[SYSTEM] Мониторинг / анализ остановлен.</b>")

    # -------- actions --------
    def open_pcap(self) -> None:
        if self.is_monitoring:
            QMessageBox.information(self, "PCAP", "Сначала остановите текущий мониторинг.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите PCAP-файл",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)",
        )
        if not file_path:
            return

        self.switch_page(1)
        self.last_pcap_path = file_path
        self.clear_pcap_view()
        self._update_pcap_file_summary(file_path)
        self.is_monitoring = True
        self.current_mode = "pcap"

        self.action_btn.setEnabled(False)
        self.settings_btn.setEnabled(False)
        self.pcap_btn.setEnabled(False)
        self._set_pcap_enrichment_busy(True)
        if hasattr(self, "open_main_btn"):
            self.open_main_btn.setEnabled(False)
        self.settings_page_btn.setEnabled(False)

        self.set_status_text("Статус: offline-анализ PCAP")
        self.append_log(f"<b style='color:#2563eb;'>[SYSTEM] Запуск PCAP анализа: {file_path}</b>")
        self.start_worker(mode="pcap", pcap_path=file_path)

    def toggle_monitoring(self) -> None:
        if not self.is_monitoring:
            self.switch_page(0)
            self.is_monitoring = True
            self.current_mode = "live"
            self.action_btn.setText("Стоп")
            self.action_btn.setObjectName("stop_mode")
            self._refresh_widget_style(self.action_btn)

            self.settings_btn.setEnabled(False)
            self.pcap_btn.setEnabled(False)
            self._set_pcap_enrichment_busy(True)
            if hasattr(self, "open_main_btn"):
                self.open_main_btn.setEnabled(False)
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
        card.setObjectName("metric_card_primary" if title == "IB Score" else "metric_card")
        card.setMinimumHeight(76)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("metric_title")
        title_label.setWordWrap(True)

        value_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        subtitle_label.setWordWrap(True)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(8)
        header.addWidget(title_label, 1)
        header.addWidget(value_label, 0)

        layout.addLayout(header)
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
            "HTML report (*.html)",
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
        if index == 2:
            self.refresh_settings_profile_page()
        if index == 4 and hasattr(self, "alerts_table"):
            self.ensure_alerts_loaded()
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
        if hasattr(self, "sidebar"):
            self._apply_sidebar_state(refresh_styles=False)

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
