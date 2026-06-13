# -*- coding: utf-8 -*-
#
# Razreshenie VPN Client
# Copyright (C) 2026 Razreshenie VPN contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

"""PyQt6 Fluent GUI, переработанный по архитектуре zapret-kvn."""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from PyQt6.QtCore import (
    QEasingCurve,
    QObject,
    QSize,
    Qt,
    QTimer,
    QVariantAnimation,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QBrush,
    QCloseEvent,
    QColor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    FluentWindow,
    InfoBar,
    InfoBarPosition,
    NavigationItemPosition,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SearchLineEdit,
    SettingCard,
    SettingCardGroup,
    SmoothScrollArea,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    SwitchSettingCard,
    TableWidget,
    Theme,
    setTheme,
    setThemeColor,
)

from gui.common import (
    ACCENT,
    DANGER,
    FLAG_ICON_SIZE,
    SUCCESS,
    app_logo_icon,
    create_logo_label,
    install_emoji_font_fallbacks,
    protocol_label,
    server_display_text_and_icon,
    server_label_html,
)
from gui.dialogs import (
    MATCH_KIND_PROCESS_NAME,
    MATCH_KIND_PROCESS_PATH,
    MATCH_KIND_PROCESS_PATH_REGEX,
    ONBOARDING_ACTION_ADD_SUBSCRIPTION,
    ONBOARDING_ACTION_DOWNLOAD_CORE,
    ONBOARDING_ACTION_IMPORT_SERVER,
    ONBOARDING_ACTION_OPEN_SETTINGS,
    ONBOARDING_ACTION_SKIP,
    OnboardingDialog,
    OnboardingResult,
    PerAppRuleDialog,
)
from gui.pages.activity import DomainActivityPage
from gui.widgets import JsonEditorDialog, TrafficGraphWidget, _LineCard, _SpinCard
from core import app_state
from core.app_updater import AppUpdateInfo, check_for_app_update, download_update_asset
from core.connectivity import ConnectivityCheckResult, normalize_connectivity_timeout_ms, normalize_connectivity_urls
from core.diagnostics import build_diagnostics_archive
from core.domain_activity import DomainActivityTracker
from core.error_messages import format_safe_traceback, format_user_error, sanitize_error_text
from core.latency_scanner import LatencyScanner, LatencyScanSummary
from core.rules_manager import RulesImportError, RulesImportResult, RulesManager
from core.smart_connect import SmartConnectManager
from core.singbox_manager import SingBoxError, SingBoxManager
from core.subscription_manager import SubscriptionFetchResult, SubscriptionManager
from models.connection import ServerQualityStats
from models.profile import Subscription, VlessProfile, utc_now_iso
from models.rules import (
    BUILTIN_DIRECT_DOMAIN_SUFFIXES,
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    domain_site_suffix,
    normalize_outbound,
)
from models.settings import (
    BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS,
    BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
    BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
    DEFAULT_TUN_IPV6_ADDRESS,
    DNS_STRATEGY_IPV4_ONLY,
    DNS_STRATEGY_IPV6_ONLY,
    DNS_STRATEGY_PREFER_IPV4,
    DNS_STRATEGY_PREFER_IPV6,
    SELF_HEALING_DEFAULT_COOLDOWN_SECONDS,
    SELF_HEALING_DEFAULT_MAX_ATTEMPTS,
    SELF_HEALING_MAX_COOLDOWN_SECONDS,
    SELF_HEALING_MAX_MAX_ATTEMPTS,
    SELF_HEALING_MIN_COOLDOWN_SECONDS,
    SELF_HEALING_MIN_MAX_ATTEMPTS,
    AppSettings,
    normalize_dns_strategy,
)
from utils import paths, windows
from utils.app_logger import LogBuffer, setup_logger
from utils.network import (
    TrafficMonitor,
    check_dns_resolver,
    format_bytes,
    format_speed,
    get_public_ip,
    measure_server_latency_ms,
)
from utils.scheduler import RepeatingTask
from utils.version import (
    APP_NAME,
    FLAG_ICONS_REPOSITORY,
    APP_REPOSITORY,
    APP_VERSION,
    RUSSIA_MOBILE_WHITELIST_REPOSITORY,
    ZAPRET_KVN_REPOSITORY,
)


LATENCY_SCAN_TIMEOUT_MS = 15000
LATENCY_SCAN_WORKERS = 20
LATENCY_BATCH_SIZE = 48
LATENCY_BATCH_INTERVAL_SECONDS = 0.25
LATENCY_UI_DRAIN_INTERVAL_MS = 16
LATENCY_UI_DRAIN_LIMIT = 24
SMART_CONNECT_SCAN_LIMIT = 8
SERVER_LATENCY_FAST_MS = 180
SERVER_LATENCY_OK_MS = 450
SERVER_QUALITY_GOOD_PERCENT = 90
SERVER_QUALITY_OK_PERCENT = 70
LIVE_ACTIVITY_RULE_SOURCE_TYPE = "live_activity"
LIVE_ACTIVITY_RULE_SOURCE = "Live Activity"
PER_APP_RULE_SOURCE_TYPE = "per_app"
PER_APP_RULE_SOURCE = "Per-app routing"
class UiBridge(QObject):
    call = pyqtSignal(object)
    log_line = pyqtSignal(str, str)
    activity_changed = pyqtSignal()


class DashboardPage(QWidget):
    toggle_connection_requested = pyqtSignal()
    profile_selected = pyqtSignal(str)
    mode_changed = pyqtSignal(str)
    import_requested = pyqtSignal()
    dns_requested = pyqtSignal()
    download_core_requested = pyqtSignal()
    rules_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("dashboard")
        self._profile_ids: list[str] = []
        self._peak_down_bps = 0.0
        self._peak_up_bps = 0.0

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = SmoothScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        scroll.setWidget(container)
        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        brand_row = QHBoxLayout()
        brand_row.setSpacing(12)
        brand_row.addWidget(create_logo_label(container, 54))
        brand_text = QVBoxLayout()
        brand_text.setSpacing(2)
        brand_text.addWidget(SubtitleLabel(f"{APP_NAME} {APP_VERSION}", container))
        slogan = CaptionLabel("Разреши себе доступ к любым сайтам", container)
        slogan.setStyleSheet(f"color: {ACCENT};")
        summary = CaptionLabel("Панель управления подключением, маршрутизацией и трафиком.", container)
        summary.setWordWrap(True)
        brand_text.addWidget(slogan)
        brand_text.addWidget(summary)
        brand_row.addLayout(brand_text, 1)
        brand_row.addStretch(1)
        root.addLayout(brand_row)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        root.addLayout(cards)

        self.connection_card = CardWidget(container)
        connection_layout = QVBoxLayout(self.connection_card)
        connection_layout.setContentsMargins(18, 16, 18, 16)
        connection_layout.setSpacing(8)
        connection_layout.addWidget(StrongBodyLabel("Подключение", self.connection_card))
        self.connection_state = SubtitleLabel("Отключено", self.connection_card)
        self.connection_state.setStyleSheet(f"color: {DANGER}; font-weight: 700;")
        self.connection_status = CaptionLabel("Core остановлен", self.connection_card)
        self.connection_status.setWordWrap(True)
        self.profile_combo = ComboBox(self.connection_card)
        self.profile_combo.setIconSize(FLAG_ICON_SIZE)
        self.mode_combo = ComboBox(self.connection_card)
        self.mode_combo.addItem("Proxy", userData="proxy")
        self.mode_combo.addItem("TUN", userData="tun")
        self.toggle_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Подключить", self.connection_card)
        connection_layout.addWidget(self.connection_state)
        connection_layout.addWidget(self.connection_status)
        connection_layout.addWidget(BodyLabel("Активный профиль", self.connection_card))
        connection_layout.addWidget(self.profile_combo)
        connection_layout.addWidget(BodyLabel("Режим", self.connection_card))
        connection_layout.addWidget(self.mode_combo)
        connection_layout.addWidget(self.toggle_btn)
        connection_layout.addStretch(1)
        cards.addWidget(self.connection_card, 1)

        self.routing_card = CardWidget(container)
        routing_layout = QVBoxLayout(self.routing_card)
        routing_layout.setContentsMargins(18, 16, 18, 16)
        routing_layout.setSpacing(8)
        routing_layout.addWidget(StrongBodyLabel("Маршрутизация", self.routing_card))
        self.routing_label = BodyLabel("Proxy / TUN", self.routing_card)
        self.rules_label = CaptionLabel("Правила: отключены", self.routing_card)
        self.rules_label.setWordWrap(True)
        self.open_rules_btn = PushButton(FIF.CODE, "Открыть правила", self.routing_card)
        routing_layout.addWidget(self.routing_label)
        routing_layout.addWidget(self.rules_label)
        routing_layout.addStretch(1)
        routing_layout.addWidget(self.open_rules_btn)
        cards.addWidget(self.routing_card, 1)

        self.total_traffic_card = CardWidget(container)
        total_traffic_layout = QVBoxLayout(self.total_traffic_card)
        total_traffic_layout.setContentsMargins(18, 16, 18, 16)
        total_traffic_layout.setSpacing(8)
        total_traffic_layout.addWidget(StrongBodyLabel("Общий трафик", self.total_traffic_card))
        totals = QHBoxLayout()
        totals.setSpacing(10)
        total_down_block, self.total_download_label = self._metric_block("Прибыло", "0 Б", "#00B4FF", self.total_traffic_card)
        total_up_block, self.total_upload_label = self._metric_block("Отправлено", "0 Б", "#00DC78", self.total_traffic_card)
        totals.addWidget(total_down_block, 1)
        totals.addWidget(total_up_block, 1)
        total_traffic_layout.addLayout(totals)
        total_traffic_layout.addStretch(1)
        cards.addWidget(self.total_traffic_card, 1)

        self.traffic_card = CardWidget(container)
        traffic_layout = QVBoxLayout(self.traffic_card)
        traffic_layout.setContentsMargins(18, 16, 18, 16)
        traffic_layout.setSpacing(8)
        traffic_header = QHBoxLayout()
        traffic_header.addWidget(StrongBodyLabel("Трафик", self.traffic_card))
        traffic_header.addStretch(1)
        self.ip_label = CaptionLabel("IP: —", self.traffic_card)
        self.ping_label = CaptionLabel("Пинг: —", self.traffic_card)
        traffic_header.addWidget(self.ip_label)
        traffic_header.addWidget(self.ping_label)
        traffic_layout.addLayout(traffic_header)

        speed_metrics = QHBoxLayout()
        speed_metrics.setSpacing(10)
        down_block, self.down_speed_label = self._metric_block("Download", "0.0 Б/с", "#00B4FF", self.traffic_card)
        up_block, self.up_speed_label = self._metric_block("Upload", "0.0 Б/с", "#00DC78", self.traffic_card)
        current_block, self.speed_label = self._metric_block("Сейчас всего", "0.0 Б/с", "#F9A825", self.traffic_card)
        peak_block, self.peak_speed_label = self._metric_block("Пик сессии", "↓ 0.0 Б/с · ↑ 0.0 Б/с", "#C8D6E5", self.traffic_card)
        speed_metrics.addWidget(down_block, 1)
        speed_metrics.addWidget(up_block, 1)
        speed_metrics.addWidget(current_block, 1)
        speed_metrics.addWidget(peak_block, 2)
        traffic_layout.addLayout(speed_metrics)
        self.graph = TrafficGraphWidget(self.traffic_card)
        traffic_layout.addWidget(self.graph)
        root.addWidget(self.traffic_card)

        actions = QHBoxLayout()
        self.import_btn = PrimaryPushButton(FIF.ADD, "Импортировать сервер", container)
        self.dns_btn = PushButton(FIF.LINK, "Проверить DNS", container)
        self.core_btn = PushButton(FIF.DOWNLOAD, "Скачать/обновить sing-box", container)
        actions.addWidget(self.import_btn)
        actions.addWidget(self.dns_btn)
        actions.addWidget(self.core_btn)
        actions.addStretch(1)
        root.addLayout(actions)
        root.addStretch(1)

        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.toggle_btn.clicked.connect(self.toggle_connection_requested)
        self.import_btn.clicked.connect(self.import_requested)
        self.dns_btn.clicked.connect(self.dns_requested)
        self.core_btn.clicked.connect(self.download_core_requested)
        self.open_rules_btn.clicked.connect(self.rules_requested)

    @staticmethod
    def _metric_block(title: str, value: str, color: str, parent: QWidget) -> tuple[QWidget, StrongBodyLabel]:
        block = QWidget(parent)
        block.setStyleSheet("QWidget { background: transparent; }")
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        caption = CaptionLabel(title, block)
        caption.setStyleSheet("color: rgba(255, 255, 255, 150);")
        label = StrongBodyLabel(value, block)
        label.setWordWrap(True)
        label.setStyleSheet(f"color: {color}; font-weight: 700;")
        layout.addWidget(caption)
        layout.addWidget(label)
        return block, label

    def set_profiles(self, profiles: list[VlessProfile], active_id: str | None) -> None:
        self._profile_ids.clear()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        selected_index = 0
        for index, profile in enumerate(profiles):
            server_name, flag = server_display_text_and_icon(profile.name, profile.address)
            combo_text = f"{server_name}  [{protocol_label(profile)}]  ({profile.address}:{profile.port})"
            self.profile_combo.addItem(combo_text, icon=flag)
            self._profile_ids.append(profile.id)
            if active_id and profile.id == active_id:
                selected_index = index
        if profiles:
            self.profile_combo.setEnabled(True)
            self.profile_combo.setCurrentIndex(selected_index)
            active_profile = profiles[selected_index]
            self.connection_status.setText(server_label_html(f"{protocol_label(active_profile)}  ·  {active_profile.label}"))
        else:
            self.profile_combo.addItem("Нет профилей")
            self.profile_combo.setEnabled(False)
            self.connection_status.setText("Активный профиль не выбран")
        self.profile_combo.blockSignals(False)

    def set_active_profile(self, profile: VlessProfile) -> None:
        if profile.id in self._profile_ids:
            self.profile_combo.blockSignals(True)
            self.profile_combo.setCurrentIndex(self._profile_ids.index(profile.id))
            self.profile_combo.blockSignals(False)
        self.connection_status.setText(server_label_html(f"{protocol_label(profile)}  ·  {profile.label}"))

    def set_mode(self, mode: str) -> None:
        index = 1 if mode == "tun" else 0
        self.mode_combo.blockSignals(True)
        self.mode_combo.setCurrentIndex(index)
        self.mode_combo.blockSignals(False)
        self.routing_label.setText("TUN: системный туннель" if mode == "tun" else "Proxy: SOCKS5 + HTTP")

    def set_connection(self, connected: bool, busy: bool = False, message: str | None = None) -> None:
        if busy:
            self.connection_state.setText(message or "Выполняется…")
            self.connection_state.setStyleSheet("color: #F9A825; font-weight: 700;")
            self.toggle_btn.setEnabled(False)
            return
        self.toggle_btn.setEnabled(True)
        if connected:
            self.connection_state.setText("Подключено")
            self.connection_state.setStyleSheet(f"color: {SUCCESS}; font-weight: 700;")
            self.toggle_btn.setText("Отключить")
            self.toggle_btn.setIcon(FIF.PAUSE_BOLD)
        else:
            self.connection_state.setText("Отключено")
            self.connection_state.setStyleSheet(f"color: {DANGER}; font-weight: 700;")
            self.toggle_btn.setText("Подключить")
            self.toggle_btn.setIcon(FIF.PLAY_SOLID)

    def set_metrics(
        self,
        ip: str,
        ping: str,
        speed: str,
        down_bps: float,
        up_bps: float,
        total_down: str,
        total_up: str,
    ) -> None:
        self.ip_label.setText(ip)
        self.ping_label.setText(ping)
        safe_down = max(0.0, float(down_bps or 0.0))
        safe_up = max(0.0, float(up_bps or 0.0))
        self._peak_down_bps = max(self._peak_down_bps, safe_down)
        self._peak_up_bps = max(self._peak_up_bps, safe_up)
        self.down_speed_label.setText(format_speed(safe_down))
        self.up_speed_label.setText(format_speed(safe_up))
        self.speed_label.setText(format_speed(safe_down + safe_up))
        self.speed_label.setToolTip(speed)
        self.peak_speed_label.setText(f"↓ {format_speed(self._peak_down_bps)} · ↑ {format_speed(self._peak_up_bps)}")
        self.total_download_label.setText(total_down)
        self.total_upload_label.setText(total_up)
        self.graph.add_point(down_bps, up_bps)

    def set_rules_summary(self, text: str) -> None:
        self.rules_label.setText(text)

    def clear_graph(self) -> None:
        self._peak_down_bps = 0.0
        self._peak_up_bps = 0.0
        self.down_speed_label.setText("0.0 Б/с")
        self.up_speed_label.setText("0.0 Б/с")
        self.speed_label.setText("0.0 Б/с")
        self.speed_label.setToolTip("")
        self.peak_speed_label.setText("↓ 0.0 Б/с · ↑ 0.0 Б/с")
        self.total_download_label.setText("0 Б")
        self.total_upload_label.setText("0 Б")
        self.graph.clear_data()

    def _on_profile_changed(self, index: int) -> None:
        if 0 <= index < len(self._profile_ids):
            self.profile_selected.emit(self._profile_ids[index])

    def _on_mode_changed(self, _index: int) -> None:
        self.mode_changed.emit(str(self.mode_combo.currentData() or "proxy"))


class ServersPage(QWidget):
    import_requested = pyqtSignal()
    import_files_requested = pyqtSignal()
    failover_group_requested = pyqtSignal(str)
    activate_requested = pyqtSignal(str)
    edit_requested = pyqtSignal(str)
    delete_requested = pyqtSignal(str)
    ping_requested = pyqtSignal(str)
    ping_all_requested = pyqtSignal()
    sort_latency_requested = pyqtSignal()
    validate_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("servers")
        self._profiles: list[VlessProfile] = []
        self._profile_by_id: dict[str, VlessProfile] = {}
        self._quality_stats: dict[str, ServerQualityStats] = {}
        self._subscription_names: dict[str, str] = {}
        self._collapsed_groups: set[str] = set()
        self._row_entries: list[tuple[str, str]] = []
        self._visible_ids: list[str] = []
        self._row_by_id: dict[str, int] = {}
        self._active_id: str | None = None
        self._group_animation: QVariantAnimation | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Серверы", self))

        filters = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Поиск серверов")
        self.sort_combo = ComboBox(self)
        for item in ("Вручную", "Имя", "Пинг", "Качество"):
            self.sort_combo.addItem(item)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.sort_combo)
        root.addLayout(filters)

        toolbar = QHBoxLayout()
        self.import_btn = PrimaryPushButton(FIF.ADD, "Импорт", self)
        self.import_menu = QMenu(self)
        self.import_text_action = QAction("Из текста", self)
        self.import_files_action = QAction("Из файлов", self)
        self.import_menu.addAction(self.import_text_action)
        self.import_menu.addAction(self.import_files_action)
        self.import_btn.setMenu(self.import_menu)
        self.edit_btn = PushButton(FIF.EDIT, "JSON", self)
        self.ping_btn = PushButton(FIF.SEND, "Пинг выбранного", self)
        self.ping_all_btn = PushButton(FIF.SYNC, "Пинг всех", self)
        self.ping_all_btn.setFixedWidth(150)
        self.sort_ping_btn = PushButton(FIF.SPEED_HIGH, "Сортировать по отклику", self)
        self.failover_btn = PushButton(FIF.LINK, "Failover-группа", self)
        self.validate_btn = PushButton(FIF.CODE, "Проверить config", self)
        self.delete_btn = PushButton(FIF.DELETE, "Удалить", self)
        for widget in (
            self.import_btn,
            self.edit_btn,
            self.ping_btn,
            self.ping_all_btn,
            self.sort_ping_btn,
            self.failover_btn,
            self.validate_btn,
            self.delete_btn,
        ):
            toolbar.addWidget(widget)
        toolbar.addStretch(1)
        root.addLayout(toolbar)

        self.table = TableWidget(self)
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["Название", "Группа", "Адрес", "Порт", "Тип", "Пинг", "Качество", "Активен"])
        self.table.setIconSize(FLAG_ICON_SIZE)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(34)
        fixed_columns = {3: 72, 4: 96, 5: 116, 6: 134, 7: 86}
        for col, width in fixed_columns.items():
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(col, width)
        root.addWidget(self.table, 1)

        self.search.textChanged.connect(self.reload)
        self.sort_combo.currentIndexChanged.connect(self.reload)
        self.table.cellPressed.connect(self._activate_pressed_cell)
        self.import_btn.clicked.connect(self.import_requested)
        self.import_text_action.triggered.connect(lambda _checked=False: self.import_requested.emit())
        self.import_files_action.triggered.connect(lambda _checked=False: self.import_files_requested.emit())
        self.edit_btn.clicked.connect(lambda: self._emit_for_selected(self.edit_requested))
        self.delete_btn.clicked.connect(lambda: self._emit_for_selected(self.delete_requested))
        self.ping_btn.clicked.connect(lambda: self._emit_for_selected(self.ping_requested))
        self.ping_all_btn.clicked.connect(self.ping_all_requested)
        self.sort_ping_btn.clicked.connect(self.sort_latency_requested)
        self.failover_btn.clicked.connect(lambda: self._emit_for_selected(self.failover_group_requested))
        self.validate_btn.clicked.connect(self.validate_requested)

    def set_profiles(
        self,
        profiles: list[VlessProfile],
        active_id: str | None,
        subscriptions: list[Subscription] | None = None,
        quality_stats: dict[str, ServerQualityStats] | None = None,
    ) -> None:
        self._profiles = list(profiles)
        self._profile_by_id = {profile.id: profile for profile in self._profiles}
        if quality_stats is not None:
            self._quality_stats = dict(quality_stats)
        if subscriptions is not None:
            self._subscription_names = {subscription.id: subscription.name for subscription in subscriptions}
        self._active_id = active_id
        self.reload()

    def set_quality_stats(self, quality_stats: dict[str, ServerQualityStats]) -> None:
        self._quality_stats = dict(quality_stats)

    def set_active_id(self, active_id: str | None) -> None:
        if self._active_id == active_id:
            return
        previous_id = self._active_id
        self._active_id = active_id
        self._update_active_row(previous_id)
        self._update_active_row(active_id)

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._row_entries):
            entry_type, entry_id = self._row_entries[row]
            if entry_type == "profile":
                return entry_id
        return None

    def reload(self) -> None:
        selected_id = self.selected_id()
        query = self.search.text().strip().lower()
        sort_mode = self.sort_combo.currentText()
        rows = self._build_rows(query, sort_mode)

        self._row_entries = [(row_type, row_id) for row_type, row_id, _profile in rows]
        self._visible_ids = [row_id for row_type, row_id, _profile in rows if row_type == "profile"]
        self._row_by_id = {
            row_id: row
            for row, (row_type, row_id, _profile) in enumerate(rows)
            if row_type == "profile"
        }
        self.table.setUpdatesEnabled(False)
        try:
            if hasattr(self.table, "clearSpans"):
                self.table.clearSpans()
            self.table.clearContents()
            self.table.setRowCount(len(rows))
            for row, (row_type, row_id, profile) in enumerate(rows):
                if row_type == "group":
                    self._set_group_row(row, row_id)
                    continue
                if profile is None:
                    continue
                self.table.setRowHeight(row, self._profile_row_height())
                display_name, flag = server_display_text_and_icon(profile.name, profile.address)
                values = [
                    display_name,
                    self._profile_group_label(profile),
                    profile.address,
                    str(profile.port),
                    protocol_label(profile),
                    self._latency_label(profile),
                    self._quality_label(profile),
                    "Да" if profile.id == getattr(self, "_active_id", None) else "",
                ]
                for col, value in enumerate(values):
                    table_item = QTableWidgetItem(value)
                    if col == 0:
                        if flag:
                            table_item.setIcon(flag)
                    if col in (0, 1, 5, 6):
                        table_item.setToolTip(self._profile_tooltip(profile))
                    if col in (3, 4, 5, 6, 7):
                        table_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    table_item.setData(Qt.ItemDataRole.UserRole, profile.id)
                    self.table.setItem(row, col, table_item)
                self._paint_row(row, profile.id == getattr(self, "_active_id", None))
            target_id = selected_id if selected_id in self._visible_ids else getattr(self, "_active_id", None)
            target_row = self._row_by_id.get(target_id)
            if target_row is not None:
                self.table.selectRow(target_row)
        finally:
            self.table.setUpdatesEnabled(True)
            self.table.viewport().update()

    def _build_rows(self, query: str, sort_mode: str) -> list[tuple[str, str, VlessProfile | None]]:
        groups: dict[str, list[VlessProfile]] = {}
        group_order: list[str] = []
        for profile in self._profiles:
            group_id = self._group_id(profile)
            if group_id not in groups:
                groups[group_id] = []
                group_order.append(group_id)
            groups[group_id].append(profile)

        rows: list[tuple[str, str, VlessProfile | None]] = []
        for group_id in group_order:
            group_profiles = groups[group_id]
            group_title = self._group_name(group_id)
            if query:
                if query in group_title.lower():
                    items = list(group_profiles)
                else:
                    items = [
                        profile
                        for profile in group_profiles
                        if query in profile.name.lower()
                        or query in profile.address.lower()
                        or query in profile.protocol.lower()
                        or query in self._profile_group_label(profile).lower()
                        or query in str(profile.source_name or "").lower()
                        or any(query in str(tag or "").lower() for tag in profile.tags)
                    ]
            else:
                items = list(group_profiles)
            if not items:
                continue
            if sort_mode == "Имя":
                items.sort(key=lambda item: item.name.lower())
            elif sort_mode == "Пинг":
                items.sort(key=lambda item: (item.latency_ms is None, item.latency_ms or 10**9, item.name.lower()))
            elif sort_mode == "Качество":
                items.sort(key=self._quality_sort_key)
            rows.append(("group", group_id, None))
            if query or group_id not in self._collapsed_groups:
                rows.extend(("profile", profile.id, profile) for profile in items)
        return rows

    @staticmethod
    def _group_id(profile: VlessProfile) -> str:
        subscription_key = profile.subscription_id or "__manual__"
        group_name = " ".join(str(profile.group or "").split())
        if group_name:
            return f"{subscription_key}::{group_name}"
        return subscription_key

    def _group_name(self, group_id: str) -> str:
        subscription_id, _, server_group = group_id.partition("::")
        if subscription_id == "__manual__":
            base_name = "Без подписки"
        else:
            base_name = self._subscription_names.get(subscription_id) or "Подписка"
        if server_group:
            return f"{base_name} / {server_group}"
        return base_name

    def _group_count(self, group_id: str) -> int:
        return sum(1 for profile in self._profiles if self._group_id(profile) == group_id)

    def _set_group_row(self, row: int, group_id: str) -> None:
        collapsed = group_id in self._collapsed_groups and not self.search.text().strip()
        arrow = "▸" if collapsed else "▾"
        count = self._group_count(group_id)
        group_name, flag = server_display_text_and_icon(self._group_name(group_id), self._group_name(group_id))
        label = f"{arrow}  {group_name}  ·  {count} серверов"
        item = QTableWidgetItem(label)
        if flag:
            item.setIcon(flag)
        item.setData(Qt.ItemDataRole.UserRole, group_id)
        item.setForeground(QColor("#F2F2F2"))
        item.setBackground(QColor("#303030"))
        self.table.setItem(row, 0, item)
        self.table.setSpan(row, 0, 1, self.table.columnCount())
        self.table.setRowHeight(row, self._group_row_height())

    def _latency_label(self, profile: VlessProfile) -> str:
        if profile.latency_ms is not None:
            prefix = self._latency_badge(profile.latency_ms)
            return f"{prefix} {profile.latency_ms} ms"
        if profile.latency_checked_at:
            return "Таймаут"
        return "—"

    def _quality_label(self, profile: VlessProfile) -> str:
        stats = self._quality_stats.get(profile.id)
        if not stats:
            return "—"
        latency = stats.recent_average_latency_ms or int(stats.latency_ewma_ms or 0) or stats.last_latency_ms
        latency_text = f"{latency} ms" if latency else "—"
        return f"{int(stats.recent_success_rate * 100)}% · {latency_text}"

    @staticmethod
    def _latency_badge(latency_ms: int) -> str:
        if latency_ms <= SERVER_LATENCY_FAST_MS:
            return "Быстро"
        if latency_ms <= SERVER_LATENCY_OK_MS:
            return "Норм"
        return "Медленно"

    def _quality_sort_key(self, profile: VlessProfile) -> tuple[int, int, int, str]:
        stats = self._quality_stats.get(profile.id)
        if not stats:
            return (1, 0, 10**9, profile.name.lower())
        latency = stats.recent_average_latency_ms or int(stats.latency_ewma_ms or 0) or stats.last_latency_ms or 10**9
        return (0, -int(stats.recent_success_rate * 100), latency, profile.name.lower())

    @staticmethod
    def _profile_group_label(profile: VlessProfile) -> str:
        group = " ".join(str(profile.group or "").split())
        if group:
            return group
        tags = [" ".join(str(tag or "").split()) for tag in profile.tags]
        tags = [tag for tag in tags if tag]
        return ", ".join(tags[:3]) if tags else "—"

    def _profile_tooltip(self, profile: VlessProfile) -> str:
        parts = [
            profile.name,
            f"{profile.address}:{profile.port}" if profile.address else "",
            f"Тип: {protocol_label(profile)}",
        ]
        if profile.group:
            parts.append(f"Группа: {profile.group}")
        if profile.tags:
            parts.append(f"Теги: {', '.join(str(tag) for tag in profile.tags[:8])}")
        if profile.source_name:
            parts.append(f"Источник: {profile.source_name}")
        stats = self._quality_stats.get(profile.id)
        if stats:
            parts.extend(self._quality_tooltip_lines(stats))
        return "\n".join(part for part in parts if part)

    @staticmethod
    def _quality_tooltip_lines(stats: ServerQualityStats) -> list[str]:
        lines = [
            "",
            "Качество:",
            f"  Success rate: {int(stats.success_rate * 100)}%",
            f"  Recent success: {int(stats.recent_success_rate * 100)}%",
            f"  Успехов/ошибок: {stats.success_count}/{stats.failure_count}",
            f"  Ошибок подряд: {stats.consecutive_failures}",
        ]
        if stats.latency_ewma_ms is not None:
            lines.append(f"  EWMA latency: {int(stats.latency_ewma_ms)} ms")
        if stats.recent_average_latency_ms is not None:
            lines.append(f"  Recent avg latency: {stats.recent_average_latency_ms} ms")
        if stats.last_checked_at:
            lines.append(f"  Последняя проверка: {stats.last_checked_at}")
        if stats.history:
            lines.append("  Последние события:")
            for event in stats.history[-6:]:
                latency = f" · {event.latency_ms} ms" if event.latency_ms is not None else ""
                message = f" · {event.message}" if event.message else ""
                state = "ok" if event.success else "fail"
                lines.append(f"    {event.timestamp}: {event.event}/{state}{latency}{message}")
        return lines

    def _activate_pressed_cell(self, row: int, _column: int) -> None:
        if not 0 <= row < len(self._row_entries):
            return
        entry_type, entry_id = self._row_entries[row]
        if entry_type == "group":
            self._toggle_group(entry_id)
            return
        self._focus_active_row_now(row, entry_id)
        self.activate_requested.emit(entry_id)

    def _toggle_group(self, group_id: str) -> None:
        if self.search.text().strip():
            self._toggle_group_immediate(group_id)
            return
        if group_id in self._collapsed_groups:
            self._expand_group(group_id)
        else:
            self._collapse_group(group_id)

    def _toggle_group_immediate(self, group_id: str) -> None:
        if group_id in self._collapsed_groups:
            self._collapsed_groups.remove(group_id)
        else:
            self._collapsed_groups.add(group_id)
        self.reload()

    def _collapse_group(self, group_id: str) -> None:
        self._stop_group_animation()
        rows = self._group_child_rows(group_id)
        if not rows:
            self._collapsed_groups.add(group_id)
            self.reload()
            return
        self._set_group_collapsed_label(group_id, True)
        self._animate_group_rows(
            rows,
            self._profile_row_height(),
            0,
            lambda: self._finish_group_collapse(group_id),
        )

    def _expand_group(self, group_id: str) -> None:
        self._stop_group_animation()
        self._collapsed_groups.remove(group_id)
        self.reload()
        rows = self._group_child_rows(group_id)
        if not rows:
            return
        self._set_group_rows_height(rows, 0)
        self._animate_group_rows(
            rows,
            0,
            self._profile_row_height(),
            lambda: self._finish_group_expand(rows),
        )

    def _finish_group_collapse(self, group_id: str) -> None:
        self._group_animation = None
        self._collapsed_groups.add(group_id)
        self.reload()

    def _finish_group_expand(self, rows: list[int]) -> None:
        self._group_animation = None
        self._set_group_rows_height(rows, self._profile_row_height())

    def _group_row_index(self, group_id: str) -> int | None:
        for row, (entry_type, entry_id) in enumerate(self._row_entries):
            if entry_type == "group" and entry_id == group_id:
                return row
        return None

    def _group_child_rows(self, group_id: str) -> list[int]:
        group_row = self._group_row_index(group_id)
        if group_row is None:
            return []
        rows: list[int] = []
        for row in range(group_row + 1, len(self._row_entries)):
            entry_type, entry_id = self._row_entries[row]
            if entry_type == "group":
                break
            profile = self._profile_by_id.get(entry_id)
            if profile and self._group_id(profile) == group_id:
                rows.append(row)
        return rows

    def _set_group_collapsed_label(self, group_id: str, collapsed: bool) -> None:
        row = self._group_row_index(group_id)
        if row is None:
            return
        item = self.table.item(row, 0)
        if item:
            arrow = "▸" if collapsed else "▾"
            group_name, flag = server_display_text_and_icon(self._group_name(group_id), self._group_name(group_id))
            label = f"{arrow}  {group_name}  ·  {self._group_count(group_id)} серверов"
            item.setText(label)
            if flag:
                item.setIcon(flag)

    def _animate_group_rows(
        self,
        rows: list[int],
        start_height: int,
        end_height: int,
        on_finished: Callable[[], None],
    ) -> None:
        animation = QVariantAnimation(self)
        animation.setDuration(190)
        animation.setStartValue(start_height)
        animation.setEndValue(end_height)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.valueChanged.connect(lambda value, rows=rows: self._set_group_rows_height(rows, int(value)))
        animation.finished.connect(on_finished)
        self._group_animation = animation
        animation.start()

    def _set_group_rows_height(self, rows: list[int], height: int) -> None:
        value = max(0, int(height))
        for row in rows:
            if 0 <= row < self.table.rowCount():
                self.table.setRowHeight(row, value)
        self.table.viewport().update()

    def _stop_group_animation(self) -> None:
        if self._group_animation:
            self._group_animation.stop()
            self._group_animation = None

    @staticmethod
    def _profile_row_height() -> int:
        return 34

    @staticmethod
    def _group_row_height() -> int:
        return 36

    def _focus_active_row_now(self, row: int, profile_id: str) -> None:
        self.table.setFocus(Qt.FocusReason.MouseFocusReason)
        self.table.setCurrentCell(row, 0)
        self.table.selectRow(row)
        self.set_active_id(profile_id)
        self.table.viewport().repaint()

    def _update_active_row(self, profile_id: str | None) -> None:
        if not profile_id:
            return
        row = self._row_by_id.get(profile_id)
        if row is None:
            return
        self._paint_row(row, profile_id == self._active_id)

    def _paint_row(self, row: int, active: bool) -> None:
        profile = None
        if 0 <= row < len(self._row_entries):
            entry_type, entry_id = self._row_entries[row]
            if entry_type == "profile":
                profile = self._profile_by_id.get(entry_id)
        color = QColor(130, 200, 255) if active else QColor("#F2F2F2")
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                if profile and col in (4, 5, 6):
                    self._apply_badge_style(item, col, profile)
                else:
                    item.setForeground(color)
                    item.setBackground(QBrush())
        active_item = self.table.item(row, 7)
        if active_item:
            active_item.setText("Да" if active else "")
            active_item.setForeground(QColor("#85E89D") if active else QColor(145, 145, 145))

    def _apply_badge_style(self, item: QTableWidgetItem, column: int, profile: VlessProfile) -> None:
        if column == 4:
            self._apply_protocol_style(item, profile)
            return
        if column == 5:
            self._apply_latency_style(item, profile)
            return
        if column == 6:
            self._apply_quality_style(item, profile)

    @staticmethod
    def _set_badge_style(item: QTableWidgetItem, foreground: str, background: str) -> None:
        item.setForeground(QColor(foreground))
        item.setBackground(QColor(background))

    def _apply_protocol_style(self, item: QTableWidgetItem, profile: VlessProfile) -> None:
        protocol = str(profile.protocol or "").lower()
        palette = {
            "vless": ("#8EC5FF", "#182B3E"),
            "trojan": ("#D7B8FF", "#30243F"),
            "vmess": ("#80CBC4", "#193633"),
            "hysteria2": ("#FFD37A", "#3D2D14"),
            "tuic": ("#FFB4A2", "#3F211B"),
            "shadowsocks": ("#9BE7A5", "#17351F"),
            "wireguard": ("#F2F2F2", "#303030"),
        }
        foreground, background = palette.get(protocol, ("#D6D6D6", "#2A2A2A"))
        self._set_badge_style(item, foreground, background)

    def _apply_latency_style(self, item: QTableWidgetItem, profile: VlessProfile) -> None:
        if profile.latency_ms is None:
            if profile.latency_checked_at:
                self._set_badge_style(item, "#FFB4A2", "#3F211B")
            else:
                self._set_badge_style(item, "#B8B8B8", "#242424")
            return
        if profile.latency_ms <= SERVER_LATENCY_FAST_MS:
            self._set_badge_style(item, "#85E89D", "#17351F")
        elif profile.latency_ms <= SERVER_LATENCY_OK_MS:
            self._set_badge_style(item, "#8EC5FF", "#182B3E")
        else:
            self._set_badge_style(item, "#FFD37A", "#3D2D14")

    def _apply_quality_style(self, item: QTableWidgetItem, profile: VlessProfile) -> None:
        stats = self._quality_stats.get(profile.id)
        if not stats:
            self._set_badge_style(item, "#B8B8B8", "#242424")
            return
        success_percent = int(stats.recent_success_rate * 100)
        if stats.consecutive_failures >= 2 or success_percent < SERVER_QUALITY_OK_PERCENT:
            self._set_badge_style(item, "#FFB4A2", "#3F211B")
        elif success_percent < SERVER_QUALITY_GOOD_PERCENT:
            self._set_badge_style(item, "#FFD37A", "#3D2D14")
        else:
            self._set_badge_style(item, "#85E89D", "#17351F")

    def update_latency_cells(self, profile_ids: list[str]) -> None:
        if not profile_ids:
            return
        self.table.setUpdatesEnabled(False)
        try:
            for profile_id in profile_ids:
                row = self._row_by_id.get(profile_id)
                profile = self._profile_by_id.get(profile_id)
                if row is None or profile is None:
                    continue
                latency_item = self.table.item(row, 5)
                if latency_item:
                    latency_item.setText(self._latency_label(profile))
                    latency_item.setToolTip(self._profile_tooltip(profile))
                    self._apply_latency_style(latency_item, profile)
                quality_item = self.table.item(row, 6)
                if quality_item:
                    quality_item.setText(self._quality_label(profile))
                    quality_item.setToolTip(self._profile_tooltip(profile))
                    self._apply_quality_style(quality_item, profile)
        finally:
            self.table.setUpdatesEnabled(True)
            self.table.viewport().update()

    def _emit_for_selected(self, signal) -> None:
        selected = self.selected_id()
        if selected:
            signal.emit(selected)

    def set_latency_busy(self, busy: bool) -> None:
        self.ping_btn.setEnabled(not busy)
        self.ping_all_btn.setEnabled(not busy)
        self.sort_ping_btn.setEnabled(not busy)
        self.ping_all_btn.setText("Пинг выполняется..." if busy else "Пинг всех")

    def set_latency_progress(self, completed: int, total: int) -> None:
        if total > 0:
            self.ping_all_btn.setText(f"Пинг {completed}/{total}")


class SubscriptionsPage(QWidget):
    add_requested = pyqtSignal()
    update_all_requested = pyqtSignal()
    update_requested = pyqtSignal(str)
    delete_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("subscriptions")
        self._ids: list[str] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Подписки", self))
        toolbar = QHBoxLayout()
        self.add_btn = PrimaryPushButton(FIF.ADD, "Добавить URL", self)
        self.update_btn = PushButton(FIF.SYNC, "Обновить выбранную", self)
        self.update_all_btn = PushButton(FIF.UPDATE, "Обновить все", self)
        self.delete_btn = PushButton(FIF.DELETE, "Удалить", self)
        for button in (self.add_btn, self.update_btn, self.update_all_btn, self.delete_btn):
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        root.addLayout(toolbar)
        self.table = TableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Название", "URL", "Профилей", "Обновлено", "Кэш/HTTP", "Ошибка"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table, 1)
        self.add_btn.clicked.connect(self.add_requested)
        self.update_all_btn.clicked.connect(self.update_all_requested)
        self.update_btn.clicked.connect(lambda: self._emit_selected(self.update_requested))
        self.delete_btn.clicked.connect(lambda: self._emit_selected(self.delete_requested))

    def set_subscriptions(self, subscriptions: list[Subscription], profile_counts: dict[str, int] | None = None) -> None:
        self._ids = [item.id for item in subscriptions]
        self.table.setRowCount(len(subscriptions))
        for row, sub in enumerate(subscriptions):
            profile_count = sub.profile_count if profile_counts is None else profile_counts.get(sub.id, sub.profile_count)
            values = [
                sub.name,
                sub.url,
                str(profile_count),
                sub.last_update_at or "никогда",
                self._metadata_label(sub),
                sub.last_error or "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 4:
                    item.setToolTip(self._metadata_tooltip(sub))
                item.setData(Qt.ItemDataRole.UserRole, sub.id)
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()

    def set_update_busy(self, busy: bool) -> None:
        self.add_btn.setEnabled(not busy)
        self.update_btn.setEnabled(not busy)
        self.update_all_btn.setEnabled(not busy)
        self.delete_btn.setEnabled(not busy)
        self.update_btn.setText("Обновление..." if busy else "Обновить выбранную")
        self.update_all_btn.setText("Обновление..." if busy else "Обновить все")

    @staticmethod
    def _metadata_label(subscription: Subscription) -> str:
        parts: list[str] = []
        if subscription.last_cached_at:
            parts.append("cache")
        if subscription.etag:
            parts.append("ETag")
        if subscription.last_modified:
            parts.append("Last-Modified")
        if subscription.last_content_hash:
            parts.append(subscription.last_content_hash[:8])
        return " / ".join(parts) if parts else "—"

    @staticmethod
    def _metadata_tooltip(subscription: Subscription) -> str:
        lines: list[str] = []
        if subscription.last_cached_at:
            lines.append(f"Кэш: {subscription.last_cached_at}")
        if subscription.etag:
            lines.append(f"ETag: {subscription.etag}")
        if subscription.last_modified:
            lines.append(f"Last-Modified: {subscription.last_modified}")
        if subscription.last_content_hash:
            lines.append(f"SHA256: {subscription.last_content_hash}")
        return "\n".join(lines) if lines else "Нет metadata"

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._ids):
            return self._ids[row]
        return None

    def _emit_selected(self, signal) -> None:
        selected = self.selected_id()
        if selected:
            signal.emit(selected)


class RoutingPage(QWidget):
    load_file_requested = pyqtSignal()
    load_url_requested = pyqtSignal()
    per_app_rule_requested = pyqtSignal()
    rule_outbound_requested = pyqtSignal(str, str)
    rule_enabled_requested = pyqtSignal(str, bool)
    rule_move_requested = pyqtSignal(str, int)
    delete_rule_requested = pyqtSignal(str)
    clear_rules_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("routing")
        self._ids: list[str] = []
        self._rule_sets: list[RoutingRuleSet] = []
        self._resource_by_tag: dict[str, RouteRuleSetResource] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Маршрутизация", self))
        group = CardWidget(self)
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(18, 16, 18, 16)
        buttons = QHBoxLayout()
        self.file_btn = PrimaryPushButton(FIF.FOLDER, "Загрузить JSON/TXT/SRS", group)
        self.url_btn = PushButton(FIF.DOWNLOAD, "Загрузить URL", group)
        self.app_btn = PushButton(FIF.APPLICATION, "Приложение", group)
        self.up_btn = PushButton("Выше", group)
        self.down_btn = PushButton("Ниже", group)
        self.clear_btn = PushButton(FIF.DELETE, "Очистить все", group)
        buttons.addWidget(self.file_btn)
        buttons.addWidget(self.url_btn)
        buttons.addWidget(self.app_btn)
        buttons.addWidget(self.up_btn)
        buttons.addWidget(self.down_btn)
        buttons.addWidget(self.clear_btn)
        buttons.addStretch(1)
        group_layout.addWidget(BodyLabel("Наборы маршрутизации", group))
        group_layout.addLayout(buttons)
        root.addWidget(group)

        self.table = TableWidget(self)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Приоритет", "Набор", "Туннелирование", "Элементов", "Включен", "Источник", "Действия"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for col in (0, 2, 3, 4, 6):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table, 3)

        self.summary = PlainTextEdit(self)
        self.summary.setReadOnly(True)
        root.addWidget(self.summary, 1)
        self.file_btn.clicked.connect(self.load_file_requested)
        self.url_btn.clicked.connect(self.load_url_requested)
        self.app_btn.clicked.connect(self.per_app_rule_requested)
        self.up_btn.clicked.connect(lambda: self._emit_move(-1))
        self.down_btn.clicked.connect(lambda: self._emit_move(1))
        self.clear_btn.clicked.connect(self.clear_rules_requested)

    def set_rules(self, rules: SplitRules, summary: str) -> None:
        selected_before = self.selected_id()
        self._rule_sets = self._ordered_rule_sets(rules.rule_sets)
        self._ids = [rule_set.id for rule_set in self._rule_sets]
        self._resource_by_tag = {
            resource.tag: resource
            for resource in rules.rule_set_resources
            if resource.tag
        }
        self.table.setRowCount(len(self._rule_sets))
        for row, rule_set in enumerate(self._rule_sets):
            values = [
                str(rule_set.priority),
                rule_set.name,
                "",
                str(rule_set.total_items),
                "",
                self._source_label(rule_set),
                "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, rule_set.id)
                if col == 5:
                    item.setToolTip(self._source_tooltip(rule_set))
                if not rule_set.enabled:
                    item.setForeground(QColor(150, 150, 150))
                elif normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_PROXY:
                    item.setForeground(QColor(0, 120, 212))
                self.table.setItem(row, col, item)
            self.table.setCellWidget(row, 2, self._route_combo(rule_set))
            self.table.setCellWidget(row, 4, self._enabled_switch(rule_set))
            self.table.setCellWidget(row, 6, self._delete_button(rule_set))
        self.table.resizeRowsToContents()
        self.summary.setPlainText(summary)
        target_id = selected_before if selected_before in self._ids else (self._ids[0] if self._ids else None)
        if target_id:
            self.select_rule(target_id)

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._ids):
            return self._ids[row]
        return None

    def select_rule(self, rule_set_id: str) -> None:
        if rule_set_id in self._ids:
            self.table.selectRow(self._ids.index(rule_set_id))

    def _emit_selected(self, signal) -> None:
        selected = self.selected_id()
        if selected:
            signal.emit(selected)

    def _emit_move(self, direction: int) -> None:
        selected = self.selected_id()
        if selected:
            self.rule_move_requested.emit(selected, direction)

    @staticmethod
    def _ordered_rule_sets(rule_sets: list[RoutingRuleSet]) -> list[RoutingRuleSet]:
        return [item for _index, item in sorted(enumerate(rule_sets), key=lambda pair: (pair[1].priority, pair[0]))]

    def _source_label(self, rule_set: RoutingRuleSet) -> str:
        process_label = self._process_source_label(rule_set)
        if process_label:
            return process_label
        if rule_set.rule_set_tags:
            labels = []
            for tag in rule_set.rule_set_tags:
                resource = self._resource_by_tag.get(tag)
                if resource:
                    labels.append(f"SRS {resource.type}: {tag}" if resource.format == "binary" else f"Rule-set {resource.type}: {tag}")
                else:
                    labels.append(f"Rule-set: {tag}")
            return ", ".join(labels)
        if rule_set.geosite or rule_set.geoip:
            parts = []
            if rule_set.geosite:
                parts.append(f"geosite:{len(rule_set.geosite)}")
            if rule_set.geoip:
                parts.append(f"geoip:{len(rule_set.geoip)}")
            return ", ".join(parts)
        return rule_set.source or rule_set.source_type or "inline"

    def _source_tooltip(self, rule_set: RoutingRuleSet) -> str:
        lines = [
            f"ID: {rule_set.id}",
            f"Priority: {rule_set.priority}",
            f"Source: {rule_set.source or rule_set.source_type or 'inline'}",
        ]
        for tag in rule_set.rule_set_tags:
            resource = self._resource_by_tag.get(tag)
            if not resource:
                lines.append(f"Rule-set: {tag}")
                continue
            location = resource.url or resource.path or resource.source or "—"
            lines.append(f"{tag}: {resource.type}/{resource.format} · {location}")
        if rule_set.geosite:
            lines.append(f"geosite: {', '.join(rule_set.geosite[:8])}")
        if rule_set.geoip:
            lines.append(f"geoip: {', '.join(rule_set.geoip[:8])}")
        if rule_set.process_name:
            lines.append(f"process_name: {', '.join(rule_set.process_name[:8])}")
        if rule_set.process_path:
            lines.append(f"process_path: {', '.join(rule_set.process_path[:4])}")
        if rule_set.process_path_regex:
            lines.append(f"process_path_regex: {', '.join(rule_set.process_path_regex[:4])}")
        return "\n".join(lines)

    @staticmethod
    def _process_source_label(rule_set: RoutingRuleSet) -> str:
        parts = []
        if rule_set.process_name:
            parts.append(f"Процессы: {len(rule_set.process_name)}")
        if rule_set.process_path:
            parts.append(f"Пути: {len(rule_set.process_path)}")
        if rule_set.process_path_regex:
            parts.append(f"Regex пути: {len(rule_set.process_path_regex)}")
        return ", ".join(parts)

    def _route_combo(self, rule_set: RoutingRuleSet) -> QWidget:
        combo = ComboBox(self.table)
        combo.setMinimumWidth(170)
        combo.addItem("Текущий сервер", userData=ROUTE_OUTBOUND_PROXY)
        combo.addItem("Напрямую", userData=ROUTE_OUTBOUND_DIRECT)
        combo.setCurrentIndex(0 if normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_PROXY else 1)
        combo.currentIndexChanged.connect(
            lambda _index, rule_id=rule_set.id, widget=combo: self.rule_outbound_requested.emit(
                rule_id,
                normalize_outbound(str(widget.currentData() or ROUTE_OUTBOUND_PROXY)),
            )
        )
        return self._cell_container(combo)

    def _enabled_switch(self, rule_set: RoutingRuleSet) -> QWidget:
        switch = SwitchButton(self.table)
        switch.setChecked(rule_set.enabled)
        switch.checkedChanged.connect(lambda checked, rule_id=rule_set.id: self.rule_enabled_requested.emit(rule_id, bool(checked)))
        return self._cell_container(switch)

    def _delete_button(self, rule_set: RoutingRuleSet) -> QWidget:
        button = PushButton(FIF.DELETE, "Удалить", self.table)
        button.clicked.connect(lambda _checked=False, rule_id=rule_set.id: self.delete_rule_requested.emit(rule_id))
        return self._cell_container(button)

    def _cell_container(self, widget: QWidget) -> QWidget:
        container = QWidget(self.table)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(6, 2, 6, 2)
        layout.addWidget(widget)
        layout.addStretch(1)
        return container


class LogsPage(QWidget):
    clear_requested = pyqtSignal()
    export_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("logs")
        self._lines: list[str] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Логи и диагностика", self))
        toolbar = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Фильтр логов")
        self.clear_btn = PushButton("Очистить", self)
        self.export_btn = PrimaryPushButton("Диагностика ZIP", self)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        root.addLayout(toolbar)
        self.text = PlainTextEdit(self)
        self.text.setReadOnly(True)
        self.text.document().setMaximumBlockCount(2500)
        root.addWidget(self.text, 1)
        self.search.textChanged.connect(self.refresh)
        self.clear_btn.clicked.connect(self.clear_requested)
        self.export_btn.clicked.connect(self.export_requested)

    def append_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) > 5000:
            self._lines = self._lines[-5000:]
        if self.search.text().strip() and self.search.text().strip().lower() not in line.lower():
            return
        self.text.appendPlainText(line)
        self.text.verticalScrollBar().setValue(self.text.verticalScrollBar().maximum())

    def set_lines(self, lines: list[str]) -> None:
        self._lines = list(lines)
        self.refresh()

    def clear_view(self) -> None:
        self._lines.clear()
        self.text.clear()

    def refresh(self) -> None:
        query = self.search.text().strip().lower()
        lines = self._lines if not query else [line for line in self._lines if query in line.lower()]
        self.text.setPlainText("\n".join(lines[-2500:]))
        self.text.verticalScrollBar().setValue(self.text.verticalScrollBar().maximum())


class SettingsPage(QWidget):
    settings_changed = pyqtSignal()
    reset_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("settings")
        self._loading_values = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = SmoothScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)
        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        scroll.setWidget(container)
        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(8)
        root.addWidget(SubtitleLabel("Настройки", container))

        network_group = SettingCardGroup("Сеть", container)
        self.dns_card = _LineCard(FIF.LINK, "DNS-серверы", "Через запятую", network_group)
        self.port_card = _SpinCard(FIF.COMMAND_PROMPT, "Proxy порт", "SOCKS5 + HTTP mixed inbound", 1, 65535, network_group)
        self.mtu_card = _SpinCard(FIF.SPEED_HIGH, "TUN MTU", "MTU виртуального интерфейса", 576, 65535, network_group)
        self.ipv6_card = SwitchSettingCard(FIF.GLOBE, "IPv6", "Добавлять IPv6 TUN address, AAAA DNS и FakeIP IPv6", parent=network_group)
        self.tun_ipv6_card = _LineCard(FIF.GLOBE, "TUN IPv6", "IPv6 адрес виртуального интерфейса", network_group)
        self.dns_strategy_card = SettingCard(FIF.GLOBE, "DNS strategy", "Как sing-box выбирает A/AAAA ответы", network_group)
        self.dns_strategy_combo = ComboBox(self.dns_strategy_card)
        self.dns_strategy_combo.addItem("Prefer IPv4", userData=DNS_STRATEGY_PREFER_IPV4)
        self.dns_strategy_combo.addItem("Prefer IPv6", userData=DNS_STRATEGY_PREFER_IPV6)
        self.dns_strategy_combo.addItem("IPv4 only", userData=DNS_STRATEGY_IPV4_ONLY)
        self.dns_strategy_combo.addItem("IPv6 only", userData=DNS_STRATEGY_IPV6_ONLY)
        self.dns_strategy_combo.setMinimumWidth(180)
        self.dns_strategy_card.hBoxLayout.addWidget(self.dns_strategy_combo, 0, Qt.AlignmentFlag.AlignRight)
        self.dns_strategy_card.hBoxLayout.addSpacing(16)
        self.connectivity_urls_card = _LineCard(FIF.LINK, "Health-check URL", "Через запятую", network_group)
        self.connectivity_timeout_card = _SpinCard(
            FIF.SPEED_HIGH,
            "Health-check timeout",
            "Таймаут проверки, мс",
            1000,
            30000,
            network_group,
        )
        self.interval_card = _SpinCard(FIF.UPDATE, "Интервал подписок", "Автообновление, часов", 1, 720, network_group)
        for card in (
            self.dns_card,
            self.port_card,
            self.mtu_card,
            self.ipv6_card,
            self.tun_ipv6_card,
            self.dns_strategy_card,
            self.connectivity_urls_card,
            self.connectivity_timeout_card,
            self.interval_card,
        ):
            network_group.addSettingCard(card)
        root.addWidget(network_group)

        behavior_group = SettingCardGroup("Поведение", container)
        self.kill_switch_card = SwitchSettingCard(FIF.CHECKBOX, "Kill Switch", "Для TUN включает strict route", parent=behavior_group)
        self.firewall_kill_switch_card = SwitchSettingCard(
            FIF.CERTIFICATE,
            "Firewall Kill Switch",
            "Opt-in fail-closed режим Windows Firewall; требует права администратора",
            parent=behavior_group,
        )
        self.proxy_guard_card = SwitchSettingCard(FIF.LINK, "Proxy guard", "Включать системный proxy Windows", parent=behavior_group)
        self.auto_connect_card = SwitchSettingCard(FIF.PLAY_SOLID, "Автоподключение", "Подключаться при запуске приложения", parent=behavior_group)
        self.smart_connect_card = SwitchSettingCard(
            FIF.SPEED_HIGH,
            "Smart Connect",
            "Выбирать лучший сервер при ручном подключении",
            parent=behavior_group,
        )
        self.auto_start_card = SwitchSettingCard(FIF.PLAY_SOLID, "Автозапуск Windows", "Запускать приложение вместе с Windows", parent=behavior_group)
        self.app_updates_card = SwitchSettingCard(FIF.UPDATE, "Обновления приложения", "Проверять GitHub Releases при запуске", parent=behavior_group)
        self.auto_update_card = SwitchSettingCard(FIF.SYNC, "Автообновление подписок", "Обновлять подписки по расписанию", parent=behavior_group)
        self.health_check_card = SwitchSettingCard(FIF.SYNC, "Health monitor", "Фоновая проверка текущего соединения", parent=behavior_group)
        self.health_interval_card = _SpinCard(
            FIF.SPEED_HIGH,
            "Health interval",
            "Интервал проверки, секунд",
            BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
            BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
            behavior_group,
        )
        self.health_threshold_card = _SpinCard(
            FIF.CHECKBOX,
            "Health failures",
            "Ошибок подряд до восстановления",
            BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
            BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
            behavior_group,
        )
        self.self_healing_card = SwitchSettingCard(
            FIF.SYNC,
            "Self-healing",
            "Автоматически восстанавливать sing-box после падения",
            parent=behavior_group,
        )
        self.self_healing_attempts_card = _SpinCard(
            FIF.CHECKBOX,
            "Self-healing attempts",
            "Максимум попыток восстановления подряд",
            SELF_HEALING_MIN_MAX_ATTEMPTS,
            SELF_HEALING_MAX_MAX_ATTEMPTS,
            behavior_group,
        )
        self.self_healing_cooldown_card = _SpinCard(
            FIF.SPEED_HIGH,
            "Self-healing cooldown",
            "Пауза после исчерпания попыток, секунд",
            SELF_HEALING_MIN_COOLDOWN_SECONDS,
            SELF_HEALING_MAX_COOLDOWN_SECONDS,
            behavior_group,
        )
        self.data_dir_card = SettingCard(FIF.FOLDER, "Папка данных", str(paths.data_dir()), behavior_group)
        self.notifications_card = SwitchSettingCard(FIF.INFO, "Windows-уведомления", "Показывать toast-уведомления", parent=behavior_group)
        self.tray_card = SwitchSettingCard(FIF.DOWN, "Сворачивать в трей", "Закрытие окна скрывает приложение", parent=behavior_group)
        for card in (
            self.kill_switch_card,
            self.firewall_kill_switch_card,
            self.proxy_guard_card,
            self.auto_connect_card,
            self.smart_connect_card,
            self.auto_start_card,
            self.app_updates_card,
            self.auto_update_card,
            self.health_check_card,
            self.health_interval_card,
            self.health_threshold_card,
            self.self_healing_card,
            self.self_healing_attempts_card,
            self.self_healing_cooldown_card,
            self.data_dir_card,
            self.notifications_card,
            self.tray_card,
        ):
            behavior_group.addSettingCard(card)
        root.addWidget(behavior_group)

        self.reset_btn = PushButton(container)
        self.reset_btn.setObjectName("dangerResetButton")
        self.reset_btn.setMinimumWidth(380)
        self.reset_btn.setMinimumHeight(34)
        self.reset_btn.setStyleSheet(
            "#dangerResetButton {"
            "color: #ffb4a2;"
            "padding: 0;"
            "}"
        )
        reset_layout = QHBoxLayout(self.reset_btn)
        reset_layout.setContentsMargins(18, 0, 18, 0)
        reset_layout.setSpacing(10)
        reset_icon = QLabel(self.reset_btn)
        reset_icon.setFixedSize(18, 18)
        reset_icon.setPixmap(FIF.DELETE.icon(color=QColor("#ffb4a2")).pixmap(QSize(16, 16)))
        reset_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        reset_icon.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        reset_text = QLabel("Удалить все настройки и sing-box", self.reset_btn)
        reset_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        reset_text.setStyleSheet("QLabel { color: #ffb4a2; background: transparent; }")
        reset_text.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        reset_layout.addWidget(reset_icon)
        reset_layout.addWidget(reset_text, 1)
        reset_layout.addSpacing(28)
        actions = QHBoxLayout()
        actions.addWidget(self.reset_btn)
        actions.addStretch(1)
        root.addLayout(actions)
        root.addStretch(1)
        self.reset_btn.clicked.connect(self.reset_requested)
        self._connect_auto_save_signals()

    def set_values(self, settings: AppSettings) -> None:
        self._loading_values = True
        try:
            self.dns_card.edit.setText(", ".join(settings.dns_servers))
            self.port_card.spin.setValue(settings.mixed_port)
            self.mtu_card.spin.setValue(settings.tun_mtu)
            self.ipv6_card.setChecked(settings.enable_ipv6)
            self.tun_ipv6_card.edit.setText(settings.tun_ipv6_address)
            self._set_dns_strategy(settings.dns_strategy, settings.enable_ipv6)
            self.connectivity_urls_card.edit.setText(", ".join(settings.connectivity_check_urls))
            self.connectivity_timeout_card.spin.setValue(settings.connectivity_check_timeout_ms)
            self.interval_card.spin.setValue(settings.subscription_update_interval_hours)
            self.kill_switch_card.setChecked(settings.kill_switch)
            self.proxy_guard_card.setChecked(settings.enable_system_proxy_guard)
            self.auto_connect_card.setChecked(settings.auto_connect)
            self.smart_connect_card.setChecked(settings.smart_connect_enabled)
            self.auto_start_card.setChecked(settings.auto_start_windows)
            self.app_updates_card.setChecked(settings.auto_check_app_updates)
            self.auto_update_card.setChecked(settings.auto_update_subscriptions)
            self.health_check_card.setChecked(settings.background_health_check_enabled)
            self.health_interval_card.spin.setValue(settings.background_health_check_interval_seconds)
            self.health_threshold_card.spin.setValue(settings.background_health_check_failure_threshold)
            self.self_healing_card.setChecked(settings.self_healing_enabled)
            self.self_healing_attempts_card.spin.setValue(settings.self_healing_max_attempts)
            self.self_healing_cooldown_card.spin.setValue(settings.self_healing_cooldown_seconds)
            self.notifications_card.setChecked(settings.show_notifications)
            self.tray_card.setChecked(settings.minimize_to_tray)
            self.firewall_kill_switch_card.setChecked(settings.firewall_kill_switch)
        finally:
            self._loading_values = False

    def apply_to_settings(self, settings: AppSettings) -> AppSettings:
        settings.dns_servers = [item.strip() for item in self.dns_card.edit.text().split(",") if item.strip()]
        settings.mixed_port = int(self.port_card.spin.value())
        settings.tun_mtu = int(self.mtu_card.spin.value())
        settings.enable_ipv6 = self.ipv6_card.isChecked()
        settings.tun_ipv6_address = self.tun_ipv6_card.edit.text().strip() or DEFAULT_TUN_IPV6_ADDRESS
        settings.dns_strategy = normalize_dns_strategy(
            self.dns_strategy_combo.currentData(),
            ipv6_enabled=settings.enable_ipv6,
        )
        settings.connectivity_check_urls = normalize_connectivity_urls(self.connectivity_urls_card.edit.text())
        settings.connectivity_check_timeout_ms = normalize_connectivity_timeout_ms(
            self.connectivity_timeout_card.spin.value()
        )
        settings.subscription_update_interval_hours = int(self.interval_card.spin.value())
        settings.kill_switch = self.kill_switch_card.isChecked()
        settings.firewall_kill_switch = self.firewall_kill_switch_card.isChecked()
        settings.enable_system_proxy_guard = self.proxy_guard_card.isChecked()
        settings.auto_connect = self.auto_connect_card.isChecked()
        settings.smart_connect_enabled = self.smart_connect_card.isChecked()
        settings.auto_start_windows = self.auto_start_card.isChecked()
        settings.auto_check_app_updates = self.app_updates_card.isChecked()
        settings.auto_update_subscriptions = self.auto_update_card.isChecked()
        settings.background_health_check_enabled = self.health_check_card.isChecked()
        settings.background_health_check_interval_seconds = int(self.health_interval_card.spin.value())
        settings.background_health_check_failure_threshold = int(self.health_threshold_card.spin.value())
        settings.self_healing_enabled = self.self_healing_card.isChecked()
        settings.self_healing_max_attempts = int(self.self_healing_attempts_card.spin.value())
        settings.self_healing_cooldown_seconds = int(self.self_healing_cooldown_card.spin.value())
        settings.portable_mode = False
        settings.show_notifications = self.notifications_card.isChecked()
        settings.minimize_to_tray = self.tray_card.isChecked()
        return settings

    def _set_dns_strategy(self, strategy: str, ipv6_enabled: bool) -> None:
        normalized = normalize_dns_strategy(strategy, ipv6_enabled=ipv6_enabled)
        for index in range(self.dns_strategy_combo.count()):
            if self.dns_strategy_combo.itemData(index) == normalized:
                self.dns_strategy_combo.setCurrentIndex(index)
                return
        self.dns_strategy_combo.setCurrentIndex(0)

    def _connect_auto_save_signals(self) -> None:
        for card in (
            self.ipv6_card,
            self.kill_switch_card,
            self.firewall_kill_switch_card,
            self.proxy_guard_card,
            self.auto_connect_card,
            self.smart_connect_card,
            self.auto_start_card,
            self.app_updates_card,
            self.auto_update_card,
            self.health_check_card,
            self.self_healing_card,
            self.notifications_card,
            self.tray_card,
        ):
            card.checkedChanged.connect(self._emit_settings_changed)
        for card in (
            self.port_card,
            self.mtu_card,
            self.connectivity_timeout_card,
            self.interval_card,
            self.health_interval_card,
            self.health_threshold_card,
            self.self_healing_attempts_card,
            self.self_healing_cooldown_card,
        ):
            card.spin.valueChanged.connect(self._emit_settings_changed)
        for card in (
            self.dns_card,
            self.tun_ipv6_card,
            self.connectivity_urls_card,
        ):
            card.edit.editingFinished.connect(self._emit_settings_changed)
        self.dns_strategy_combo.currentIndexChanged.connect(self._emit_settings_changed)

    def _emit_settings_changed(self, *_args) -> None:
        if not self._loading_values:
            self.settings_changed.emit()


class AboutPage(QWidget):
    check_update_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("about")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("О проекте", self))
        card = CardWidget(self)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        header = QHBoxLayout()
        header.setSpacing(14)
        header.addWidget(create_logo_label(card, 76))
        title_block = QVBoxLayout()
        title = StrongBodyLabel(f"{APP_NAME} {APP_VERSION}", card)
        subtitle = BodyLabel("Разреши себе доступ к любым сайтам", card)
        subtitle.setStyleSheet(f"color: {ACCENT};")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        title_block.addStretch(1)
        header.addLayout(title_block, 1)
        text = CaptionLabel(
            "Полностью open-source проект под лицензией GPLv3.\n\n"
            "Без телеметрии, скрытой аналитики, сбора IP, доменов, профилей, подписок или логов пользователя.\n"
            "Все данные хранятся локально. Сообщество может проверять код, открывать issues и присылать pull requests.\n\n"
            f"Репозиторий: {APP_REPOSITORY}\n\n"
            "Часть кода, графической архитектуры и дизайн-подходов адаптированы из open-source проекта "
            f"zapret-kvn: {ZAPRET_KVN_REPOSITORY}\n\n"
            "Спасибо проекту russia-mobile-internet-whitelist за домены из российского "
            f"\"белого списка\" для встроенного bypass: {RUSSIA_MOBILE_WHITELIST_REPOSITORY}\n\n"
            f"SVG-флаги стран предоставлены проектом flag-icons под лицензией MIT: {FLAG_ICONS_REPOSITORY}",
            card,
        )
        text.setWordWrap(True)
        self.version_label = CaptionLabel(f"Версия приложения: {APP_VERSION}", card)
        self.core_label = CaptionLabel("Core: sing-box", card)
        self.github_btn = PrimaryPushButton(FIF.LINK, "Открыть GitHub", card)
        self.update_btn = PushButton(FIF.UPDATE, "Проверить обновления", card)
        self.zapret_btn = PushButton(FIF.LINK, "Открыть zapret-kvn", card)
        self.whitelist_btn = PushButton(FIF.LINK, "Открыть whitelist", card)
        self.flags_btn = PushButton(FIF.LINK, "Открыть flag-icons", card)
        layout.addLayout(header)
        layout.addSpacing(8)
        layout.addWidget(text)
        layout.addWidget(self.version_label)
        layout.addWidget(self.core_label)
        buttons = QHBoxLayout()
        buttons.addWidget(self.github_btn)
        buttons.addWidget(self.update_btn)
        buttons.addWidget(self.zapret_btn)
        buttons.addWidget(self.whitelist_btn)
        buttons.addWidget(self.flags_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        root.addWidget(card)
        root.addStretch(1)
        self.github_btn.clicked.connect(lambda: webbrowser.open(APP_REPOSITORY))
        self.update_btn.clicked.connect(lambda _checked=False: self.check_update_requested.emit())
        self.zapret_btn.clicked.connect(lambda: webbrowser.open(ZAPRET_KVN_REPOSITORY))
        self.whitelist_btn.clicked.connect(lambda: webbrowser.open(RUSSIA_MOBILE_WHITELIST_REPOSITORY))
        self.flags_btn.clicked.connect(lambda: webbrowser.open(FLAG_ICONS_REPOSITORY))

    def set_core_version(self, version: str) -> None:
        self.core_label.setText(f"Core: {version}")


class RazreshenieWindow(FluentWindow):
    def __init__(self) -> None:
        super().__init__()
        paths.ensure_app_dirs()
        self.bridge = UiBridge(self)
        self.bridge.call.connect(lambda callback: callback())
        self.bridge.log_line.connect(self._append_log_line)
        self.bridge.activity_changed.connect(self._schedule_activity_refresh)
        self.log_buffer = LogBuffer()
        self.domain_activity = DomainActivityTracker()
        self.logger = setup_logger(paths.log_file_path(), self._on_log_from_thread)
        self.settings = app_state.load_settings()
        self.settings.app_name = APP_NAME
        self.settings.portable_mode = paths.is_portable_mode()
        self.profiles = app_state.load_profiles()
        self._profiles_by_id = {profile.id: profile for profile in self.profiles}
        self.subscriptions = app_state.load_subscriptions()
        self.split_rules = app_state.load_split_rules()
        self.rules_manager = RulesManager()
        self.subscription_manager = SubscriptionManager()
        self.smart_connect = SmartConnectManager(app_state.load_quality_stats(), app_state.load_smart_groups())
        self.smart_connect.prune_missing_profiles(profile.id for profile in self.profiles)
        self._sync_subscription_profile_counts(save=True)
        self.singbox = SingBoxManager(self.logger)
        self.latency_scanner = LatencyScanner(
            timeout_ms=LATENCY_SCAN_TIMEOUT_MS,
            max_workers=LATENCY_SCAN_WORKERS,
            batch_size=LATENCY_BATCH_SIZE,
            batch_interval_seconds=LATENCY_BATCH_INTERVAL_SECONDS,
            logger=self.logger,
            binary_provider=self.singbox.ensure_binary,
        )
        self.traffic = TrafficMonitor()
        self.scheduler: RepeatingTask | None = None
        self._closing = False
        self._busy = False
        self._ip_refreshing = False
        self._ping_refreshing = False
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self._latency_result_queue: deque[tuple[str, int | None]] = deque()
        self._pending_latency_summary: LatencyScanSummary | None = None
        self._core_version_cache: str | None = None
        self._last_ip_refresh = 0
        self._last_ping_refresh = 0
        self._last_health_check = 0
        self._ip_label = "IP: —"
        self._ping_label = "Пинг: —"
        self._speed_label = "↓ 0.0 Б/с   ↑ 0.0 Б/с"
        self._activity_signal_lock = threading.Lock()
        self._activity_signal_pending = False
        self._failover_anchor_profile_id: str | None = None
        self._failover_failed_ids: set[str] = set()
        self._failover_in_progress = False
        self._manual_disconnect_requested = False
        self._last_connection_running = False
        self._health_check_running = False
        self._health_failure_count = 0
        self._self_healing_attempts = 0
        self._self_healing_last_attempt_at = 0
        self._self_healing_cooldown_until = 0
        self.tray: QSystemTrayIcon | None = None

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.setWindowIcon(app_logo_icon())
        self.resize(1280, 760)
        self.setMinimumSize(760, 520)

        self.dashboard_page = DashboardPage(self)
        self.servers_page = ServersPage(self)
        self.subscriptions_page = SubscriptionsPage(self)
        self.routing_page = RoutingPage(self)
        self.activity_page = DomainActivityPage(self)
        self.logs_page = LogsPage(self)
        self.settings_page = SettingsPage(self)
        self.about_page = AboutPage(self)
        self.settings_autosave_timer = QTimer(self)
        self.settings_autosave_timer.setSingleShot(True)
        self.settings_autosave_timer.setInterval(350)
        self.settings_autosave_timer.timeout.connect(self.save_settings)
        self._create_navigation()
        self._create_tray()
        self._connect_signals()
        self.activity_refresh_timer = QTimer(self)
        self.activity_refresh_timer.setSingleShot(True)
        self.activity_refresh_timer.setInterval(180)
        self.activity_refresh_timer.timeout.connect(self._refresh_activity_page)
        self._refresh_all_views()
        self._start_subscription_scheduler()

        self.metrics_timer = QTimer(self)
        self.metrics_timer.setInterval(1000)
        self.metrics_timer.timeout.connect(self._status_loop)
        self.metrics_timer.start()
        self.latency_result_timer = QTimer(self)
        self.latency_result_timer.setInterval(LATENCY_UI_DRAIN_INTERVAL_MS)
        self.latency_result_timer.timeout.connect(self._drain_latency_result_queue)
        self.activity_timer = QTimer(self)
        self.activity_timer.setInterval(3000)
        self.activity_timer.timeout.connect(lambda: self._schedule_activity_refresh(0))
        self.activity_timer.start()
        QTimer.singleShot(250, self._post_init)

    def _create_navigation(self) -> None:
        self.navigationInterface.setMinimumExpandWidth(700)
        self.navigationInterface.setExpandWidth(200)
        self.addSubInterface(self.dashboard_page, FIF.SPEED_HIGH, "Панель")
        self.addSubInterface(self.servers_page, FIF.LINK, "Серверы")
        self.addSubInterface(self.subscriptions_page, FIF.UPDATE, "Подписки")
        self.addSubInterface(self.routing_page, FIF.CODE, "Маршрутизация")
        self.addSubInterface(self.activity_page, FIF.SEND, "Активность")
        self.addSubInterface(self.logs_page, FIF.DOCUMENT, "Логи")
        self.addSubInterface(self.about_page, FIF.INFO, "О проекте", NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FIF.SETTING, "Настройки", NavigationItemPosition.BOTTOM)

    def _create_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(app_logo_icon())
        self.tray.setToolTip(f"{APP_NAME} {APP_VERSION}")
        menu = QMenu()
        self.tray_show_action = QAction("Показать", self)
        self.tray_connect_action = QAction("Подключить", self)
        self.tray_disconnect_action = QAction("Отключить", self)
        self.tray_quit_action = QAction("Выход", self)
        menu.addAction(self.tray_show_action)
        menu.addAction(self.tray_connect_action)
        menu.addAction(self.tray_disconnect_action)
        menu.addSeparator()
        menu.addAction(self.tray_quit_action)
        self.tray.setContextMenu(menu)
        self.tray.show()
        self.tray_show_action.triggered.connect(self.show_normal)
        self.tray_connect_action.triggered.connect(self.connect_vpn)
        self.tray_disconnect_action.triggered.connect(self.disconnect_vpn)
        self.tray_quit_action.triggered.connect(self.exit_app)
        self.tray.activated.connect(lambda reason: self.show_normal() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)

    def _connect_signals(self) -> None:
        self.dashboard_page.toggle_connection_requested.connect(self.toggle_connection)
        self.dashboard_page.profile_selected.connect(self.set_active_profile)
        self.dashboard_page.mode_changed.connect(self.set_mode)
        self.dashboard_page.import_requested.connect(self.import_server_link)
        self.dashboard_page.dns_requested.connect(self.check_dns)
        self.dashboard_page.download_core_requested.connect(self.download_core)
        self.dashboard_page.rules_requested.connect(lambda: self.switchTo(self.routing_page))

        self.servers_page.import_requested.connect(self.import_server_link)
        self.servers_page.import_files_requested.connect(self.import_server_files)
        self.servers_page.activate_requested.connect(self.set_active_profile)
        self.servers_page.edit_requested.connect(self.edit_profile_by_id)
        self.servers_page.delete_requested.connect(self.delete_profile_by_id)
        self.servers_page.ping_requested.connect(self.test_profile_latency_by_id)
        self.servers_page.ping_all_requested.connect(self.test_all_latencies)
        self.servers_page.sort_latency_requested.connect(self.sort_profiles_by_latency)
        self.servers_page.failover_group_requested.connect(self.create_failover_group_by_id)
        self.servers_page.validate_requested.connect(self.validate_current_config)

        self.subscriptions_page.add_requested.connect(self.add_subscription)
        self.subscriptions_page.update_requested.connect(self.update_subscription_by_id)
        self.subscriptions_page.update_all_requested.connect(self.update_all_subscriptions)
        self.subscriptions_page.delete_requested.connect(self.delete_subscription_by_id)

        self.routing_page.load_file_requested.connect(self.load_rules_file)
        self.routing_page.load_url_requested.connect(self.load_rules_url)
        self.routing_page.per_app_rule_requested.connect(self.add_per_app_rule)
        self.routing_page.rule_outbound_requested.connect(self.set_rule_set_outbound)
        self.routing_page.rule_enabled_requested.connect(self.set_rule_set_enabled)
        self.routing_page.rule_move_requested.connect(self.move_rule_set)
        self.routing_page.delete_rule_requested.connect(self.delete_rule_set)
        self.routing_page.clear_rules_requested.connect(self.clear_rule_sets)

        self.logs_page.clear_requested.connect(self.clear_log_window)
        self.logs_page.export_requested.connect(self.export_logs)
        self.activity_page.filters_changed.connect(lambda: self._schedule_activity_refresh(120))
        self.activity_page.route_rule_requested.connect(self.add_activity_route_rule)
        self.activity_page.clear_requested.connect(self.clear_domain_activity)
        self.about_page.check_update_requested.connect(self.check_app_update)
        self.settings_page.settings_changed.connect(self._schedule_settings_save)
        self.settings_page.reset_requested.connect(self.reset_all_app_data)

    def _schedule_settings_save(self) -> None:
        if self._closing:
            return
        self.settings_autosave_timer.start()

    def _flush_pending_settings_save(self) -> None:
        if self.settings_autosave_timer.isActive():
            self.settings_autosave_timer.stop()
            self.save_settings(restart_connected=False, show_success=False)

    def _post_init(self) -> None:
        self.logger.info("Приложение запущено. Данные: %s", paths.data_dir())
        if windows.is_admin() and not self.singbox.is_running():
            self._clear_firewall_kill_switch_safely()
        if self.settings.first_run:
            self._run_first_run_onboarding()
        if self.settings.auto_check_app_updates:
            QTimer.singleShot(1200, lambda: self.check_app_update(silent=True))
        if self.settings.auto_connect and self.profiles:
            self.connect_vpn()

    def _run_first_run_onboarding(self) -> None:
        dialog = OnboardingDialog(self.settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            result = dialog.onboarding_result()
        else:
            result = self._default_onboarding_result()
        self._apply_onboarding_result(result)
        self._run_onboarding_action(result.action)

    def _default_onboarding_result(self) -> OnboardingResult:
        return OnboardingResult(
            mode=self.settings.mode,
            auto_update_subscriptions=self.settings.auto_update_subscriptions,
            background_health_check_enabled=self.settings.background_health_check_enabled,
            minimize_to_tray=self.settings.minimize_to_tray,
            auto_start_windows=self.settings.auto_start_windows,
            action=ONBOARDING_ACTION_SKIP,
        )

    def _apply_onboarding_result(self, result: OnboardingResult) -> None:
        before_runtime = self._settings_runtime_key(self.settings)
        previous_auto_start = bool(self.settings.auto_start_windows)
        self.settings.mode = "tun" if result.mode == "tun" else "proxy"
        self.settings.auto_update_subscriptions = bool(result.auto_update_subscriptions)
        self.settings.background_health_check_enabled = bool(result.background_health_check_enabled)
        self.settings.minimize_to_tray = bool(result.minimize_to_tray)
        self.settings.auto_start_windows = bool(result.auto_start_windows)
        self.settings.first_run = False
        if previous_auto_start != self.settings.auto_start_windows:
            try:
                windows.set_autostart(self.settings.auto_start_windows)
            except Exception as exc:
                self.logger.error("Не удалось применить автозапуск Windows из onboarding: %s", sanitize_error_text(exc))
        app_state.save_settings(self.settings)
        self._start_subscription_scheduler()
        self._refresh_all_views()
        if before_runtime != self._settings_runtime_key(self.settings):
            self._restart_if_connected("Перезапуск после мастера первого запуска…")

    def _run_onboarding_action(self, action: str) -> None:
        if action == ONBOARDING_ACTION_IMPORT_SERVER:
            self.switchTo(self.servers_page)
            QTimer.singleShot(0, self.import_server_link)
            return
        if action == ONBOARDING_ACTION_ADD_SUBSCRIPTION:
            self.switchTo(self.subscriptions_page)
            QTimer.singleShot(0, self.add_subscription)
            return
        if action == ONBOARDING_ACTION_DOWNLOAD_CORE:
            self.switchTo(self.about_page)
            QTimer.singleShot(0, self.download_core)
            return
        if action == ONBOARDING_ACTION_OPEN_SETTINGS:
            self.switchTo(self.settings_page)

    def _refresh_all_views(self) -> None:
        self._rebuild_profile_index()
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        active = self._active_profile()
        active_id = active.id if active else None
        self.dashboard_page.set_profiles(self.profiles, active_id)
        self.dashboard_page.set_mode(self.settings.mode)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self.dashboard_page.set_rules_summary(self._rules_summary_line())
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions, self.smart_connect.quality_stats)
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
        self.routing_page.set_rules(self.split_rules, self._rules_summary_text())
        self.settings_page.set_values(self.settings)
        self.about_page.set_core_version(self._core_version())
        self.logs_page.set_lines(self.log_buffer.snapshot("all"))
        self.domain_activity.refresh_routes(self.split_rules)
        self._refresh_activity_page()
        self._refresh_tray_text()

    def _refresh_server_views(self) -> None:
        self._rebuild_profile_index()
        active = self._active_profile()
        active_id = active.id if active else None
        self.dashboard_page.set_profiles(self.profiles, active_id)
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions, self.smart_connect.quality_stats)

    def _refresh_servers_table(self) -> None:
        self._rebuild_profile_index()
        active = self._active_profile()
        active_id = active.id if active else None
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions, self.smart_connect.quality_stats)

    def _subscription_profile_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for profile in self.profiles:
            if not profile.subscription_id:
                continue
            counts[profile.subscription_id] = counts.get(profile.subscription_id, 0) + 1
        return counts

    def _sync_subscription_profile_counts(self, *, save: bool) -> dict[str, int]:
        counts = self._subscription_profile_counts()
        changed = False
        for subscription in self.subscriptions:
            actual_count = counts.get(subscription.id, 0)
            if subscription.profile_count != actual_count:
                subscription.profile_count = actual_count
                changed = True
        if changed and save:
            app_state.save_subscriptions(self.subscriptions)
        return counts

    def _core_version(self, *, refresh: bool = False) -> str:
        if refresh or self._core_version_cache is None:
            self._core_version_cache = self.singbox.version()
        return self._core_version_cache

    def _active_profile(self) -> VlessProfile | None:
        if self.settings.active_profile_id:
            profile = self._profiles_by_id.get(self.settings.active_profile_id)
            if profile:
                return profile
        return self.profiles[0] if self.profiles else None

    def _rebuild_profile_index(self) -> None:
        self._profiles_by_id = {profile.id: profile for profile in self.profiles}

    def _profile_by_id(self, profile_id: str) -> VlessProfile | None:
        profile = self._profiles_by_id.get(profile_id)
        if profile is None and self.profiles:
            self._rebuild_profile_index()
            profile = self._profiles_by_id.get(profile_id)
        return profile

    def _subscription_by_id(self, subscription_id: str) -> Subscription | None:
        return next((item for item in self.subscriptions if item.id == subscription_id), None)

    def _rule_set_by_id(self, rule_set_id: str) -> RoutingRuleSet | None:
        return next((item for item in self.split_rules.rule_sets if item.id == rule_set_id), None)

    def create_failover_group_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        members = self.smart_connect.group_profiles(profile, self.profiles)
        if len(members) < 2:
            self._show_status("warning", "Для failover-группы нужно минимум два сервера в одной группе")
            return
        group, members = self.smart_connect.create_or_update_failover_group(
            profile,
            self.profiles,
            name=self._failover_group_name(profile),
        )
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._show_status("success", f"Failover-группа сохранена: {group.name} · серверов: {len(members)}")

    def _failover_group_name(self, profile: VlessProfile) -> str:
        subscription = self._subscription_by_id(profile.subscription_id) if profile.subscription_id else None
        source_group = " ".join(str(profile.group or "").split())
        if subscription and source_group:
            return f"{subscription.name} / {source_group}"
        if subscription:
            return subscription.name
        if source_group:
            return f"Без подписки / {source_group}"
        return "Без подписки"

    def set_active_profile(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if self.settings.active_profile_id == profile_id:
            return
        was_running = self.singbox.is_running()
        self.settings.active_profile_id = profile_id
        app_state.save_settings(self.settings)
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile_id)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self._refresh_tray_text()
        if was_running:
            self._start_or_restart_vpn(profile, "Переключение сервера…")

    def set_mode(self, mode: str) -> None:
        previous_mode = self.settings.mode
        next_mode = "tun" if mode == "tun" else "proxy"
        if next_mode == "tun" and not windows.is_admin():
            self.settings.mode = "tun"
            app_state.save_settings(self.settings)
            if self._request_admin_for_tun("Для включения TUN-режима нужны права администратора."):
                return
            self.settings.mode = previous_mode if previous_mode != "tun" else "proxy"
            app_state.save_settings(self.settings)
            self.dashboard_page.set_mode(self.settings.mode)
            return

        self.settings.mode = next_mode
        app_state.save_settings(self.settings)
        self.dashboard_page.set_mode(self.settings.mode)
        if previous_mode != next_mode:
            self._restart_if_connected("Перезапуск режима подключения…")

    def toggle_connection(self) -> None:
        if self.singbox.is_running():
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self) -> None:
        profile = self._active_profile()
        if not profile:
            self._show_status("warning", "Импортируйте сервер или подписку")
            return
        if (self.settings.mode == "tun" or self.settings.firewall_kill_switch) and not windows.is_admin():
            app_state.save_settings(self.settings)
            reason = (
                "Для подключения с Firewall Kill Switch нужны права администратора."
                if self.settings.firewall_kill_switch
                else "Для подключения в TUN-режиме нужны права администратора."
            )
            self._request_admin_for_tun(reason)
            return
        self._reset_self_healing_state()
        self._manual_disconnect_requested = False
        if self.settings.smart_connect_enabled:
            self._smart_connect_and_start(profile)
        else:
            self._direct_connect_and_start(profile)

    def _smart_connect_and_start(self, anchor_profile: VlessProfile) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return

        def worker() -> VlessProfile:
            selected = self._select_smart_connect_profile(anchor_profile)
            try:
                self._start_profile_core(selected)
            except Exception:
                self.smart_connect.record_failure(selected.id)
                app_state.save_quality_stats(self.smart_connect.quality_stats)
                raise
            self.smart_connect.record_success(selected.id)
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            return selected

        self._run_background(
            worker,
            lambda selected, anchor_profile=anchor_profile: self._finish_smart_connect(anchor_profile, selected),
            busy="Smart Connect…",
        )

    def _direct_connect_and_start(self, profile: VlessProfile) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return

        def worker() -> VlessProfile:
            try:
                self._start_profile_core(profile)
            except Exception:
                self.smart_connect.record_failure(profile.id)
                app_state.save_quality_stats(self.smart_connect.quality_stats)
                raise
            self.smart_connect.record_success(profile.id)
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            return profile

        self._run_background(
            worker,
            lambda selected: self._finish_smart_connect(selected, selected),
            busy="Подключение…",
        )

    def _select_smart_connect_profile(self, anchor_profile: VlessProfile) -> VlessProfile:
        candidates = self.smart_connect.candidate_profiles(
            anchor_profile,
            self.profiles,
            limit=SMART_CONNECT_SCAN_LIMIT,
        )
        if not candidates:
            return anchor_profile
        if len(candidates) == 1:
            return candidates[0]

        try:
            scan_result = self.latency_scanner.scan_profiles_sync(candidates, settings=self.settings)
        except Exception as exc:
            self.logger.warning(
                "Smart Connect quick scan не выполнен, использую сохраненную статистику: %s",
                sanitize_error_text(exc),
            )
            decision = self.smart_connect.choose_best(
                anchor_profile,
                candidates,
                limit=SMART_CONNECT_SCAN_LIMIT,
            )
            return decision.selected or anchor_profile

        checked_at = utc_now_iso()
        for candidate in candidates:
            latency = scan_result.results.get(candidate.id)
            self._set_profile_latency(candidate.id, latency, checked_at)
        app_state.save_profiles(self.profiles)
        app_state.save_quality_stats(self.smart_connect.quality_stats)

        decision = self.smart_connect.choose_best(
            anchor_profile,
            candidates,
            latency_overrides=scan_result.results,
            limit=SMART_CONNECT_SCAN_LIMIT,
        )
        selected = decision.selected or anchor_profile
        self.logger.info(
            "Smart Connect выбрал сервер: %s из %s кандидатов",
            selected.name,
            len(candidates),
        )
        return selected

    def _finish_smart_connect(self, anchor_profile: VlessProfile, profile: VlessProfile) -> None:
        self.settings.active_profile_id = profile.id
        app_state.save_settings(self.settings)
        self._begin_failover_session(anchor_profile)
        self._refresh_server_views()
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile.id)
        self._connected_ui(profile)

    def _start_profile_core(self, profile: VlessProfile) -> None:
        firewall_enabled = False
        try:
            if self.settings.firewall_kill_switch:
                self._enable_firewall_kill_switch()
                firewall_enabled = True
            if self.settings.enable_system_proxy_guard and self.settings.mode != "proxy":
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self.singbox.start(profile, self.settings, self.split_rules)
            if self.settings.enable_system_proxy_guard and self.settings.mode == "proxy":
                windows.set_system_proxy(True, self.settings.mixed_listen_host, self.settings.mixed_port)
            elif self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
        except Exception:
            if firewall_enabled:
                self._clear_firewall_kill_switch_safely()
            raise

    def _enable_firewall_kill_switch(self) -> None:
        executable = self.singbox.ensure_binary()
        windows.set_firewall_kill_switch(
            True,
            executable,
            app_executable=windows.executable_for_pyinstaller(),
        )

    def _clear_firewall_kill_switch_safely(self) -> None:
        if not windows.is_windows():
            return
        if not windows.is_admin():
            self.logger.warning("Firewall Kill Switch cleanup пропущен: нет прав администратора")
            return
        try:
            windows.clear_firewall_kill_switch()
        except Exception as exc:
            self.logger.error("Не удалось отключить Firewall Kill Switch: %s", sanitize_error_text(exc))

    def _start_or_restart_vpn(self, profile: VlessProfile, busy: str) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return
        def worker() -> None:
            self._start_profile_core(profile)

        self._run_background(worker, lambda _result: self._finish_manual_connection(profile), busy=busy)

    def _finish_manual_connection(self, profile: VlessProfile) -> None:
        self._begin_failover_session(profile)
        self._connected_ui(profile)

    def _restart_if_connected(self, busy: str) -> None:
        if not self.singbox.is_running():
            return
        profile = self._active_profile()
        if not profile:
            return
        self._start_or_restart_vpn(profile, busy)

    def disconnect_vpn(self) -> None:
        self._manual_disconnect_requested = True
        self._reset_self_healing_state()
        def worker() -> None:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self._clear_firewall_kill_switch_safely()

        self._run_background(worker, lambda _result: self._disconnected_ui(), busy="Отключение…")

    def _connected_ui(self, profile: VlessProfile) -> None:
        self._last_connection_running = True
        self._health_failure_count = 0
        self._last_health_check = int(time.time())
        self.dashboard_page.set_connection(True)
        self.traffic.reset()
        self.dashboard_page.clear_graph()
        self._refresh_tray_text()
        self._show_status("success", f"Подключено: {profile.name}")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", f"Подключено: {profile.name}")

    def _disconnected_ui(self) -> None:
        self._clear_failover_session()
        self._reset_self_healing_state()
        self._last_connection_running = False
        self._health_check_running = False
        self._health_failure_count = 0
        self.dashboard_page.set_connection(False)
        self._refresh_tray_text()
        self._show_status("info", "Соединение остановлено")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", "Соединение остановлено")

    def _begin_failover_session(self, anchor_profile: VlessProfile) -> None:
        self._failover_anchor_profile_id = anchor_profile.id
        self._failover_failed_ids.clear()
        self._manual_disconnect_requested = False

    def _clear_failover_session(self) -> None:
        self._failover_anchor_profile_id = None
        self._failover_failed_ids.clear()
        self._failover_in_progress = False
        self._manual_disconnect_requested = False

    def _should_auto_failover(self) -> bool:
        return bool(
            self._failover_anchor_profile_id
            and not self._manual_disconnect_requested
            and not self._failover_in_progress
            and not self._busy
            and not self._closing
        )

    def _start_failover_after_drop(self, failed_profile: VlessProfile) -> None:
        if not self._should_auto_failover():
            return
        self._failover_in_progress = True
        self._failover_failed_ids.add(failed_profile.id)
        self.smart_connect.record_failure(failed_profile.id)
        app_state.save_quality_stats(self.smart_connect.quality_stats)
        self.logger.warning("Failover: сервер упал, ищу замену: %s", failed_profile.name)

        def worker() -> tuple[VlessProfile | None, str]:
            try:
                return self._run_failover_attempt(failed_profile)
            except Exception as exc:
                message = format_user_error(exc, context="Failover")
                self.logger.error("Failover failed: %s\n%s", message.display_text, format_safe_traceback(exc))
                return None, message.display_text

        self._run_background(worker, self._finish_failover_attempt, busy="Failover…")

    def _run_failover_attempt(self, failed_profile: VlessProfile) -> tuple[VlessProfile | None, str]:
        anchor_profile = self._profile_by_id(self._failover_anchor_profile_id or "") or failed_profile
        candidates = self.smart_connect.failover_profiles(
            anchor_profile,
            self.profiles,
            current_profile=failed_profile,
            failed_ids=self._failover_failed_ids,
            limit=SMART_CONNECT_SCAN_LIMIT,
        )
        if not candidates:
            return None, "Failover: нет доступных кандидатов в текущей группе"

        latency_overrides: dict[str, int | None] | None = None
        try:
            scan_result = self.latency_scanner.scan_profiles_sync(candidates, settings=self.settings)
            checked_at = utc_now_iso()
            for candidate in candidates:
                self._set_profile_latency(candidate.id, scan_result.results.get(candidate.id), checked_at)
            app_state.save_profiles(self.profiles)
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            latency_overrides = scan_result.results
        except Exception as exc:
            self.logger.warning(
                "Failover quick scan не выполнен, использую сохраненную статистику: %s",
                sanitize_error_text(exc),
            )

        decision = self.smart_connect.choose_failover_next(
            anchor_profile,
            self.profiles,
            current_profile=failed_profile,
            failed_ids=self._failover_failed_ids,
            latency_overrides=latency_overrides,
            limit=SMART_CONNECT_SCAN_LIMIT,
        )
        ordered = [candidate.profile for candidate in decision.candidates]
        if not ordered:
            return None, "Failover: все кандидаты недоступны"

        last_error = ""
        for candidate in ordered:
            try:
                self._start_profile_core(candidate)
            except Exception as exc:
                message = format_user_error(exc, context="Failover")
                last_error = message.display_text
                self.logger.warning("Failover: не удалось запустить %s: %s", candidate.name, sanitize_error_text(exc))
                self._failover_failed_ids.add(candidate.id)
                self.smart_connect.record_failure(candidate.id)
                app_state.save_quality_stats(self.smart_connect.quality_stats)
                continue
            self.smart_connect.record_success(candidate.id)
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            return candidate, ""
        return None, last_error or "Failover: не удалось запустить ни один кандидат"

    def _finish_failover_attempt(self, result: tuple[VlessProfile | None, str]) -> None:
        self._failover_in_progress = False
        profile, error = result
        if profile:
            self.settings.active_profile_id = profile.id
            app_state.save_settings(self.settings)
            self._refresh_server_views()
            self.dashboard_page.set_active_profile(profile)
            self.servers_page.set_active_id(profile.id)
            self._connected_ui(profile)
            self._show_status("success", f"Failover: переключено на {profile.name}")
            return

        self._handle_unrecoverable_connection_failure(error or "Failover: нет доступного сервера")

    def _maybe_run_background_health_check(self, now: int, running: bool) -> None:
        if not running or not self.settings.background_health_check_enabled:
            return
        if self._health_check_running or self._busy or self._failover_in_progress:
            return
        if self._manual_disconnect_requested or self._closing:
            return
        interval = self._background_health_interval_seconds()
        if now - self._last_health_check < interval:
            return
        profile = self._active_profile()
        if not profile:
            return

        self._last_health_check = now
        self._health_check_running = True
        settings_snapshot = AppSettings.from_dict(self.settings.to_dict())

        def worker() -> ConnectivityCheckResult:
            return self.singbox.check_current_connectivity(settings_snapshot)

        self._run_background(
            worker,
            lambda result, profile_id=profile.id: self._finish_background_health_check(profile_id, result),
            set_busy=False,
        )

    def _finish_background_health_check(self, profile_id: str, result: ConnectivityCheckResult) -> None:
        self._health_check_running = False
        if self._closing or self._manual_disconnect_requested:
            return
        profile = self._profile_by_id(profile_id)
        if not profile or not self.singbox.is_running():
            return

        if result.success:
            self._health_failure_count = 0
            attempt = result.successful_attempt
            timestamp = utc_now_iso()
            if attempt and attempt.latency_ms is not None:
                self._set_profile_latency(profile_id, attempt.latency_ms, timestamp)
                app_state.save_profiles(self.profiles)
                self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
                self.servers_page.update_latency_cells([profile_id])
            else:
                self.smart_connect.record_success(profile_id, checked_at=timestamp)
                self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
                self.servers_page.update_latency_cells([profile_id])
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            self.logger.debug("Health monitor OK: %s", result.summary)
            return

        self._health_failure_count += 1
        self.smart_connect.record_failure(profile_id)
        self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
        self.servers_page.update_latency_cells([profile_id])
        app_state.save_quality_stats(self.smart_connect.quality_stats)
        threshold = self._background_health_failure_threshold()
        self.logger.warning(
            "Health monitor fail %s/%s: %s",
            self._health_failure_count,
            threshold,
            sanitize_error_text(result.error),
        )
        if self._health_failure_count >= threshold:
            self._recover_unhealthy_connection(profile, sanitize_error_text(result.error))

    def _recover_unhealthy_connection(self, profile: VlessProfile, reason: str) -> None:
        if self._manual_disconnect_requested or self._busy or self._failover_in_progress:
            return
        self._health_failure_count = 0
        anchor_profile = self._profile_by_id(self._failover_anchor_profile_id or "") or profile
        candidates = self.smart_connect.failover_profiles(
            anchor_profile,
            self.profiles,
            current_profile=profile,
            failed_ids={profile.id},
            limit=SMART_CONNECT_SCAN_LIMIT,
        )
        if candidates and self._should_auto_failover():
            self._show_status("warning", f"Health monitor: соединение нестабильно, переключаю сервер. {sanitize_error_text(reason)}")
            self._start_failover_after_drop(profile)
            return
        self._restart_unhealthy_profile(profile, reason)

    def _restart_unhealthy_profile(self, profile: VlessProfile, reason: str) -> None:
        if self._busy:
            return
        self.logger.warning("Health monitor: переподключаю текущий сервер %s: %s", profile.name, reason)

        def worker() -> tuple[VlessProfile | None, str]:
            try:
                self.singbox.stop()
                if self.settings.enable_system_proxy_guard:
                    windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
                self._start_profile_core(profile)
            except Exception as exc:
                self.smart_connect.record_failure(profile.id)
                app_state.save_quality_stats(self.smart_connect.quality_stats)
                return None, format_user_error(exc, context="Health monitor").display_text
            self.smart_connect.record_success(profile.id)
            app_state.save_quality_stats(self.smart_connect.quality_stats)
            return profile, ""

        self._run_background(worker, self._finish_health_reconnect, busy="Восстановление подключения…")

    def _finish_health_reconnect(self, result: tuple[VlessProfile | None, str]) -> None:
        profile, error = result
        if profile:
            self.settings.active_profile_id = profile.id
            app_state.save_settings(self.settings)
            self._begin_failover_session(profile)
            self._refresh_server_views()
            self.dashboard_page.set_active_profile(profile)
            self.servers_page.set_active_id(profile.id)
            self._connected_ui(profile)
            self._show_status("success", f"Health monitor: подключение восстановлено: {profile.name}")
            return

        self._handle_unrecoverable_connection_failure(f"Health monitor: переподключение не удалось: {error}")

    def _handle_unexpected_core_stop(self) -> None:
        failed_profile = self._active_profile()
        reason = sanitize_error_text(self.singbox.last_runtime_error())
        self.singbox.mark_stopped_if_exited()
        self._last_connection_running = False
        self._health_check_running = False
        self.logger.warning("Watchdog: sing-box остановился вне ручного отключения: %s", reason)
        if not failed_profile:
            self._handle_unrecoverable_connection_failure("sing-box остановился, но активный профиль не найден")
            return
        if not self._should_self_heal_after_drop(failed_profile):
            self._handle_unrecoverable_connection_failure(reason)
            return
        if not self._register_self_healing_attempt(reason):
            self._handle_unrecoverable_connection_failure(reason)
            return
        self._show_status("warning", f"Watchdog: sing-box остановился, восстанавливаю подключение. {reason}")
        self._recover_unhealthy_connection(failed_profile, reason)

    def _should_self_heal_after_drop(self, profile: VlessProfile | None) -> bool:
        return bool(
            profile
            and self.settings.self_healing_enabled
            and not self._manual_disconnect_requested
            and not self._closing
            and not self._busy
            and not self._failover_in_progress
        )

    def _register_self_healing_attempt(self, reason: str) -> bool:
        now = int(time.time())
        cooldown = self._self_healing_cooldown_seconds()
        if self._self_healing_cooldown_until and now < self._self_healing_cooldown_until:
            remaining = self._self_healing_cooldown_until - now
            self.logger.error("Self-healing paused for %s seconds: %s", remaining, reason)
            self._show_status("error", f"Self-healing на паузе ещё {remaining} сек.: {reason}")
            return False
        if self._self_healing_cooldown_until and now >= self._self_healing_cooldown_until:
            self._reset_self_healing_state()
        if self._self_healing_last_attempt_at and now - self._self_healing_last_attempt_at > cooldown:
            self._self_healing_attempts = 0

        self._self_healing_attempts += 1
        self._self_healing_last_attempt_at = now
        max_attempts = self._self_healing_max_attempts()
        if self._self_healing_attempts > max_attempts:
            self._self_healing_cooldown_until = now + cooldown
            self.logger.error(
                "Self-healing stopped after %s attempts; cooldown=%ss. Last reason: %s",
                max_attempts,
                cooldown,
                reason,
            )
            self._show_status("error", f"Self-healing: лимит {max_attempts} попыток исчерпан, пауза {cooldown} сек.")
            return False

        self.logger.warning(
            "Self-healing attempt %s/%s after sing-box stop: %s",
            self._self_healing_attempts,
            max_attempts,
            reason,
        )
        return True

    def _reset_self_healing_state(self) -> None:
        self._self_healing_attempts = 0
        self._self_healing_last_attempt_at = 0
        self._self_healing_cooldown_until = 0

    def _handle_unrecoverable_connection_failure(self, message: str) -> None:
        self._clear_failover_session()
        self._last_connection_running = False
        self._health_check_running = False
        self._clear_proxy_guard_safely()
        self.dashboard_page.set_connection(False)
        self._refresh_tray_text()
        message = sanitize_error_text(message)
        if self.settings.firewall_kill_switch:
            message = f"{message}. Firewall Kill Switch оставлен включенным в fail-closed режиме."
        self._show_status("error", message)
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", "Подключение не восстановлено")

    def _clear_proxy_guard_safely(self) -> None:
        if not self.settings.enable_system_proxy_guard:
            return
        try:
            windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
        except Exception as exc:
            self.logger.error("Не удалось отключить Windows proxy guard после сбоя: %s", sanitize_error_text(exc))

    def _self_healing_max_attempts(self) -> int:
        try:
            value = int(self.settings.self_healing_max_attempts)
        except (TypeError, ValueError):
            value = SELF_HEALING_DEFAULT_MAX_ATTEMPTS
        return max(SELF_HEALING_MIN_MAX_ATTEMPTS, min(SELF_HEALING_MAX_MAX_ATTEMPTS, value))

    def _self_healing_cooldown_seconds(self) -> int:
        try:
            value = int(self.settings.self_healing_cooldown_seconds)
        except (TypeError, ValueError):
            value = SELF_HEALING_DEFAULT_COOLDOWN_SECONDS
        return max(SELF_HEALING_MIN_COOLDOWN_SECONDS, min(SELF_HEALING_MAX_COOLDOWN_SECONDS, value))

    def _background_health_interval_seconds(self) -> int:
        try:
            value = int(self.settings.background_health_check_interval_seconds)
        except (TypeError, ValueError):
            value = BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS
        return max(
            BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
            min(BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS, value),
        )

    def _background_health_failure_threshold(self) -> int:
        try:
            value = int(self.settings.background_health_check_failure_threshold)
        except (TypeError, ValueError):
            value = BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD
        return max(
            BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
            min(BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD, value),
        )

    def _request_admin_for_tun(self, reason: str) -> bool:
        if windows.is_admin():
            return True
        self.logger.info("%s Запрашиваю повышенные права через Windows UAC.", reason)
        self._show_status("info", f"{reason} Сейчас откроется запрос Windows UAC.")
        if windows.relaunch_as_admin():
            QTimer.singleShot(250, self.exit_app)
            return True
        self._show_status("error", "Windows не выдала права администратора или запрос был отменен")
        return False

    def import_server_link(self) -> None:
        value, ok = QInputDialog.getMultiLineText(
            self,
            "Импорт серверов",
            "Вставьте ссылки, base64-подписку, Clash YAML/JSON или sing-box JSON",
        )
        if not ok or not value.strip():
            return
        sources = self._text_import_sources(value)

        def worker() -> tuple[list[VlessProfile], str]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Импорт {event.current}/{event.total}: {event.source}",
                    )
                )

            profiles = self.subscription_manager.parse_many(sources, progress_callback=progress)
            return profiles, "из текста"

        self._run_background(
            worker,
            lambda result: self._apply_imported_profiles(result[0], result[1]),
            busy="Импорт серверов…",
        )

    def import_server_files(self) -> None:
        file_names, _ = QFileDialog.getOpenFileNames(
            self,
            "Импорт серверов из файлов",
            "",
            "Подписки (*.txt *.json *.yaml *.yml);;TXT (*.txt);;JSON (*.json);;YAML (*.yaml *.yml);;Все файлы (*.*)",
        )
        if not file_names:
            return
        file_paths = [Path(file_name) for file_name in file_names]

        def worker() -> tuple[list[VlessProfile], str]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Импорт {event.current}/{event.total}: {Path(event.source).name}",
                    )
                )

            profiles = self.subscription_manager.parse_files(file_paths, progress_callback=progress)
            return profiles, "из файлов"

        self._run_background(
            worker,
            lambda result: self._apply_imported_profiles(result[0], result[1]),
            busy="Импорт файлов…",
        )

    def _text_import_sources(self, text: str) -> list[tuple[str, str]]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) > 1 and all("://" in line for line in lines):
            return [(f"строка {index}", line) for index, line in enumerate(lines, start=1)]
        return [("вставленный текст", text)]

    def _apply_imported_profiles(self, profiles: list[VlessProfile], source_label: str) -> None:
        if not profiles:
            self._show_status("warning", "Серверы не импортированы")
            return
        self.profiles.extend(profiles)
        self.settings.active_profile_id = profiles[0].id
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()
        self._show_status("success", f"Импортировано {len(profiles)} серверов {source_label}")

    def edit_profile_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        dialog = JsonEditorDialog("Редактирование профиля", profile.to_dict(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = VlessProfile.from_dict(dialog.data())
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._show_status("error", format_user_error(exc, context="Редактирование профиля").display_text)
            return
        updated.touch()
        self.profiles = [updated if item.id == profile_id else item for item in self.profiles]
        app_state.save_profiles(self.profiles)
        self._refresh_all_views()

    def delete_profile_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if QMessageBox.question(self, "Удалить профиль", f"Удалить {profile.name}?") != QMessageBox.StandardButton.Yes:
            return
        self.profiles = [item for item in self.profiles if item.id != profile_id]
        if self.settings.active_profile_id == profile_id:
            self.settings.active_profile_id = self.profiles[0].id if self.profiles else None
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()

    def test_profile_latency_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        self._start_latency_scan((profile,))

    def test_all_latencies(self) -> None:
        self._start_latency_scan(self.profiles)

    def _start_latency_scan(self, profiles: tuple[VlessProfile, ...] | list[VlessProfile]) -> None:
        if self._latency_scan_running or self.latency_scanner.is_running:
            self._show_status("info", "Проверка отклика уже выполняется")
            return
        if not profiles:
            self._show_status("warning", "Сначала импортируйте серверы")
            return

        total_profiles = len(profiles)
        self._latency_result_queue.clear()
        self._pending_latency_summary = None
        self._latency_scan_running = True
        self._latency_scan_total = total_profiles
        self._latency_scan_completed = 0
        self.servers_page.set_latency_busy(True)
        self.servers_page.set_latency_progress(0, total_profiles)

        def on_batch(results: list[tuple[str, int | None]]) -> None:
            self.bridge.call.emit(lambda results=results: self._queue_latency_results(results))

        def on_done(summary: LatencyScanSummary) -> None:
            self.bridge.call.emit(lambda summary=summary: self._queue_latency_finish(summary))

        def on_error(exc: Exception) -> None:
            self.bridge.call.emit(lambda exc=exc: self._fail_latency_scan(exc))

        started = self.latency_scanner.scan_profiles(
            profiles,
            settings=self.settings,
            on_batch=on_batch,
            on_done=on_done,
            on_error=on_error,
        )
        if not started:
            self._latency_scan_running = False
            self._latency_scan_total = 0
            self._latency_scan_completed = 0
            self._pending_latency_summary = None
            self._latency_result_queue.clear()
            self.servers_page.set_latency_busy(False)
            self._show_status("info", "Проверка отклика уже выполняется")

    def _queue_latency_results(self, results: list[tuple[str, int | None]]) -> None:
        self._latency_result_queue.extend(results)
        if not self.latency_result_timer.isActive():
            self.latency_result_timer.start()

    def _queue_latency_finish(self, summary: LatencyScanSummary) -> None:
        self._pending_latency_summary = summary
        if not self.latency_result_timer.isActive():
            self.latency_result_timer.start()

    def _drain_latency_result_queue(self) -> None:
        if not self._latency_result_queue:
            self.latency_result_timer.stop()
            if self._pending_latency_summary is not None:
                summary = self._pending_latency_summary
                self._pending_latency_summary = None
                self._finish_latency_scan(summary)
            return

        batch: list[tuple[str, int | None]] = []
        while self._latency_result_queue and len(batch) < LATENCY_UI_DRAIN_LIMIT:
            batch.append(self._latency_result_queue.popleft())
        self._apply_latency_result_batch(batch)

    def _apply_latency_result_batch(self, results: list[tuple[str, int | None]]) -> None:
        changed_ids: list[str] = []
        checked_at = utc_now_iso()
        for profile_id, latency in results:
            if self._set_profile_latency(profile_id, latency, checked_at):
                changed_ids.append(profile_id)
        self._latency_scan_completed = min(self._latency_scan_total, self._latency_scan_completed + len(results))
        self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
        self.servers_page.update_latency_cells(changed_ids)
        self.servers_page.set_latency_progress(self._latency_scan_completed, self._latency_scan_total)

    def _finish_latency_scan(self, summary: LatencyScanSummary) -> None:
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self.servers_page.set_latency_busy(False)
        self._save_profiles_background()
        if summary.cancelled:
            self._show_status("info", "Проверка отклика остановлена")
            return
        self._show_status(
            "success",
            (
                f"Проверено: {summary.total_profiles}, успешно: {summary.successful_profiles}, "
                f"таймаутов: {summary.timeout_profiles}"
            ),
        )

    def _fail_latency_scan(self, exc: Exception) -> None:
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self._pending_latency_summary = None
        self._latency_result_queue.clear()
        if self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        self.servers_page.set_latency_busy(False)
        self._show_status("error", format_user_error(exc, context="Проверка отклика").display_text)

    def _set_profile_latency(
        self,
        profile_id: str,
        latency: int | None,
        checked_at: str | None = None,
    ) -> VlessProfile | None:
        profile = self._profile_by_id(profile_id)
        if profile:
            profile.latency_ms = latency
            timestamp = checked_at or utc_now_iso()
            profile.latency_checked_at = timestamp
            profile.updated_at = timestamp
            self.smart_connect.record_latency(profile_id, latency, checked_at=timestamp)
        return profile

    def _save_profiles_background(self) -> None:
        snapshot = list(self.profiles)
        quality_snapshot = dict(self.smart_connect.quality_stats)

        def worker() -> None:
            try:
                app_state.save_profiles(snapshot)
                app_state.save_quality_stats(quality_snapshot)
            except Exception as exc:
                self.logger.error("Не удалось сохранить профили после проверки отклика: %s", sanitize_error_text(exc))

        threading.Thread(target=worker, name="RazreshenieProfileSave", daemon=True).start()

    def sort_profiles_by_latency(self) -> None:
        self.profiles.sort(key=lambda item: (item.latency_ms is None, item.latency_ms or 10**9, item.name.lower()))
        app_state.save_profiles(self.profiles)
        self._refresh_server_views()

    def add_subscription(self) -> None:
        url, ok = QInputDialog.getText(self, "Добавить подписку", "URL подписки")
        if not ok or not url.strip():
            return
        parsed = urlparse(url.strip())
        subscription = Subscription(
            name=parsed.netloc or "Подписка",
            url=url.strip(),
            update_interval_hours=self.settings.subscription_update_interval_hours,
        )
        self.subscriptions.append(subscription)
        app_state.save_subscriptions(self.subscriptions)
        self._refresh_all_views()
        self.update_subscription(subscription)

    def update_subscription_by_id(self, subscription_id: str) -> None:
        subscription = self._subscription_by_id(subscription_id)
        if subscription:
            self.update_subscription(subscription)

    def update_subscription(self, subscription: Subscription) -> None:
        self._sync_subscription_profile_counts(save=True)

        def worker() -> SubscriptionFetchResult:
            try:
                profiles, updated_subscription = self.subscription_manager.fetch(subscription)
            except Exception as exc:
                message = format_user_error(exc, context="Подписка").display_text
                subscription.last_error = message
                return SubscriptionFetchResult(subscription=subscription, error=message)
            return SubscriptionFetchResult(subscription=updated_subscription, profiles=profiles)

        self.subscriptions_page.set_update_busy(True)
        self._run_background(worker, self._finish_subscription_update, busy="Обновление подписки…")

    def _finish_subscription_update(self, result: SubscriptionFetchResult) -> None:
        try:
            if result.success:
                self._apply_subscription_update(result.subscription, result.profiles)
            else:
                message = format_user_error(result.error or "ошибка обновления", context="Подписка").display_text
                self._record_subscription_error(result.subscription, message)
                self._show_status("error", message)
        finally:
            self.subscriptions_page.set_update_busy(False)

    def _apply_subscription_update(
        self,
        subscription: Subscription,
        profiles: list[VlessProfile],
        *,
        show_status: bool = True,
    ) -> None:
        subscription_counts = self._merge_subscription_update(subscription, profiles)
        self._save_subscription_state()
        self._refresh_server_views()
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
        self._refresh_tray_text()
        if show_status:
            self._show_status("success", f"Подписка обновлена: {subscription.name} · серверов: {subscription.profile_count}")

    def _merge_subscription_update(self, subscription: Subscription, profiles: list[VlessProfile]) -> dict[str, int]:
        active_before = self._active_profile()
        active_key = self.subscription_manager.profile_key(active_before) if active_before else None
        old_subscription_profiles = [profile for profile in self.profiles if profile.subscription_id == subscription.id]
        other_profiles = [profile for profile in self.profiles if profile.subscription_id != subscription.id]
        merged_profiles = self._merge_subscription_profiles(old_subscription_profiles, profiles)
        subscription.profile_count = len(merged_profiles)
        self.profiles = other_profiles + merged_profiles
        self.subscriptions = [subscription if item.id == subscription.id else item for item in self.subscriptions]
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        if active_key and not any(profile.id == self.settings.active_profile_id for profile in self.profiles):
            restored = next((profile for profile in merged_profiles if self.subscription_manager.profile_key(profile) == active_key), None)
            self.settings.active_profile_id = restored.id if restored else ""
        if not self.settings.active_profile_id and self.profiles:
            self.settings.active_profile_id = self.profiles[0].id
        return subscription_counts

    def _record_subscription_error(self, subscription: Subscription, error: str) -> None:
        subscription.last_error = error
        self.subscriptions = [subscription if item.id == subscription.id else item for item in self.subscriptions]
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        app_state.save_subscriptions(self.subscriptions)
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)

    def _save_subscription_state(self) -> None:
        app_state.save_profiles(self.profiles)
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_settings(self.settings)

    def _merge_subscription_profiles(
        self,
        existing_profiles: list[VlessProfile],
        incoming_profiles: list[VlessProfile],
    ) -> list[VlessProfile]:
        existing_by_key: dict[str, deque[VlessProfile]] = {}
        for profile in existing_profiles:
            key = self.subscription_manager.profile_key(profile)
            existing_by_key.setdefault(key, deque()).append(profile)

        merged: list[VlessProfile] = []

        for incoming in incoming_profiles:
            key = self.subscription_manager.profile_key(incoming)
            existing_profiles_for_key = existing_by_key.get(key)
            existing = existing_profiles_for_key.popleft() if existing_profiles_for_key else None
            if existing is not None:
                incoming.id = existing.id
                incoming.created_at = existing.created_at
                incoming.latency_ms = existing.latency_ms
                incoming.latency_checked_at = existing.latency_checked_at
            merged.append(incoming)

        return merged

    def update_all_subscriptions(self) -> None:
        subscriptions = [subscription for subscription in list(self.subscriptions) if subscription.enabled]
        if not subscriptions:
            self._show_status("warning", "Нет включенных подписок")
            return
        self._sync_subscription_profile_counts(save=True)

        def worker() -> list[SubscriptionFetchResult]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Обновление {event.current}/{event.total}: {event.subscription.name}",
                    )
                )

            return self.subscription_manager.fetch_many(subscriptions, progress_callback=progress)

        self.subscriptions_page.set_update_busy(True)
        self._run_background(worker, self._apply_subscription_batch_update, busy="Обновление подписок…")

    def _apply_subscription_batch_update(self, results: list[SubscriptionFetchResult]) -> None:
        try:
            updated = 0
            failed: list[str] = []
            subscription_counts: dict[str, int] = self._subscription_profile_counts()
            for result in results:
                if result.success:
                    subscription_counts = self._merge_subscription_update(result.subscription, result.profiles)
                    updated += 1
                else:
                    failed.append(result.subscription.name)
                    result.subscription.last_error = format_user_error(
                        result.error or "ошибка обновления",
                        context="Подписка",
                    ).display_text
                    self.subscriptions = [
                        result.subscription if item.id == result.subscription.id else item
                        for item in self.subscriptions
                    ]

            subscription_counts = self._sync_subscription_profile_counts(save=False)
            self._save_subscription_state()
            self._refresh_server_views()
            self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
            self._refresh_tray_text()
            if failed:
                self._show_status("warning", f"Обновлено: {updated}, ошибок: {len(failed)}")
            else:
                self._show_status("success", f"Обновлено подписок: {updated}")
        finally:
            self.subscriptions_page.set_update_busy(False)

    def delete_subscription_by_id(self, subscription_id: str) -> None:
        subscription = self._subscription_by_id(subscription_id)
        if not subscription:
            return
        if QMessageBox.question(self, "Удалить подписку", f"Удалить {subscription.name} и ее профили?") != QMessageBox.StandardButton.Yes:
            return
        self.subscriptions = [item for item in self.subscriptions if item.id != subscription_id]
        self.profiles = [profile for profile in self.profiles if profile.subscription_id != subscription_id]
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_profiles(self.profiles)
        self._refresh_all_views()

    def load_rules_file(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Загрузить правила",
            "",
            "Правила (*.json *.txt *.srs);;SRS (*.srs);;JSON (*.json);;TXT (*.txt);;Все файлы (*.*)",
        )
        if not file_name:
            return
        path = Path(file_name)
        default_outbound = ROUTE_OUTBOUND_DIRECT if path.suffix.lower() in {".txt", ".srs"} else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.import_file(path, default_outbound))

    def load_rules_url(self) -> None:
        url, ok = QInputDialog.getText(self, "Загрузка правил", "URL на JSON, TXT или SRS")
        if not ok or not url.strip():
            return
        parsed = urlparse(url.strip())
        default_outbound = ROUTE_OUTBOUND_DIRECT if Path(parsed.path).suffix.lower() in {".txt", ".srs"} else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.import_url(url.strip(), default_outbound))

    def add_per_app_rule(self) -> None:
        dialog = PerAppRuleDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.rule_data()
        if not data:
            self._show_status("warning", "Не удалось создать правило приложения")
            return

        normalized_rule = self._build_per_app_rule(data.name, data.outbound, data.match_kind, data.value)
        if not normalized_rule:
            self._show_status("warning", "Не удалось нормализовать правило приложения")
            return

        existing = self._find_per_app_rule(data.match_kind, data.value)
        if existing:
            self._apply_per_app_match(existing, data.match_kind, data.value)
            existing.name = data.name
            existing.outbound = normalize_outbound(data.outbound)
            existing.enabled = True
            existing.source_type = PER_APP_RULE_SOURCE_TYPE
            existing.source = PER_APP_RULE_SOURCE
            target_rule = RoutingRuleSet.from_dict(existing.to_dict())
            self.split_rules.rule_sets = [
                target_rule if item.id == existing.id else item
                for item in self.split_rules.rule_sets
            ]
            status = "обновлено"
        else:
            self.split_rules.rule_sets.append(normalized_rule)
            target_rule = normalized_rule
            status = "создано"

        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(target_rule.id)
        self._show_status("success", f"Per-app routing: {status}: {target_rule.name} -> {target_rule.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _build_per_app_rule(self, name: str, outbound: str, match_kind: str, value: str) -> RoutingRuleSet | None:
        rule_set = RoutingRuleSet(
            name=name,
            enabled=True,
            outbound=normalize_outbound(outbound),
            source_type=PER_APP_RULE_SOURCE_TYPE,
            source=PER_APP_RULE_SOURCE,
            priority=self._next_rule_priority(),
        )
        if not self._apply_per_app_match(rule_set, match_kind, value):
            return None
        normalized = RoutingRuleSet.from_dict(rule_set.to_dict())
        return normalized if not normalized.is_empty else None

    @staticmethod
    def _apply_per_app_match(rule_set: RoutingRuleSet, match_kind: str, value: str) -> bool:
        clean_value = str(value or "").strip()
        if not clean_value:
            return False
        rule_set.process_name = []
        rule_set.process_path = []
        rule_set.process_path_regex = []
        if match_kind == MATCH_KIND_PROCESS_NAME:
            rule_set.process_name = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH:
            rule_set.process_path = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            rule_set.process_path_regex = [clean_value]
        else:
            return False
        return True

    def _find_per_app_rule(self, match_kind: str, value: str) -> RoutingRuleSet | None:
        target = str(value or "").strip().casefold()
        if not target:
            return None
        for rule_set in self.split_rules.rule_sets:
            if rule_set.source_type != PER_APP_RULE_SOURCE_TYPE:
                continue
            values = self._per_app_values(rule_set, match_kind)
            if target in {item.casefold() for item in values}:
                return rule_set
        return None

    @staticmethod
    def _per_app_values(rule_set: RoutingRuleSet, match_kind: str) -> list[str]:
        if match_kind == MATCH_KIND_PROCESS_NAME:
            return rule_set.process_name
        if match_kind == MATCH_KIND_PROCESS_PATH:
            return rule_set.process_path
        if match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            return rule_set.process_path_regex
        return []

    def _load_rules(self, loader: Callable[[], RulesImportResult]) -> None:
        try:
            result = loader()
        except RulesImportError as exc:
            self._show_status("error", format_user_error(exc, context="Маршрутизация").display_text)
            return
        if not result.rule_sets:
            self._show_status("error", "Импорт не вернул правил маршрутизации")
            return
        self._append_rule_set_resources(result.rule_set_resources)
        for rule_set in result.rule_sets:
            rule_set.priority = self._next_rule_priority()
            self.split_rules.rule_sets.append(rule_set)
        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(result.rule_sets[0].id)
        resource_count = len(result.rule_set_resources)
        resource_text = f" · resources: {resource_count}" if resource_count else ""
        item_count = sum(rule_set.total_items for rule_set in result.rule_sets)
        self._show_status("success", f"Добавлены правила: {len(result.rule_sets)} · элементов: {item_count}{resource_text}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _append_rule_set_resources(self, resources: list[RouteRuleSetResource]) -> None:
        if not resources:
            return
        by_tag = {resource.tag: resource for resource in self.split_rules.rule_set_resources if resource.tag}
        for resource in resources:
            if not resource.tag:
                continue
            by_tag[resource.tag] = resource
        self.split_rules.rule_set_resources = list(by_tag.values())

    def _next_rule_priority(self) -> int:
        if not self.split_rules.rule_sets:
            return 1000
        return max((rule_set.priority for rule_set in self.split_rules.rule_sets), default=990) + 10

    def set_rule_set_outbound(self, rule_set_id: str, outbound: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.outbound = normalize_outbound(outbound)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._show_status("success", f"{rule_set.name}: {rule_set.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def set_rule_set_enabled(self, rule_set_id: str, enabled: bool) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = bool(enabled)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def toggle_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = not rule_set.enabled
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def move_rule_set(self, rule_set_id: str, direction: int) -> None:
        ordered = self._ordered_rule_sets()
        current_index = next((index for index, item in enumerate(ordered) if item.id == rule_set_id), None)
        if current_index is None:
            return
        target_index = current_index + int(direction)
        if target_index < 0 or target_index >= len(ordered):
            return
        ordered[current_index], ordered[target_index] = ordered[target_index], ordered[current_index]
        self.split_rules.rule_sets = ordered
        self._renumber_rule_priorities()
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(rule_set_id)
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _ordered_rule_sets(self) -> list[RoutingRuleSet]:
        return [item for _index, item in sorted(enumerate(self.split_rules.rule_sets), key=lambda pair: (pair[1].priority, pair[0]))]

    def _renumber_rule_priorities(self) -> None:
        for index, rule_set in enumerate(self.split_rules.rule_sets, start=1):
            rule_set.priority = index * 10

    def delete_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        if QMessageBox.question(self, "Удалить правила", f"Удалить {rule_set.name}?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules.rule_sets = [item for item in self.split_rules.rule_sets if item.id != rule_set_id]
        self._prune_unused_rule_set_resources()
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _prune_unused_rule_set_resources(self) -> None:
        used_tags = {
            tag
            for rule_set in self.split_rules.rule_sets
            for tag in rule_set.rule_set_tags
        }
        self.split_rules.rule_set_resources = [
            resource
            for resource in self.split_rules.rule_set_resources
            if resource.tag in used_tags
        ]

    def clear_rule_sets(self) -> None:
        if not self.split_rules.rule_sets and not self.split_rules.rule_set_resources:
            return
        if QMessageBox.question(self, "Очистить маршрутизацию", "Удалить все наборы правил маршрутизации?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules = SplitRules(enabled=False)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def add_activity_route_rule(self, domain: str, match_kind: str, outbound: str) -> None:
        clean_domain = self._normalize_activity_domain(domain)
        if not clean_domain:
            self._show_status("warning", "Не удалось создать правило: домен не распознан")
            return

        normalized_outbound = normalize_outbound(outbound)
        rule_set, created = self._activity_rule_set(normalized_outbound)
        target_values, rule_value, label = self._activity_rule_target(rule_set, clean_domain, match_kind)
        was_enabled = rule_set.enabled and self.split_rules.enabled
        if rule_value.lower() in {item.lower() for item in target_values}:
            if not was_enabled:
                rule_set.enabled = True
                rule_set.outbound = normalized_outbound
                self.split_rules.enabled = True
                app_state.save_split_rules(self.split_rules)
                self._refresh_all_views()
                self.routing_page.select_rule(rule_set.id)
                self._show_status("success", f"Live Activity: правило включено: {rule_value}")
                self._restart_if_connected("Перезапуск маршрутизации…")
                return
            self.routing_page.select_rule(rule_set.id)
            self._show_status("info", f"Правило уже есть: {rule_value}")
            return

        rule_set.enabled = True
        rule_set.outbound = normalized_outbound
        target_values.append(rule_value)
        target_values.sort(key=str.lower)
        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(rule_set.id)
        created_text = "создан набор, " if created else ""
        self._show_status("success", f"Live Activity: {created_text}{label} {rule_value} -> {rule_set.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _activity_rule_set(self, outbound: str) -> tuple[RoutingRuleSet, bool]:
        normalized_outbound = normalize_outbound(outbound)
        for rule_set in self.split_rules.rule_sets:
            if rule_set.source_type == LIVE_ACTIVITY_RULE_SOURCE_TYPE and normalize_outbound(rule_set.outbound) == normalized_outbound:
                return rule_set, False

        route_name = "напрямую" if normalized_outbound == ROUTE_OUTBOUND_DIRECT else "через VPN"
        rule_set = RoutingRuleSet(
            name=f"Live Activity: {route_name}",
            enabled=True,
            outbound=normalized_outbound,
            source_type=LIVE_ACTIVITY_RULE_SOURCE_TYPE,
            source=LIVE_ACTIVITY_RULE_SOURCE,
            priority=self._activity_rule_priority(normalized_outbound),
        )
        self.split_rules.rule_sets.append(rule_set)
        return rule_set, True

    def _activity_rule_priority(self, outbound: str) -> int:
        used_priorities = {rule_set.priority for rule_set in self.split_rules.rule_sets}
        priority = 100 if normalize_outbound(outbound) == ROUTE_OUTBOUND_DIRECT else 110
        while priority in used_priorities:
            priority += 1
        return priority

    def _activity_rule_target(
        self,
        rule_set: RoutingRuleSet,
        domain: str,
        match_kind: str,
    ) -> tuple[list[str], str, str]:
        if match_kind == "domain_suffix":
            return rule_set.domain_suffix, self._activity_domain_suffix(domain), "зона"
        return rule_set.domains, domain, "домен"

    @staticmethod
    def _normalize_activity_domain(domain: str) -> str:
        text = str(domain or "").strip().lower().strip(".")
        if "://" in text:
            text = urlparse(text).hostname or ""
        text = text.strip().strip(".")
        if not text or "." not in text:
            return ""
        if any(char.isspace() for char in text):
            return ""
        return text

    @staticmethod
    def _activity_domain_suffix(domain: str) -> str:
        return domain_site_suffix(domain)

    def save_settings(self, *, restart_connected: bool = True, show_success: bool = True) -> None:
        before_runtime = self._settings_runtime_key(self.settings)
        before_firewall_kill_switch = bool(self.settings.firewall_kill_switch)
        before_auto_start = bool(self.settings.auto_start_windows)
        try:
            next_settings = self.settings_page.apply_to_settings(AppSettings.from_dict(self.settings.to_dict()))
            if next_settings.to_dict() == self.settings.to_dict():
                return
            firewall_turning_on = bool(next_settings.firewall_kill_switch) and not before_firewall_kill_switch
            if firewall_turning_on and windows.is_windows() and not windows.is_admin():
                self._show_status("info", "Firewall Kill Switch требует права администратора. Сейчас откроется запрос Windows UAC.")
                if windows.relaunch_as_admin():
                    app_state.save_settings(next_settings)
                    QTimer.singleShot(250, self.exit_app)
                    return
                self._show_status("error", "Windows не выдала права администратора или запрос был отменен")
                self.settings_page.set_values(self.settings)
                return
            self.settings = next_settings
            paths.set_portable_mode(self.settings.portable_mode)
            if before_auto_start != bool(self.settings.auto_start_windows):
                windows.set_autostart(self.settings.auto_start_windows)
            if before_firewall_kill_switch and not self.settings.firewall_kill_switch:
                self._clear_firewall_kill_switch_safely()
            app_state.save_settings(self.settings)
            self._start_subscription_scheduler()
        except Exception as exc:
            self.logger.error("Settings save failed: %s\n%s", format_user_error(exc).display_text, format_safe_traceback(exc))
            self._show_status("error", format_user_error(exc, context="Настройки").display_text)
            self.settings_page.set_values(self.settings)
            return
        if show_success:
            self._show_status("success", "Настройки сохранены автоматически")
        if restart_connected and before_runtime != self._settings_runtime_key(self.settings):
            self._restart_if_connected("Перезапуск подключения…")

    @staticmethod
    def _settings_runtime_key(settings: AppSettings) -> tuple[object, ...]:
        return (
            settings.mode,
            settings.mixed_listen_host,
            int(settings.mixed_port),
            settings.tun_interface_name,
            settings.tun_address,
            settings.tun_ipv6_address,
            int(settings.tun_mtu),
            bool(settings.enable_ipv6),
            settings.dns_strategy,
            tuple(settings.dns_servers),
            tuple(settings.connectivity_check_urls),
            int(settings.connectivity_check_timeout_ms),
            bool(settings.kill_switch),
            bool(settings.firewall_kill_switch),
            bool(settings.enable_system_proxy_guard),
            settings.log_level,
        )

    def validate_current_config(self) -> None:
        profile = self._active_profile()
        if not profile:
            self._show_status("warning", "Нет активного профиля")
            return

        def worker() -> tuple[bool, str]:
            config_path = self.singbox.build_and_save_config(profile, self.settings, self.split_rules)
            return self.singbox.check_config(config_path)

        def done(result: tuple[bool, str]) -> None:
            ok, output = result
            self._show_status("success" if ok else "error", output)

        self._run_background(worker, done, busy="Проверка config…")

    def check_app_update(self, *, silent: bool = False) -> None:
        def worker() -> AppUpdateInfo | BaseException:
            try:
                return check_for_app_update(current_version=APP_VERSION)
            except Exception as exc:
                return exc

        def done(result: AppUpdateInfo | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_app_update_error(result, "Проверка обновлений", silent=silent)
                return
            if not result.update_available:
                if not silent:
                    self._show_status("info", f"Установлена актуальная версия: {APP_VERSION}")
                return
            self._show_app_update_prompt(result)

        self._run_background(
            worker,
            done,
            busy=None if silent else "Проверка обновлений…",
            set_busy=not silent,
        )

    def _show_app_update_prompt(self, update: AppUpdateInfo) -> None:
        asset_line = "Windows-файл в release не найден"
        if update.asset:
            size = f" · {format_bytes(update.asset.size)}" if update.asset.size else ""
            asset_line = f"{update.asset.name}{size}"

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Доступно обновление")
        dialog.setText(f"Доступна версия {update.latest_version}")
        dialog.setInformativeText(
            f"Установлена версия: {update.current_version}\n"
            f"Release: {update.release_name or update.latest_version}\n"
            f"Файл: {asset_line}\n\n"
            "Приложение скачает файл в локальную папку downloads/app-updates. "
            "Автоматическая замена запущенного exe не выполняется."
        )
        download_button = None
        if update.asset:
            download_button = dialog.addButton("Скачать", QMessageBox.ButtonRole.AcceptRole)
        release_button = dialog.addButton("Открыть release", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        if download_button is not None and clicked is download_button:
            self.download_app_update(update)
            return
        if clicked is release_button:
            webbrowser.open(update.release_url)

    def download_app_update(self, update: AppUpdateInfo) -> None:
        if not update.asset:
            self._show_status("warning", "В release нет подходящего Windows-файла обновления")
            webbrowser.open(update.release_url)
            return

        def worker() -> Path | BaseException:
            try:
                return download_update_asset(update)
            except Exception as exc:
                return exc

        def done(result: Path | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_app_update_error(result, "Загрузка обновления", silent=False)
                return
            self._show_status("success", f"Обновление скачано: {result.name}")
            self._prompt_downloaded_update(result)

        self._run_background(worker, done, busy="Скачивание обновления…")

    def _prompt_downloaded_update(self, path: Path) -> None:
        is_installer = path.suffix.lower() in {".exe", ".msi"}
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Обновление скачано")
        dialog.setText(path.name)
        dialog.setInformativeText(
            "Перед установкой новой версии закройте VPN-подключение и само приложение.\n\n"
            f"Файл сохранён: {path}"
        )
        open_label = "Запустить файл" if is_installer else "Показать файл"
        open_button = dialog.addButton(open_label, QMessageBox.ButtonRole.AcceptRole)
        folder_button = dialog.addButton("Открыть папку", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Позже", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        try:
            if clicked is open_button:
                if is_installer:
                    windows.open_path(path)
                else:
                    windows.reveal_in_file_manager(path)
            elif clicked is folder_button:
                windows.open_path(path.parent)
        except Exception as exc:
            self.logger.error("Не удалось открыть скачанное обновление: %s\n%s", sanitize_error_text(exc), format_safe_traceback(exc))
            self._show_status("error", f"Не удалось открыть файл: {sanitize_error_text(exc)}")

    def _handle_app_update_error(self, error: BaseException, action: str, *, silent: bool) -> None:
        message = sanitize_error_text(error) or "неизвестная ошибка"
        self.logger.warning("%s приложения не выполнена: %s\n%s", action, message, format_safe_traceback(error))
        if not silent:
            self._show_status("error", f"{action}: {message}")

    def download_core(self) -> None:
        def done(exe: Path) -> None:
            self._core_version_cache = None
            self.about_page.set_core_version(self._core_version(refresh=True))
            self._show_status("success", f"Установлен: {exe}")

        self._run_background(lambda: self.singbox.download_latest(), done, busy="Загрузка sing-box…")

    def check_dns(self) -> None:
        self._run_background(lambda: check_dns_resolver(), lambda result: QMessageBox.information(self, "DNS leak check", result), busy="Проверка DNS…")

    def clear_log_window(self) -> None:
        self.logs_page.clear_view()

    def clear_domain_activity(self) -> None:
        self.domain_activity.clear()
        self._refresh_activity_page()

    def export_logs(self) -> None:
        default_name = f"razreshenie-diagnostics-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт диагностики",
            default_name,
            "Zip archive (*.zip)",
        )
        if not target:
            return

        def worker() -> Path:
            return build_diagnostics_archive(
                target,
                settings=self.settings,
                profiles=self.profiles,
                subscriptions=self.subscriptions,
                split_rules=self.split_rules,
                quality_stats=self.smart_connect.quality_stats,
                smart_groups=self.smart_connect.smart_groups,
                singbox=self.singbox,
                log_lines=self.log_buffer.snapshot("all"),
            )

        def done(path: Path) -> None:
            self._show_status("success", f"Диагностика сохранена: {path}")

        self._run_background(worker, done, busy="Экспорт диагностики…")

    def reset_all_app_data(self) -> None:
        confirmation = QMessageBox(self)
        confirmation.setIcon(QMessageBox.Icon.Warning)
        confirmation.setWindowTitle("Удалить все настройки?")
        confirmation.setText("Удалить все настройки Razreshenie VPN Client?")
        confirmation.setInformativeText(
            "Будут удалены все серверы, подписки, правила маршрутизации, настройки, "
            "runtime-конфиги и скачанный sing-box core.\n\n"
            "После удаления VPN-клиент будет полностью закрыт. Это действие нельзя отменить."
        )
        confirmation.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        confirmation.setDefaultButton(QMessageBox.StandardButton.No)
        confirmation.button(QMessageBox.StandardButton.Yes).setText("Удалить и закрыть")
        confirmation.button(QMessageBox.StandardButton.No).setText("Отмена")
        if confirmation.exec() != QMessageBox.StandardButton.Yes:
            return

        def worker() -> None:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self._clear_firewall_kill_switch_safely()
            windows.set_autostart(False)
            self._delete_runtime_data()

        self._run_background(worker, lambda _result: self._finish_reset_and_exit(), busy="Сброс данных…")

    def _delete_runtime_data(self) -> None:
        app_dirs = paths.ensure_app_dirs()
        root = paths.data_dir().resolve()
        for file_path in (paths.settings_path(), paths.profiles_path(), paths.subscriptions_path(), paths.rules_path()):
            resolved = file_path.resolve()
            if resolved.exists() and self._is_inside(resolved, root):
                resolved.unlink()
        for dir_path in (app_dirs["configs"], app_dirs["cores"], app_dirs["downloads"], app_dirs["rules"], app_dirs["backups"]):
            resolved = dir_path.resolve()
            if resolved.exists() and self._is_inside(resolved, root):
                shutil.rmtree(resolved)

    def _finish_reset_and_exit(self) -> None:
        self.logger.info("Все настройки, серверы и sing-box удалены. Приложение закрывается.")
        self._busy = False
        self._closing = True
        if self.metrics_timer.isActive():
            self.metrics_timer.stop()
        if self.activity_timer.isActive():
            self.activity_timer.stop()
        if self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.stop()
        if self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        self.latency_scanner.stop()
        if self.tray:
            self.tray.hide()
        self.hide()
        self.close()
        QApplication.quit()

    def _status_loop(self) -> None:
        running = self.singbox.is_running()
        if not running and self._last_connection_running:
            self._handle_unexpected_core_stop()
        elif running:
            self._last_connection_running = True
        elif not self._failover_in_progress:
            self._last_connection_running = False
        sample = self.traffic.sample(active=running)
        self._speed_label = f"↓ {format_speed(sample.download)}   ↑ {format_speed(sample.upload)}"
        now = int(time.time())
        self._maybe_run_background_health_check(now, running)
        if now - self._last_ip_refresh > 30 and not self._ip_refreshing:
            self._last_ip_refresh = now
            self._ip_refreshing = True

            def ip_done(ip: str) -> None:
                self._set_ip(f"IP: {ip}")
                self._ip_refreshing = False

            self._run_background(get_public_ip, ip_done, set_busy=False)
        if now - self._last_ping_refresh > 10 and not self._ping_refreshing:
            self._last_ping_refresh = now
            profile = self._active_profile()
            if profile:
                self._ping_refreshing = True
                address, port = profile.address, profile.port

                def ping_worker() -> str:
                    latency = measure_server_latency_ms(address, port, timeout_ms=1000)
                    return f"{latency} мс" if latency is not None else "таймаут"

                def ping_done(ping: str) -> None:
                    self._set_ping(f"Пинг: {ping}")
                    self._ping_refreshing = False

                self._run_background(ping_worker, ping_done, set_busy=False)
        self.dashboard_page.set_metrics(
            self._ip_label,
            self._ping_label,
            self._speed_label,
            sample.download,
            sample.upload,
            format_bytes(sample.total_download),
            format_bytes(sample.total_upload),
        )

    def _set_ip(self, text: str) -> None:
        self._ip_label = text

    def _set_ping(self, text: str) -> None:
        self._ping_label = text

    def _start_subscription_scheduler(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        if self.settings.auto_update_subscriptions:
            interval = self.settings.subscription_update_interval_hours * 3600
            self.scheduler = RepeatingTask(interval, lambda: self.bridge.call.emit(self.update_all_subscriptions))
            self.scheduler.start()

    def _run_background(
        self,
        worker: Callable[[], object],
        on_success: Callable[[object], None] | None = None,
        *,
        busy: str | None = None,
        set_busy: bool = True,
    ) -> None:
        if set_busy and busy:
            self._busy = True
            self.dashboard_page.set_connection(self.singbox.is_running(), busy=True, message=busy)

        def target() -> None:
            try:
                result = worker()
            except Exception as exc:
                message = format_user_error(exc)
                self.logger.error("Background task failed [%s]: %s\n%s", message.category, message.display_text, format_safe_traceback(exc))
                self.bridge.call.emit(lambda message=message: self._show_status("error", message.display_text))
            else:
                if on_success:
                    self.bridge.call.emit(lambda result=result: on_success(result))
            finally:
                if set_busy:
                    self.bridge.call.emit(self._clear_busy)

        threading.Thread(target=target, daemon=True).start()

    def _clear_busy(self) -> None:
        if self._closing:
            return
        self._busy = False
        self.dashboard_page.set_connection(self.singbox.is_running())

    def _rules_summary_line(self) -> str:
        status = "включены" if self.split_rules.enabled_rule_sets else "отключены"
        default_label = "текущий сервер" if self.split_rules.effective_default_outbound == ROUTE_OUTBOUND_PROXY else "напрямую"
        return (
            f"Правила: {status} · наборов: {len(self.split_rules.rule_sets)} · "
            f"активных: {len(self.split_rules.enabled_rule_sets)} · остальной трафик: {default_label} · "
            f"rule-set resources: {len(self.split_rules.rule_set_resources)} · "
            f"встроенный bypass: {len(BUILTIN_DIRECT_DOMAIN_SUFFIXES)} доменов"
        )

    def _rules_summary_text(self) -> str:
        lines = [
            self._rules_summary_line(),
            "",
            "Каждый набор ниже имеет собственный маршрут: текущий сервер или напрямую.",
            (
                f"Встроенный bypass всегда отправляет напрямую {len(BUILTIN_DIRECT_DOMAIN_SUFFIXES)} доменов "
                f"из whitelist.json. Примеры: {', '.join(BUILTIN_DIRECT_DOMAIN_SUFFIXES[:12])}."
            ),
            "",
        ]
        if not self.split_rules.rule_sets:
            lines.append("Пользовательские правила не загружены.")
            return "\n".join(lines)

        resource_by_tag = {
            resource.tag: resource
            for resource in self.split_rules.rule_set_resources
            if resource.tag
        }
        for index, rule_set in enumerate(self._ordered_rule_sets(), start=1):
            preview = (
                rule_set.domains
                + rule_set.domain_suffix
                + rule_set.domain_keyword
                + rule_set.domain_regex
                + [f"geosite:{item}" for item in rule_set.geosite]
                + [f"geoip:{item}" for item in rule_set.geoip]
                + rule_set.ip_cidr
                + rule_set.process_name
                + rule_set.process_path
                + rule_set.process_path_regex
                + [f"rule_set:{item}" for item in rule_set.rule_set_tags]
            )[:12]
            lines.extend(
                [
                    f"{index}. {rule_set.name}",
                    f"   Маршрут: {rule_set.outbound_label}",
                    f"   Статус: {'включен' if rule_set.enabled else 'отключен'}",
                    f"   Приоритет: {rule_set.priority}",
                    f"   Источник: {rule_set.source or '—'}",
                    f"   Элементов: {rule_set.total_items}",
                    f"   Домены exact: {len(rule_set.domains)}",
                    f"   Домены suffix: {len(rule_set.domain_suffix)}",
                    f"   Ключевые слова доменов: {len(rule_set.domain_keyword)}",
                    f"   Domain regex: {len(rule_set.domain_regex)}",
                    f"   Geosite: {len(rule_set.geosite)}",
                    f"   GeoIP: {len(rule_set.geoip)}",
                    f"   IP/CIDR: {len(rule_set.ip_cidr)}",
                    f"   Процессы: {len(rule_set.process_name)}",
                    f"   Process path: {len(rule_set.process_path)}",
                    f"   Process path regex: {len(rule_set.process_path_regex)}",
                    f"   Rule-set: {', '.join(rule_set.rule_set_tags) if rule_set.rule_set_tags else '—'}",
                    f"   Первые элементы: {', '.join(preview) if preview else '—'}",
                    "",
                ]
            )
            for tag in rule_set.rule_set_tags:
                resource = resource_by_tag.get(tag)
                if resource:
                    location = resource.url or resource.path or resource.source or "—"
                    lines.extend(
                        [
                            f"   Resource {tag}: {resource.type}/{resource.format}",
                            f"   Location: {location}",
                            "",
                        ]
                    )
        return "\n".join(lines)

    def _show_status(self, level: str, message: str) -> None:
        if level == "error":
            InfoBar.error("Ошибка", message, position=InfoBarPosition.TOP_RIGHT, duration=6000, parent=self)
        elif level == "warning":
            InfoBar.warning("Внимание", message, position=InfoBarPosition.TOP_RIGHT, duration=3500, parent=self)
        elif level == "success":
            InfoBar.success("Успешно", message, position=InfoBarPosition.TOP_RIGHT, duration=2500, parent=self)
        else:
            InfoBar.info("Инфо", message, position=InfoBarPosition.TOP_RIGHT, duration=2500, parent=self)

    def _on_log_from_thread(self, level: str, message: str) -> None:
        self.log_buffer.append(level, message)
        if self.domain_activity.ingest_log_line(message, self.split_rules):
            should_emit = False
            with self._activity_signal_lock:
                if not self._activity_signal_pending:
                    self._activity_signal_pending = True
                    should_emit = True
            if should_emit:
                self.bridge.activity_changed.emit()
        self.bridge.log_line.emit(level, message)

    def _append_log_line(self, _level: str, message: str) -> None:
        self.logs_page.append_line(message)

    def _schedule_activity_refresh(self, delay_ms: int = 180) -> None:
        if self._closing:
            return
        if delay_ms <= 0:
            if self.activity_refresh_timer.isActive():
                self.activity_refresh_timer.stop()
            self._refresh_activity_page()
            return
        if not self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.start(delay_ms)

    def _refresh_activity_page(self) -> None:
        entries = self.domain_activity.snapshot(
            self.activity_page.query(),
            self.activity_page.route_filter(),
            self.activity_page.rule_filter(),
            self.activity_page.sort_mode(),
        )
        self.activity_page.set_entries(entries)
        with self._activity_signal_lock:
            self._activity_signal_pending = False

    def _refresh_tray_text(self) -> None:
        if not self.tray:
            return
        status = "подключено" if self.singbox.is_running() else "отключено"
        self.tray.setToolTip(f"{APP_NAME} {APP_VERSION} — {status}")
        if hasattr(self, "tray_connect_action"):
            self.tray_connect_action.setEnabled(not self.singbox.is_running())
            self.tray_disconnect_action.setEnabled(self.singbox.is_running())

    def show_normal(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            event.accept()
            return
        if self.settings.minimize_to_tray and not self._closing:
            event.ignore()
            self.hide()
            windows.show_toast("Razreshenie VPN", "Приложение свернуто в трей")
            return
        self._flush_pending_settings_save()
        self._closing = True
        self._shutdown_runtime()
        event.accept()
        QApplication.quit()

    def exit_app(self) -> None:
        if self._closing:
            QApplication.quit()
            return
        self._flush_pending_settings_save()
        self._closing = True
        self._shutdown_runtime()
        self.close()
        QApplication.quit()

    def _shutdown_runtime(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        self.latency_scanner.stop()
        if hasattr(self, "latency_result_timer") and self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        if hasattr(self, "activity_refresh_timer") and self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.stop()
        try:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self._clear_firewall_kill_switch_safely()
        finally:
            if self.tray:
                self.tray.hide()

    @staticmethod
    def _is_inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False


class RazreshenieApp:
    """Совместимая обертка для main.py: предоставляет mainloop как у Tk-приложения."""

    def __init__(self) -> None:
        self.qt_app = QApplication.instance() or QApplication(sys.argv)
        self.qt_app.setApplicationName(APP_NAME)
        self.qt_app.setApplicationVersion(APP_VERSION)
        install_emoji_font_fallbacks()
        setTheme(Theme.DARK)
        setThemeColor(ACCENT)
        self.window = RazreshenieWindow()

    def mainloop(self) -> int:
        self.window.show()
        return int(self.qt_app.exec())
