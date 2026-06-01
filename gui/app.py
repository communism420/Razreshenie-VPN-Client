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

from PyQt6.QtCore import QEasingCurve, QObject, QPointF, QRectF, QSize, Qt, QTimer, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QAction, QCloseEvent, QColor, QIcon, QPainter, QPen, QPixmap
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
    LineEdit,
    NavigationItemPosition,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SearchLineEdit,
    SettingCard,
    SettingCardGroup,
    SmoothScrollArea,
    SpinBox,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    SwitchSettingCard,
    TableWidget,
    Theme,
    setTheme,
    setThemeColor,
)

from core import app_state
from core.domain_activity import DomainActivityEntry, DomainActivityTracker
from core.latency_scanner import LatencyScanner, LatencyScanSummary
from core.rules_manager import RulesImportError, RulesManager
from core.singbox_manager import SingBoxError, SingBoxManager
from core.subscription_manager import SubscriptionError, SubscriptionManager
from core.vless_parser import VlessParseError, parse_vless_uri
from models.profile import Subscription, VlessProfile, utc_now_iso
from models.rules import (
    BUILTIN_DIRECT_DOMAIN_SUFFIXES,
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RoutingRuleSet,
    SplitRules,
    normalize_outbound,
)
from models.settings import AppSettings
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
    APP_REPOSITORY,
    APP_VERSION,
    RUSSIA_MOBILE_WHITELIST_REPOSITORY,
    ZAPRET_KVN_REPOSITORY,
)


ACCENT = "#0078D4"
DANGER = "#D83B01"
SUCCESS = "#16C60C"
LATENCY_SCAN_TIMEOUT_MS = 900
LATENCY_SCAN_WORKERS = 32
LATENCY_BATCH_SIZE = 48
LATENCY_BATCH_INTERVAL_SECONDS = 0.25
LATENCY_UI_DRAIN_INTERVAL_MS = 16
LATENCY_UI_DRAIN_LIMIT = 24


def app_logo_icon() -> QIcon:
    logo = paths.logo_path()
    if logo.exists():
        icon = QIcon(str(logo))
        if not icon.isNull():
            return icon
    return QIcon(":/qfluentwidgets/images/logo.png")


def app_logo_pixmap(size: int) -> QPixmap:
    logo = paths.logo_path()
    pixmap = QPixmap(str(logo)) if logo.exists() else QPixmap()
    if pixmap.isNull():
        pixmap = app_logo_icon().pixmap(size, size)
    if pixmap.isNull():
        return pixmap
    return pixmap.scaled(
        size,
        size,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )


def create_logo_label(parent: QWidget, size: int = 56) -> QLabel:
    label = QLabel(parent)
    label.setFixedSize(size, size)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setPixmap(app_logo_pixmap(size))
    label.setStyleSheet("QLabel { background: transparent; }")
    return label


class UiBridge(QObject):
    call = pyqtSignal(object)
    log_line = pyqtSignal(str, str)
    activity_changed = pyqtSignal()


class TrafficGraphWidget(QWidget):
    """Живой график входящего/исходящего трафика, как компактные карточки zapret-kvn."""

    def __init__(self, parent: QWidget | None = None, max_points: int = 80) -> None:
        super().__init__(parent)
        self._down: deque[float] = deque(maxlen=max_points)
        self._up: deque[float] = deque(maxlen=max_points)
        self._max_points = max_points
        self.setMinimumHeight(120)

    def add_point(self, down_bps: float, up_bps: float) -> None:
        self._down.append(max(0.0, down_bps))
        self._up.append(max(0.0, up_bps))
        self.update()

    def clear_data(self) -> None:
        self._down.clear()
        self._up.clear()
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 35))
        painter.drawRoundedRect(rect, 6, 6)

        pad_x, pad_y = 10, 10
        graph_x = rect.x() + pad_x
        graph_y = rect.y() + pad_y
        graph_w = max(1.0, rect.width() - pad_x * 2)
        graph_h = max(1.0, rect.height() - pad_y * 2)
        grid_pen = QPen(QColor(255, 255, 255, 22))
        grid_pen.setWidthF(0.5)
        painter.setPen(grid_pen)
        for index in range(4):
            y = graph_y + graph_h * index / 3
            painter.drawLine(QPointF(graph_x, y), QPointF(graph_x + graph_w, y))

        all_values = list(self._down) + list(self._up)
        scale = max(max(all_values, default=1.0), 100.0) * 1.15
        self._draw_series(painter, self._down, QColor(0, 180, 255), graph_x, graph_y, graph_w, graph_h, scale)
        self._draw_series(painter, self._up, QColor(0, 220, 120), graph_x, graph_y, graph_w, graph_h, scale)
        painter.end()

    def _draw_series(
        self,
        painter: QPainter,
        values: deque[float],
        color: QColor,
        graph_x: float,
        graph_y: float,
        graph_w: float,
        graph_h: float,
        scale: float,
    ) -> None:
        if len(values) < 2:
            return
        points: list[QPointF] = []
        step = graph_w / max(1, self._max_points - 1)
        start_index = self._max_points - len(values)
        for index, value in enumerate(values):
            x = graph_x + (start_index + index) * step
            y = graph_y + graph_h - min(1.0, value / scale) * graph_h
            points.append(QPointF(x, y))
        pen = QPen(color)
        pen.setWidthF(2.0)
        painter.setPen(pen)
        for index in range(1, len(points)):
            painter.drawLine(points[index - 1], points[index])


class _LineCard(SettingCard):
    def __init__(self, icon, title: str, content: str, parent: QWidget | None = None) -> None:
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setMinimumWidth(360)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _SpinCard(SettingCard):
    def __init__(
        self,
        icon,
        title: str,
        content: str,
        minimum: int,
        maximum: int,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(icon, title, content, parent)
        self.spin = SpinBox(self)
        self.spin.setRange(minimum, maximum)
        self.spin.setMinimumWidth(160)
        self.hBoxLayout.addWidget(self.spin, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class JsonEditorDialog(QDialog):
    def __init__(self, title: str, data: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 620)
        layout = QVBoxLayout(self)
        self.editor = PlainTextEdit(self)
        self.editor.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
        layout.addWidget(self.editor, 1)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.save_btn = PrimaryPushButton("Сохранить", self)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.save_btn)
        layout.addLayout(buttons)
        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self.accept)

    def data(self) -> dict:
        return json.loads(self.editor.toPlainText())


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
        self.total_download_label = BodyLabel("↓ Прибыло: 0 Б", self.total_traffic_card)
        self.total_upload_label = BodyLabel("↑ Отправлено: 0 Б", self.total_traffic_card)
        total_traffic_layout.addWidget(self.total_download_label)
        total_traffic_layout.addWidget(self.total_upload_label)
        total_traffic_layout.addStretch(1)
        cards.addWidget(self.total_traffic_card, 1)

        self.traffic_card = CardWidget(container)
        traffic_layout = QVBoxLayout(self.traffic_card)
        traffic_layout.setContentsMargins(18, 16, 18, 16)
        traffic_layout.setSpacing(8)
        traffic_layout.addWidget(StrongBodyLabel("Трафик", self.traffic_card))
        metrics = QHBoxLayout()
        self.ip_label = BodyLabel("IP: —", self.traffic_card)
        self.ping_label = BodyLabel("Пинг: —", self.traffic_card)
        self.speed_label = BodyLabel("↓ 0.0 Б/с   ↑ 0.0 Б/с", self.traffic_card)
        metrics.addWidget(self.ip_label)
        metrics.addWidget(self.ping_label)
        metrics.addWidget(self.speed_label)
        metrics.addStretch(1)
        traffic_layout.addLayout(metrics)
        self.graph = TrafficGraphWidget(self.traffic_card)
        traffic_layout.addWidget(self.graph)
        root.addWidget(self.traffic_card)

        actions = QHBoxLayout()
        self.import_btn = PrimaryPushButton(FIF.ADD, "Импортировать VLESS", container)
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

    def set_profiles(self, profiles: list[VlessProfile], active_id: str | None) -> None:
        self._profile_ids.clear()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        selected_index = 0
        for index, profile in enumerate(profiles):
            self.profile_combo.addItem(f"{profile.name}  ({profile.address}:{profile.port})")
            self._profile_ids.append(profile.id)
            if active_id and profile.id == active_id:
                selected_index = index
        if profiles:
            self.profile_combo.setEnabled(True)
            self.profile_combo.setCurrentIndex(selected_index)
            self.connection_status.setText(profiles[selected_index].label)
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
        self.connection_status.setText(profile.label)

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
        self.speed_label.setText(speed)
        self.total_download_label.setText(f"↓ Прибыло: {total_down}")
        self.total_upload_label.setText(f"↑ Отправлено: {total_up}")
        self.graph.add_point(down_bps, up_bps)

    def set_rules_summary(self, text: str) -> None:
        self.rules_label.setText(text)

    def clear_graph(self) -> None:
        self.graph.clear_data()

    def _on_profile_changed(self, index: int) -> None:
        if 0 <= index < len(self._profile_ids):
            self.profile_selected.emit(self._profile_ids[index])

    def _on_mode_changed(self, _index: int) -> None:
        self.mode_changed.emit(str(self.mode_combo.currentData() or "proxy"))


class ServersPage(QWidget):
    import_requested = pyqtSignal()
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
        for item in ("Вручную", "Имя", "Пинг"):
            self.sort_combo.addItem(item)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.sort_combo)
        root.addLayout(filters)

        toolbar = QHBoxLayout()
        self.import_btn = PrimaryPushButton(FIF.ADD, "Импорт", self)
        self.edit_btn = PushButton(FIF.EDIT, "JSON", self)
        self.ping_btn = PushButton(FIF.SEND, "Пинг выбранного", self)
        self.ping_all_btn = PushButton(FIF.SYNC, "Пинг всех", self)
        self.ping_all_btn.setFixedWidth(150)
        self.sort_ping_btn = PushButton(FIF.SPEED_HIGH, "Сортировать по отклику", self)
        self.validate_btn = PushButton(FIF.CODE, "Проверить config", self)
        self.delete_btn = PushButton(FIF.DELETE, "Удалить", self)
        for widget in (
            self.import_btn,
            self.edit_btn,
            self.ping_btn,
            self.ping_all_btn,
            self.sort_ping_btn,
            self.validate_btn,
            self.delete_btn,
        ):
            toolbar.addWidget(widget)
        toolbar.addStretch(1)
        root.addLayout(toolbar)

        self.table = TableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Название", "Адрес", "Порт", "Тип", "Пинг", "Активен"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(34)
        fixed_columns = {2: 72, 3: 82, 4: 96, 5: 86}
        for col, width in fixed_columns.items():
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(col, width)
        root.addWidget(self.table, 1)

        self.search.textChanged.connect(self.reload)
        self.sort_combo.currentIndexChanged.connect(self.reload)
        self.table.cellPressed.connect(self._activate_pressed_cell)
        self.import_btn.clicked.connect(self.import_requested)
        self.edit_btn.clicked.connect(lambda: self._emit_for_selected(self.edit_requested))
        self.delete_btn.clicked.connect(lambda: self._emit_for_selected(self.delete_requested))
        self.ping_btn.clicked.connect(lambda: self._emit_for_selected(self.ping_requested))
        self.ping_all_btn.clicked.connect(self.ping_all_requested)
        self.sort_ping_btn.clicked.connect(self.sort_latency_requested)
        self.validate_btn.clicked.connect(self.validate_requested)

    def set_profiles(
        self,
        profiles: list[VlessProfile],
        active_id: str | None,
        subscriptions: list[Subscription] | None = None,
    ) -> None:
        self._profiles = list(profiles)
        self._profile_by_id = {profile.id: profile for profile in self._profiles}
        if subscriptions is not None:
            self._subscription_names = {subscription.id: subscription.name for subscription in subscriptions}
        self._active_id = active_id
        self.reload()

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
                values = [
                    profile.name,
                    profile.address,
                    str(profile.port),
                    profile.protocol.upper(),
                    self._latency_label(profile),
                    "Да" if profile.id == getattr(self, "_active_id", None) else "",
                ]
                for col, value in enumerate(values):
                    table_item = QTableWidgetItem(value)
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
                    ]
            else:
                items = list(group_profiles)
            if not items:
                continue
            if sort_mode == "Имя":
                items.sort(key=lambda item: item.name.lower())
            elif sort_mode == "Пинг":
                items.sort(key=lambda item: (item.latency_ms is None, item.latency_ms or 10**9, item.name.lower()))
            rows.append(("group", group_id, None))
            if query or group_id not in self._collapsed_groups:
                rows.extend(("profile", profile.id, profile) for profile in items)
        return rows

    @staticmethod
    def _group_id(profile: VlessProfile) -> str:
        return profile.subscription_id or "__manual__"

    def _group_name(self, group_id: str) -> str:
        if group_id == "__manual__":
            return "Без подписки"
        return self._subscription_names.get(group_id) or "Подписка"

    def _group_count(self, group_id: str) -> int:
        return sum(1 for profile in self._profiles if self._group_id(profile) == group_id)

    def _set_group_row(self, row: int, group_id: str) -> None:
        collapsed = group_id in self._collapsed_groups and not self.search.text().strip()
        arrow = "▸" if collapsed else "▾"
        count = self._group_count(group_id)
        item = QTableWidgetItem(f"{arrow}  {self._group_name(group_id)}  ·  {count} серверов")
        item.setData(Qt.ItemDataRole.UserRole, group_id)
        item.setForeground(QColor("#F2F2F2"))
        item.setBackground(QColor("#303030"))
        self.table.setItem(row, 0, item)
        self.table.setSpan(row, 0, 1, self.table.columnCount())
        self.table.setRowHeight(row, self._group_row_height())

    def _latency_label(self, profile: VlessProfile) -> str:
        if profile.latency_ms is not None:
            return f"{profile.latency_ms} ms"
        if profile.latency_checked_at:
            return "timeout"
        return "--"

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
            item.setText(f"{arrow}  {self._group_name(group_id)}  ·  {self._group_count(group_id)} серверов")

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
        color = QColor(0, 120, 212) if active else QColor("#F2F2F2")
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setForeground(color)
        active_item = self.table.item(row, 5)
        if active_item:
            active_item.setText("Да" if active else "")

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
                item = self.table.item(row, 4)
                if item:
                    item.setText(self._latency_label(profile))
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
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Название", "URL", "Профилей", "Обновлено", "Ошибка"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
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
            values = [sub.name, sub.url, str(profile_count), sub.last_update_at or "никогда", sub.last_error or ""]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, sub.id)
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()

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
    rule_outbound_requested = pyqtSignal(str, str)
    rule_enabled_requested = pyqtSignal(str, bool)
    delete_rule_requested = pyqtSignal(str)
    clear_rules_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("routing")
        self._ids: list[str] = []
        self._rule_sets: list[RoutingRuleSet] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Маршрутизация", self))
        group = CardWidget(self)
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(18, 16, 18, 16)
        buttons = QHBoxLayout()
        self.file_btn = PrimaryPushButton(FIF.FOLDER, "Загрузить JSON/TXT-файл", group)
        self.url_btn = PushButton(FIF.DOWNLOAD, "Загрузить raw-ссылку", group)
        self.clear_btn = PushButton(FIF.DELETE, "Очистить все", group)
        buttons.addWidget(self.file_btn)
        buttons.addWidget(self.url_btn)
        buttons.addWidget(self.clear_btn)
        buttons.addStretch(1)
        group_layout.addWidget(BodyLabel("Наборы маршрутизации", group))
        group_layout.addLayout(buttons)
        root.addWidget(group)

        self.table = TableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Набор", "Туннелирование", "Элементов", "Включен", "Источник", "Действия"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table, 3)

        self.summary = PlainTextEdit(self)
        self.summary.setReadOnly(True)
        root.addWidget(self.summary, 1)
        self.file_btn.clicked.connect(self.load_file_requested)
        self.url_btn.clicked.connect(self.load_url_requested)
        self.clear_btn.clicked.connect(self.clear_rules_requested)

    def set_rules(self, rules: SplitRules, summary: str) -> None:
        selected_before = self.selected_id()
        self._rule_sets = list(rules.rule_sets)
        self._ids = [rule_set.id for rule_set in rules.rule_sets]
        self.table.setRowCount(len(rules.rule_sets))
        for row, rule_set in enumerate(rules.rule_sets):
            values = [
                rule_set.name,
                "",
                str(rule_set.total_items),
                "",
                rule_set.source or rule_set.source_type or "—",
                "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, rule_set.id)
                if not rule_set.enabled:
                    item.setForeground(QColor(150, 150, 150))
                elif normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_PROXY:
                    item.setForeground(QColor(0, 120, 212))
                self.table.setItem(row, col, item)
            self.table.setCellWidget(row, 1, self._route_combo(rule_set))
            self.table.setCellWidget(row, 3, self._enabled_switch(rule_set))
            self.table.setCellWidget(row, 5, self._delete_button(rule_set))
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
        self.export_btn = PrimaryPushButton("Экспорт", self)
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


class DomainActivityPage(QWidget):
    filters_changed = pyqtSignal()
    clear_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("domain_activity")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(SubtitleLabel("Активность доменов", self))
        hint = CaptionLabel(
            "Свежие домены и поддомены из runtime-логов sing-box с маршрутом VPN или напрямую.",
            self,
        )
        hint.setWordWrap(True)
        root.addWidget(hint)

        toolbar = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Фильтр по словам в домене или поддомене")
        self.route_combo = ComboBox(self)
        self.route_combo.addItem("Все маршруты", userData="all")
        self.route_combo.addItem("Через VPN", userData=ROUTE_OUTBOUND_PROXY)
        self.route_combo.addItem("Напрямую", userData=ROUTE_OUTBOUND_DIRECT)
        self.clear_btn = PushButton(FIF.DELETE, "Очистить", self)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.route_combo)
        toolbar.addWidget(self.clear_btn)
        root.addLayout(toolbar)

        self.table = TableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Домен / поддомен", "Маршрут", "Правило", "Запросов", "Первый раз", "Последний раз"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col in (1, 3, 4, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table, 1)

        self.search.textChanged.connect(lambda _text: self.filters_changed.emit())
        self.route_combo.currentIndexChanged.connect(lambda _index: self.filters_changed.emit())
        self.clear_btn.clicked.connect(self.clear_requested)

    def query(self) -> str:
        return self.search.text().strip()

    def route_filter(self) -> str:
        return str(self.route_combo.currentData() or "all")

    def set_entries(self, entries: list[DomainActivityEntry]) -> None:
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = [
                entry.domain,
                entry.route_label,
                entry.rule_name,
                str(entry.hits),
                entry.first_seen_label,
                entry.last_seen_label,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if entry.route == ROUTE_OUTBOUND_PROXY:
                    item.setForeground(QColor(0, 180, 255))
                elif entry.route == ROUTE_OUTBOUND_DIRECT:
                    item.setForeground(QColor(0, 220, 120))
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()


class SettingsPage(QWidget):
    save_requested = pyqtSignal()
    reset_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("settings")
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
        self.interval_card = _SpinCard(FIF.UPDATE, "Интервал подписок", "Автообновление, часов", 1, 720, network_group)
        for card in (self.dns_card, self.port_card, self.mtu_card, self.interval_card):
            network_group.addSettingCard(card)
        root.addWidget(network_group)

        behavior_group = SettingCardGroup("Поведение", container)
        self.kill_switch_card = SwitchSettingCard(FIF.CHECKBOX, "Kill Switch", "Для TUN включает strict route", parent=behavior_group)
        self.proxy_guard_card = SwitchSettingCard(FIF.LINK, "Proxy guard", "Включать системный proxy Windows", parent=behavior_group)
        self.auto_connect_card = SwitchSettingCard(FIF.PLAY_SOLID, "Автоподключение", "Подключаться при запуске приложения", parent=behavior_group)
        self.auto_start_card = SwitchSettingCard(FIF.PLAY_SOLID, "Автозапуск Windows", "Запускать приложение вместе с Windows", parent=behavior_group)
        self.auto_update_card = SwitchSettingCard(FIF.SYNC, "Автообновление подписок", "Обновлять подписки по расписанию", parent=behavior_group)
        self.data_dir_card = SettingCard(FIF.FOLDER, "Папка данных", str(paths.data_dir()), behavior_group)
        self.notifications_card = SwitchSettingCard(FIF.INFO, "Windows-уведомления", "Показывать toast-уведомления", parent=behavior_group)
        self.tray_card = SwitchSettingCard(FIF.DOWN, "Сворачивать в трей", "Закрытие окна скрывает приложение", parent=behavior_group)
        for card in (
            self.kill_switch_card,
            self.proxy_guard_card,
            self.auto_connect_card,
            self.auto_start_card,
            self.auto_update_card,
            self.data_dir_card,
            self.notifications_card,
            self.tray_card,
        ):
            behavior_group.addSettingCard(card)
        root.addWidget(behavior_group)

        actions = QHBoxLayout()
        self.save_btn = PrimaryPushButton(FIF.SAVE, "Сохранить настройки", container)
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
        actions.addWidget(self.save_btn)
        actions.addWidget(self.reset_btn)
        actions.addStretch(1)
        root.addLayout(actions)
        root.addStretch(1)
        self.save_btn.clicked.connect(self.save_requested)
        self.reset_btn.clicked.connect(self.reset_requested)

    def set_values(self, settings: AppSettings) -> None:
        self.dns_card.edit.setText(", ".join(settings.dns_servers))
        self.port_card.spin.setValue(settings.mixed_port)
        self.mtu_card.spin.setValue(settings.tun_mtu)
        self.interval_card.spin.setValue(settings.subscription_update_interval_hours)
        self.kill_switch_card.setChecked(settings.kill_switch)
        self.proxy_guard_card.setChecked(settings.enable_system_proxy_guard)
        self.auto_connect_card.setChecked(settings.auto_connect)
        self.auto_start_card.setChecked(settings.auto_start_windows)
        self.auto_update_card.setChecked(settings.auto_update_subscriptions)
        self.notifications_card.setChecked(settings.show_notifications)
        self.tray_card.setChecked(settings.minimize_to_tray)

    def apply_to_settings(self, settings: AppSettings) -> AppSettings:
        settings.dns_servers = [item.strip() for item in self.dns_card.edit.text().split(",") if item.strip()]
        settings.mixed_port = int(self.port_card.spin.value())
        settings.tun_mtu = int(self.mtu_card.spin.value())
        settings.subscription_update_interval_hours = int(self.interval_card.spin.value())
        settings.kill_switch = self.kill_switch_card.isChecked()
        settings.enable_system_proxy_guard = self.proxy_guard_card.isChecked()
        settings.auto_connect = self.auto_connect_card.isChecked()
        settings.auto_start_windows = self.auto_start_card.isChecked()
        settings.auto_update_subscriptions = self.auto_update_card.isChecked()
        settings.portable_mode = False
        settings.show_notifications = self.notifications_card.isChecked()
        settings.minimize_to_tray = self.tray_card.isChecked()
        return settings


class AboutPage(QWidget):
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
            f"\"белого списка\" для встроенного bypass: {RUSSIA_MOBILE_WHITELIST_REPOSITORY}",
            card,
        )
        text.setWordWrap(True)
        self.version_label = CaptionLabel(f"Версия приложения: {APP_VERSION}", card)
        self.core_label = CaptionLabel("Core: sing-box", card)
        self.github_btn = PrimaryPushButton(FIF.LINK, "Открыть GitHub", card)
        self.zapret_btn = PushButton(FIF.LINK, "Открыть zapret-kvn", card)
        self.whitelist_btn = PushButton(FIF.LINK, "Открыть whitelist", card)
        layout.addLayout(header)
        layout.addSpacing(8)
        layout.addWidget(text)
        layout.addWidget(self.version_label)
        layout.addWidget(self.core_label)
        buttons = QHBoxLayout()
        buttons.addWidget(self.github_btn)
        buttons.addWidget(self.zapret_btn)
        buttons.addWidget(self.whitelist_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        root.addWidget(card)
        root.addStretch(1)
        self.github_btn.clicked.connect(lambda: webbrowser.open(APP_REPOSITORY))
        self.zapret_btn.clicked.connect(lambda: webbrowser.open(ZAPRET_KVN_REPOSITORY))
        self.whitelist_btn.clicked.connect(lambda: webbrowser.open(RUSSIA_MOBILE_WHITELIST_REPOSITORY))

    def set_core_version(self, version: str) -> None:
        self.core_label.setText(f"Core: {version}")


class RazreshenieWindow(FluentWindow):
    def __init__(self) -> None:
        super().__init__()
        paths.ensure_app_dirs()
        self.bridge = UiBridge(self)
        self.bridge.call.connect(lambda callback: callback())
        self.bridge.log_line.connect(self._append_log_line)
        self.bridge.activity_changed.connect(self._refresh_activity_page)
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
        self._sync_subscription_profile_counts(save=True)
        self.singbox = SingBoxManager(self.logger)
        self.latency_scanner = LatencyScanner(
            timeout_ms=LATENCY_SCAN_TIMEOUT_MS,
            max_workers=LATENCY_SCAN_WORKERS,
            batch_size=LATENCY_BATCH_SIZE,
            batch_interval_seconds=LATENCY_BATCH_INTERVAL_SECONDS,
            logger=self.logger,
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
        self._ip_label = "IP: —"
        self._ping_label = "Пинг: —"
        self._speed_label = "↓ 0.0 Б/с   ↑ 0.0 Б/с"
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
        self._create_navigation()
        self._create_tray()
        self._connect_signals()
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
        self.activity_timer.timeout.connect(self._refresh_activity_page)
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
        self.dashboard_page.import_requested.connect(self.import_vless_key)
        self.dashboard_page.dns_requested.connect(self.check_dns)
        self.dashboard_page.download_core_requested.connect(self.download_core)
        self.dashboard_page.rules_requested.connect(lambda: self.switchTo(self.routing_page))

        self.servers_page.import_requested.connect(self.import_vless_key)
        self.servers_page.activate_requested.connect(self.set_active_profile)
        self.servers_page.edit_requested.connect(self.edit_profile_by_id)
        self.servers_page.delete_requested.connect(self.delete_profile_by_id)
        self.servers_page.ping_requested.connect(self.test_profile_latency_by_id)
        self.servers_page.ping_all_requested.connect(self.test_all_latencies)
        self.servers_page.sort_latency_requested.connect(self.sort_profiles_by_latency)
        self.servers_page.validate_requested.connect(self.validate_current_config)

        self.subscriptions_page.add_requested.connect(self.add_subscription)
        self.subscriptions_page.update_requested.connect(self.update_subscription_by_id)
        self.subscriptions_page.update_all_requested.connect(self.update_all_subscriptions)
        self.subscriptions_page.delete_requested.connect(self.delete_subscription_by_id)

        self.routing_page.load_file_requested.connect(self.load_rules_file)
        self.routing_page.load_url_requested.connect(self.load_rules_url)
        self.routing_page.rule_outbound_requested.connect(self.set_rule_set_outbound)
        self.routing_page.rule_enabled_requested.connect(self.set_rule_set_enabled)
        self.routing_page.delete_rule_requested.connect(self.delete_rule_set)
        self.routing_page.clear_rules_requested.connect(self.clear_rule_sets)

        self.logs_page.clear_requested.connect(self.clear_log_window)
        self.logs_page.export_requested.connect(self.export_logs)
        self.activity_page.filters_changed.connect(self._refresh_activity_page)
        self.activity_page.clear_requested.connect(self.clear_domain_activity)
        self.settings_page.save_requested.connect(self.save_settings)
        self.settings_page.reset_requested.connect(self.reset_all_app_data)

    def _post_init(self) -> None:
        self.logger.info("Приложение запущено. Данные: %s", paths.data_dir())
        if self.settings.first_run:
            message = QMessageBox(self)
            message.setWindowTitle("Добро пожаловать")
            message.setText(f"{APP_NAME} {APP_VERSION}")
            message.setInformativeText(
                "Разреши себе доступ к любым сайтам.\n\n"
                "Приложение полностью open-source, GPLv3, без телеметрии и сбора данных.\n\n"
                f"Часть кода и дизайн-подходов адаптированы из zapret-kvn: {ZAPRET_KVN_REPOSITORY}"
            )
            pixmap = app_logo_pixmap(72)
            if not pixmap.isNull():
                message.setIconPixmap(pixmap)
            else:
                message.setIcon(QMessageBox.Icon.Information)
            message.exec()
            self.settings.first_run = False
            app_state.save_settings(self.settings)
        if self.settings.auto_connect and self.profiles:
            self.connect_vpn()

    def _refresh_all_views(self) -> None:
        self._rebuild_profile_index()
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        active = self._active_profile()
        active_id = active.id if active else None
        self.dashboard_page.set_profiles(self.profiles, active_id)
        self.dashboard_page.set_mode(self.settings.mode)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self.dashboard_page.set_rules_summary(self._rules_summary_line())
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions)
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
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions)

    def _refresh_servers_table(self) -> None:
        self._rebuild_profile_index()
        active = self._active_profile()
        active_id = active.id if active else None
        self.servers_page.set_profiles(self.profiles, active_id, self.subscriptions)

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

    def set_active_profile(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if self.settings.active_profile_id == profile_id:
            return
        self.settings.active_profile_id = profile_id
        app_state.save_settings(self.settings)
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile_id)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self._refresh_tray_text()

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

    def toggle_connection(self) -> None:
        if self.singbox.is_running():
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self) -> None:
        profile = self._active_profile()
        if not profile:
            self._show_status("warning", "Импортируйте VLESS-ключ или подписку")
            return
        if self.settings.mode == "tun" and not windows.is_admin():
            app_state.save_settings(self.settings)
            self._request_admin_for_tun("Для подключения в TUN-режиме нужны права администратора.")
            return

        def worker() -> None:
            self.singbox.start(profile, self.settings, self.split_rules)
            if self.settings.enable_system_proxy_guard and self.settings.mode == "proxy":
                windows.set_system_proxy(True, self.settings.mixed_listen_host, self.settings.mixed_port)

        self._run_background(worker, lambda _result: self._connected_ui(profile), busy="Подключение…")

    def disconnect_vpn(self) -> None:
        def worker() -> None:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)

        self._run_background(worker, lambda _result: self._disconnected_ui(), busy="Отключение…")

    def _connected_ui(self, profile: VlessProfile) -> None:
        self.dashboard_page.set_connection(True)
        self.traffic.reset()
        self.dashboard_page.clear_graph()
        self._refresh_tray_text()
        self._show_status("success", f"Подключено: {profile.name}")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", f"Подключено: {profile.name}")

    def _disconnected_ui(self) -> None:
        self.dashboard_page.set_connection(False)
        self._refresh_tray_text()
        self._show_status("info", "Соединение остановлено")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", "Соединение остановлено")

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

    def import_vless_key(self) -> None:
        value, ok = QInputDialog.getMultiLineText(self, "Импорт VLESS", "Вставьте vless:// ключ")
        if not ok or not value.strip():
            return
        try:
            profile = parse_vless_uri(value.strip())
        except VlessParseError as exc:
            self._show_status("error", str(exc))
            return
        self.profiles.append(profile)
        self.settings.active_profile_id = profile.id
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()
        self._show_status("success", f"Импортирован профиль: {profile.name}")

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
            self._show_status("error", f"Ошибка JSON: {exc}")
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
        self._show_status("error", f"Проверка отклика не удалась: {exc}")

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
        return profile

    def _save_profiles_background(self) -> None:
        snapshot = list(self.profiles)

        def worker() -> None:
            try:
                app_state.save_profiles(snapshot)
            except Exception as exc:
                self.logger.error("Не удалось сохранить профили после проверки отклика: %s", exc)

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

        def worker() -> tuple[list[VlessProfile], Subscription]:
            return self.subscription_manager.fetch(subscription)

        self._run_background(worker, lambda result: self._apply_subscription_update(result[1], result[0]), busy="Обновление подписки…")

    def _apply_subscription_update(self, subscription: Subscription, profiles: list[VlessProfile]) -> None:
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
        app_state.save_profiles(self.profiles)
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_settings(self.settings)
        self._refresh_server_views()
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
        self._refresh_tray_text()
        self._show_status("success", f"Подписка обновлена: {subscription.name} · серверов: {subscription.profile_count}")

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
        for subscription in list(self.subscriptions):
            if subscription.enabled:
                self.update_subscription(subscription)

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
            "Правила (*.json *.txt);;JSON (*.json);;TXT (*.txt);;Все файлы (*.*)",
        )
        if not file_name:
            return
        path = Path(file_name)
        default_outbound = ROUTE_OUTBOUND_DIRECT if path.suffix.lower() == ".txt" else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.from_file(path, default_outbound))

    def load_rules_url(self) -> None:
        url, ok = QInputDialog.getText(self, "Загрузка правил", "Raw GitHub URL на JSON или TXT")
        if not ok or not url.strip():
            return
        parsed = urlparse(url.strip())
        default_outbound = ROUTE_OUTBOUND_DIRECT if Path(parsed.path).suffix.lower() == ".txt" else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.from_url(url.strip(), default_outbound))

    def _load_rules(self, loader: Callable[[], RoutingRuleSet]) -> None:
        try:
            rule_set = loader()
        except RulesImportError as exc:
            self._show_status("error", str(exc))
            return
        self.split_rules.rule_sets.append(rule_set)
        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(rule_set.id)
        self._show_status("success", f"Добавлены правила: {rule_set.name} · {rule_set.outbound_label} · {rule_set.total_items} элементов")

    def set_rule_set_outbound(self, rule_set_id: str, outbound: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.outbound = normalize_outbound(outbound)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._show_status("success", f"{rule_set.name}: {rule_set.outbound_label}")

    def set_rule_set_enabled(self, rule_set_id: str, enabled: bool) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = bool(enabled)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()

    def toggle_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = not rule_set.enabled
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()

    def delete_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        if QMessageBox.question(self, "Удалить правила", f"Удалить {rule_set.name}?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules.rule_sets = [item for item in self.split_rules.rule_sets if item.id != rule_set_id]
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()

    def clear_rule_sets(self) -> None:
        if not self.split_rules.rule_sets:
            return
        if QMessageBox.question(self, "Очистить маршрутизацию", "Удалить все наборы правил маршрутизации?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules = SplitRules(enabled=False)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()

    def save_settings(self) -> None:
        try:
            self.settings = self.settings_page.apply_to_settings(self.settings)
            paths.set_portable_mode(self.settings.portable_mode)
            windows.set_autostart(self.settings.auto_start_windows)
            app_state.save_settings(self.settings)
            self._start_subscription_scheduler()
        except Exception as exc:
            self._show_status("error", f"Ошибка настроек: {exc}")
            return
        self._show_status("success", "Настройки сохранены")

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
        target, _ = QFileDialog.getSaveFileName(self, "Экспорт логов", "", "Log (*.log);;Text (*.txt)")
        if not target:
            return
        Path(target).write_text("\n".join(self.log_buffer.snapshot("all")), encoding="utf-8")
        self._show_status("success", f"Логи сохранены: {target}")

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
        if not running and self.dashboard_page.connection_state.text() == "Подключено":
            self.dashboard_page.set_connection(False)
        sample = self.traffic.sample(active=running)
        self._speed_label = f"↓ {format_speed(sample.download)}   ↑ {format_speed(sample.upload)}"
        now = int(time.time())
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
                self.logger.error("%s", exc)
                self.bridge.call.emit(lambda exc=exc: self._show_status("error", str(exc)))
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

        for index, rule_set in enumerate(self.split_rules.rule_sets, start=1):
            preview = (
                rule_set.domains
                + rule_set.domain_suffix
                + rule_set.domain_keyword
                + rule_set.ip_cidr
                + rule_set.process_name
            )[:12]
            lines.extend(
                [
                    f"{index}. {rule_set.name}",
                    f"   Маршрут: {rule_set.outbound_label}",
                    f"   Статус: {'включен' if rule_set.enabled else 'отключен'}",
                    f"   Источник: {rule_set.source or '—'}",
                    f"   Элементов: {rule_set.total_items}",
                    f"   Домены exact: {len(rule_set.domains)}",
                    f"   Домены suffix: {len(rule_set.domain_suffix)}",
                    f"   Ключевые слова доменов: {len(rule_set.domain_keyword)}",
                    f"   IP/CIDR: {len(rule_set.ip_cidr)}",
                    f"   Процессы: {len(rule_set.process_name)}",
                    f"   Первые элементы: {', '.join(preview) if preview else '—'}",
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
            self.bridge.activity_changed.emit()
        self.bridge.log_line.emit(level, message)

    def _append_log_line(self, _level: str, message: str) -> None:
        self.logs_page.append_line(message)

    def _refresh_activity_page(self) -> None:
        entries = self.domain_activity.snapshot(
            self.activity_page.query(),
            self.activity_page.route_filter(),
        )
        self.activity_page.set_entries(entries)

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
        self._closing = True
        self._shutdown_runtime()
        event.accept()
        QApplication.quit()

    def exit_app(self) -> None:
        if self._closing:
            QApplication.quit()
            return
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
        try:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
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
        setTheme(Theme.DARK)
        setThemeColor(ACCENT)
        self.window = RazreshenieWindow()

    def mainloop(self) -> int:
        self.window.show()
        return int(self.qt_app.exec())
