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

"""Главная страница панели управления."""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    PrimaryPushButton,
    PushButton,
    SmoothScrollArea,
    StrongBodyLabel,
    SubtitleLabel,
)

from gui.common import (
    ACCENT,
    CARD_SPACING,
    DANGER,
    FLAG_ICON_SIZE,
    SUCCESS,
    apply_card_layout,
    apply_page_layout,
    create_logo_label,
    polish_toolbar_buttons,
    protocol_label,
    server_display_text_and_icon,
    server_label_html,
    style_badge_label,
)
from gui.widgets import TrafficGraphWidget
from models.profile import VlessProfile
from utils.network import format_speed
from utils.version import APP_NAME, APP_VERSION

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
        apply_page_layout(root)
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
        cards.setSpacing(CARD_SPACING + 4)
        root.addLayout(cards)

        self.connection_card = CardWidget(container)
        connection_layout = QVBoxLayout(self.connection_card)
        apply_card_layout(connection_layout)
        self.connection_card.setMinimumHeight(236)
        connection_layout.addWidget(StrongBodyLabel("Подключение", self.connection_card))
        self.connection_state = SubtitleLabel("Отключено", self.connection_card)
        self.connection_state.setStyleSheet(f"color: {DANGER}; font-weight: 700;")
        self.connection_status = CaptionLabel("Core остановлен", self.connection_card)
        self.connection_status.setWordWrap(True)
        self.profile_combo = ComboBox(self.connection_card)
        self.profile_combo.setIconSize(FLAG_ICON_SIZE)
        self.profile_combo.setMinimumWidth(260)
        self.mode_combo = ComboBox(self.connection_card)
        self.mode_combo.setMinimumWidth(132)
        self.mode_combo.addItem("Proxy", userData="proxy")
        self.mode_combo.addItem("TUN", userData="tun")
        self.toggle_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Подключить", self.connection_card)
        self.toggle_btn.setMinimumHeight(36)
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
        apply_card_layout(routing_layout)
        self.routing_card.setMinimumHeight(236)
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
        apply_card_layout(total_traffic_layout)
        self.total_traffic_card.setMinimumHeight(236)
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
        apply_card_layout(traffic_layout)
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
        polish_toolbar_buttons(self.import_btn, self.dns_btn, self.core_btn, min_width=150)
        self.import_btn.setToolTip("Добавить одиночную ссылку, подписку или файл с серверами")
        self.dns_btn.setToolTip("Проверить текущие DNS-настройки")
        self.core_btn.setToolTip("Скачать или обновить sing-box core")
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
        style_badge_label(caption, "muted")
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
