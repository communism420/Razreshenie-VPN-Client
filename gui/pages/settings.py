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

"""Страница настроек приложения."""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from qfluentwidgets import (
    ComboBox,
    FluentIcon as FIF,
    PushButton,
    SettingCard,
    SettingCardGroup,
    SmoothScrollArea,
    SubtitleLabel,
    SwitchSettingCard,
)

from core.connectivity import normalize_connectivity_timeout_ms, normalize_connectivity_urls
from gui.widgets import _LineCard, _SpinCard
from models.settings import (
    APP_UPDATE_MODE_DOWNLOAD_ONLY,
    APP_UPDATE_MODE_REPLACE_CURRENT,
    BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
    BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
    DEFAULT_TUN_IPV6_ADDRESS,
    DNS_STRATEGY_IPV4_ONLY,
    DNS_STRATEGY_IPV6_ONLY,
    DNS_STRATEGY_PREFER_IPV4,
    DNS_STRATEGY_PREFER_IPV6,
    SELF_HEALING_MAX_COOLDOWN_SECONDS,
    SELF_HEALING_MAX_MAX_ATTEMPTS,
    SELF_HEALING_MIN_COOLDOWN_SECONDS,
    SELF_HEALING_MIN_MAX_ATTEMPTS,
    AppSettings,
    normalize_app_update_mode,
    normalize_dns_strategy,
)
from utils import paths


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
        self.always_admin_card = SwitchSettingCard(
            FIF.CERTIFICATE,
            "Всегда запускать от имени администратора",
            "Запрашивать Windows UAC при каждом обычном запуске",
            parent=behavior_group,
        )
        self.app_updates_card = SwitchSettingCard(FIF.UPDATE, "Обновления приложения", "Проверять GitHub Releases при запуске", parent=behavior_group)
        self.update_mode_card = SettingCard(FIF.DOWNLOAD, "Способ обновления", "Как устанавливать новую версию приложения", behavior_group)
        self.update_mode_combo = ComboBox(self.update_mode_card)
        self.update_mode_combo.addItem("Скачать отдельно", userData=APP_UPDATE_MODE_DOWNLOAD_ONLY)
        self.update_mode_combo.addItem("Заменить текущий EXE", userData=APP_UPDATE_MODE_REPLACE_CURRENT)
        self.update_mode_combo.setMinimumWidth(230)
        self.update_mode_card.hBoxLayout.addWidget(self.update_mode_combo, 0, Qt.AlignmentFlag.AlignRight)
        self.update_mode_card.hBoxLayout.addSpacing(16)
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
            self.always_admin_card,
            self.app_updates_card,
            self.update_mode_card,
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
            self.always_admin_card.setChecked(settings.always_run_as_admin)
            self.app_updates_card.setChecked(settings.auto_check_app_updates)
            self._set_update_mode(settings.app_update_mode)
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
        settings.always_run_as_admin = self.always_admin_card.isChecked()
        settings.auto_check_app_updates = self.app_updates_card.isChecked()
        settings.app_update_mode = normalize_app_update_mode(self.update_mode_combo.currentData())
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

    def _set_update_mode(self, mode: str) -> None:
        normalized = normalize_app_update_mode(mode)
        for index in range(self.update_mode_combo.count()):
            if self.update_mode_combo.itemData(index) == normalized:
                self.update_mode_combo.setCurrentIndex(index)
                return
        self.update_mode_combo.setCurrentIndex(0)

    def _connect_auto_save_signals(self) -> None:
        for card in (
            self.ipv6_card,
            self.kill_switch_card,
            self.firewall_kill_switch_card,
            self.proxy_guard_card,
            self.auto_connect_card,
            self.smart_connect_card,
            self.auto_start_card,
            self.always_admin_card,
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
        self.update_mode_combo.currentIndexChanged.connect(self._emit_settings_changed)

    def _emit_settings_changed(self, *_args) -> None:
        if not self._loading_values:
            self.settings_changed.emit()
