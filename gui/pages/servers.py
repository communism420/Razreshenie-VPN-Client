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

"""Страница списка серверов и групп."""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QEasingCurve, Qt, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QAction, QBrush, QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QMenu,
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
    PrimaryPushButton,
    PushButton,
    SearchLineEdit,
    StrongBodyLabel,
    SubtitleLabel,
    TableWidget,
)

from gui.common import (
    FLAG_ICON_SIZE,
    apply_card_layout,
    apply_page_layout,
    polish_table,
    polish_toolbar_buttons,
    protocol_label,
    server_display_text_and_icon,
    server_label_html,
    style_badge_label,
)
from models.connection import (
    QUALITY_EVENT_FAILURE,
    QUALITY_EVENT_LATENCY,
    QUALITY_EVENT_SUCCESS,
    SMART_GROUP_MODE_FAILOVER,
    SMART_GROUP_MODE_LOAD_BALANCE,
    SMART_GROUP_MODE_MULTI_HOP,
    SMART_STRATEGY_FAILOVER_ORDER,
    SMART_STRATEGY_LATENCY,
    SMART_STRATEGY_SMART,
    ServerQualityStats,
    SmartGroup,
)
from models.profile import Subscription, VlessProfile


SERVER_LATENCY_FAST_MS = 180
SERVER_LATENCY_OK_MS = 450
SERVER_QUALITY_GOOD_PERCENT = 90
SERVER_QUALITY_OK_PERCENT = 70
SMART_STRATEGY_LABELS = {
    SMART_STRATEGY_SMART: "Умный выбор",
    SMART_STRATEGY_LATENCY: "Минимальный пинг",
    SMART_STRATEGY_FAILOVER_ORDER: "По порядку",
}
SMART_GROUP_MODE_LABELS = {
    SMART_GROUP_MODE_FAILOVER: "Failover",
    SMART_GROUP_MODE_MULTI_HOP: "Multi-hop",
    SMART_GROUP_MODE_LOAD_BALANCE: "Load Balance",
}
QUALITY_EVENT_LABELS = {
    QUALITY_EVENT_LATENCY: "Latency",
    QUALITY_EVENT_SUCCESS: "Успех",
    QUALITY_EVENT_FAILURE: "Ошибка",
}


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
    smart_group_edit_requested = pyqtSignal(str)
    smart_group_start_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("servers")
        self._profiles: list[VlessProfile] = []
        self._profile_by_id: dict[str, VlessProfile] = {}
        self._quality_stats: dict[str, ServerQualityStats] = {}
        self._smart_groups: list[SmartGroup] = []
        self._smart_connect_enabled = True
        self._subscription_names: dict[str, str] = {}
        self._collapsed_groups: set[str] = set()
        self._row_entries: list[tuple[str, str]] = []
        self._visible_ids: list[str] = []
        self._row_by_id: dict[str, int] = {}
        self._active_id: str | None = None
        self._group_animation: QVariantAnimation | None = None
        root = QVBoxLayout(self)
        apply_page_layout(root)
        root.addWidget(SubtitleLabel("Серверы", self))

        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Поиск серверов")
        self.search.setClearButtonEnabled(True)
        self.sort_combo = ComboBox(self)
        for item in ("Вручную", "Имя", "Пинг", "Качество"):
            self.sort_combo.addItem(item)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.sort_combo)
        root.addLayout(filters)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.import_btn = PrimaryPushButton(FIF.ADD, "Импорт", self)
        self.import_menu = QMenu(self)
        self.import_text_action = QAction("Из текста", self)
        self.import_files_action = QAction("Из файлов", self)
        self.import_menu.addAction(self.import_text_action)
        self.import_menu.addAction(self.import_files_action)
        self.import_btn.setMenu(self.import_menu)
        self.edit_btn = PushButton(FIF.EDIT, "JSON", self)
        self.ping_btn = PushButton(FIF.SEND, "Пинг", self)
        self.ping_all_btn = PushButton(FIF.SYNC, "Пинг всех", self)
        self.ping_all_btn.setFixedWidth(150)
        self.sort_ping_btn = PushButton(FIF.SPEED_HIGH, "По отклику", self)
        self.failover_btn = PushButton(FIF.LINK, "Failover", self)
        self.validate_btn = PushButton(FIF.CODE, "Проверка", self)
        self.delete_btn = PushButton(FIF.DELETE, "Удалить", self)
        polish_toolbar_buttons(
            self.import_btn,
            self.edit_btn,
            self.ping_btn,
            self.ping_all_btn,
            self.sort_ping_btn,
            self.failover_btn,
            self.validate_btn,
            self.delete_btn,
            min_width=104,
        )
        self.edit_btn.setToolTip("Открыть JSON выбранного профиля")
        self.ping_btn.setToolTip("Проверить задержку выбранного сервера")
        self.ping_all_btn.setToolTip("Проверить задержку всех серверов")
        self.sort_ping_btn.setToolTip("Отсортировать список по задержке")
        self.failover_btn.setToolTip("Создать или обновить Failover-группу для выбранного сервера")
        self.validate_btn.setToolTip("Проверить sing-box config для выбранного профиля")
        self.delete_btn.setToolTip("Удалить выбранный сервер")
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

        self.smart_card = CardWidget(self)
        smart_layout = QVBoxLayout(self.smart_card)
        apply_card_layout(smart_layout)
        smart_header = QHBoxLayout()
        smart_header.setSpacing(10)
        smart_title = StrongBodyLabel("Smart Connect / Failover", self.smart_card)
        self.smart_status_label = BodyLabel("Smart Connect: —", self.smart_card)
        self.smart_summary_label = CaptionLabel("Failover-группы: 0", self.smart_card)
        self.create_failover_btn = PushButton(FIF.LINK, "Создать для выбранного", self.smart_card)
        self.start_group_btn = PushButton(FIF.PLAY_SOLID, "Запустить группу", self.smart_card)
        self.edit_group_btn = PushButton(FIF.EDIT, "Редактировать", self.smart_card)
        smart_header.addWidget(smart_title)
        smart_header.addSpacing(8)
        smart_header.addWidget(self.smart_status_label)
        smart_header.addWidget(self.smart_summary_label)
        smart_header.addStretch(1)
        smart_header.addWidget(self.create_failover_btn)
        smart_header.addWidget(self.start_group_btn)
        smart_header.addWidget(self.edit_group_btn)
        smart_layout.addLayout(smart_header)

        self.smart_groups_table = TableWidget(self.smart_card)
        self.smart_groups_table.setColumnCount(6)
        self.smart_groups_table.setHorizontalHeaderLabels(["Группа", "Режим", "Стратегия", "Серверов", "Статус", "Обновлена"])
        self.smart_groups_table.verticalHeader().setVisible(False)
        self.smart_groups_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.smart_groups_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.smart_groups_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.smart_groups_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.smart_groups_table.verticalHeader().setDefaultSectionSize(30)
        self.smart_groups_table.setMaximumHeight(148)
        polish_table(self.smart_groups_table, row_height=30)
        smart_layout.addWidget(self.smart_groups_table)
        root.addWidget(self.smart_card)

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
        polish_table(self.table, row_height=34)
        root.addWidget(self.table, 1)

        self.quality_card = CardWidget(self)
        quality_layout = QVBoxLayout(self.quality_card)
        apply_card_layout(quality_layout)
        quality_header = QHBoxLayout()
        quality_header.setSpacing(10)
        self.quality_title = StrongBodyLabel("История качества", self.quality_card)
        self.quality_server_label = BodyLabel("Сервер не выбран", self.quality_card)
        quality_header.addWidget(self.quality_title)
        quality_header.addSpacing(8)
        quality_header.addWidget(self.quality_server_label, 1)
        quality_layout.addLayout(quality_header)

        quality_metrics = QHBoxLayout()
        quality_metrics.setSpacing(12)
        self.quality_success_label = CaptionLabel("Success: —", self.quality_card)
        self.quality_latency_label = CaptionLabel("Latency: —", self.quality_card)
        self.quality_failures_label = CaptionLabel("Ошибки: —", self.quality_card)
        self.quality_checked_label = CaptionLabel("Проверка: —", self.quality_card)
        self.quality_usage_label = CaptionLabel("Использование: —", self.quality_card)
        for widget in (
            self.quality_success_label,
            self.quality_latency_label,
            self.quality_failures_label,
            self.quality_checked_label,
            self.quality_usage_label,
        ):
            quality_metrics.addWidget(widget)
        quality_metrics.addStretch(1)
        quality_layout.addLayout(quality_metrics)

        self.quality_history_table = TableWidget(self.quality_card)
        self.quality_history_table.setColumnCount(5)
        self.quality_history_table.setHorizontalHeaderLabels(["Время", "Событие", "Результат", "Latency", "Сообщение"])
        self.quality_history_table.verticalHeader().setVisible(False)
        self.quality_history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quality_history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quality_history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.quality_history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.quality_history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.quality_history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.quality_history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.quality_history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.quality_history_table.verticalHeader().setDefaultSectionSize(28)
        self.quality_history_table.setMaximumHeight(150)
        polish_table(self.quality_history_table, row_height=28)
        quality_layout.addWidget(self.quality_history_table)
        root.addWidget(self.quality_card)

        self.search.textChanged.connect(self.reload)
        self.sort_combo.currentIndexChanged.connect(self.reload)
        self.table.cellPressed.connect(self._activate_pressed_cell)
        self.table.itemSelectionChanged.connect(self._refresh_quality_panel)
        self.import_btn.clicked.connect(self.import_requested)
        self.import_text_action.triggered.connect(lambda _checked=False: self.import_requested.emit())
        self.import_files_action.triggered.connect(lambda _checked=False: self.import_files_requested.emit())
        self.edit_btn.clicked.connect(lambda: self._emit_for_selected(self.edit_requested))
        self.delete_btn.clicked.connect(lambda: self._emit_for_selected(self.delete_requested))
        self.ping_btn.clicked.connect(lambda: self._emit_for_selected(self.ping_requested))
        self.ping_all_btn.clicked.connect(self.ping_all_requested)
        self.sort_ping_btn.clicked.connect(self.sort_latency_requested)
        self.failover_btn.clicked.connect(lambda: self._emit_for_selected(self.failover_group_requested))
        self.create_failover_btn.clicked.connect(lambda: self._emit_for_selected(self.failover_group_requested))
        self.start_group_btn.clicked.connect(lambda: self._emit_for_selected_group(self.smart_group_start_requested))
        self.edit_group_btn.clicked.connect(lambda: self._emit_for_selected_group(self.smart_group_edit_requested))
        self.validate_btn.clicked.connect(self.validate_requested)

    def set_profiles(
        self,
        profiles: list[VlessProfile],
        active_id: str | None,
        subscriptions: list[Subscription] | None = None,
        quality_stats: dict[str, ServerQualityStats] | None = None,
        smart_groups: list[SmartGroup] | None = None,
        smart_connect_enabled: bool | None = None,
    ) -> None:
        self._profiles = list(profiles)
        self._profile_by_id = {profile.id: profile for profile in self._profiles}
        if quality_stats is not None:
            self._quality_stats = dict(quality_stats)
        if smart_groups is not None:
            self._smart_groups = list(smart_groups)
        if smart_connect_enabled is not None:
            self._smart_connect_enabled = bool(smart_connect_enabled)
        if subscriptions is not None:
            self._subscription_names = {subscription.id: subscription.name for subscription in subscriptions}
        self._active_id = active_id
        self._refresh_smart_panel()
        self.reload()

    def set_quality_stats(self, quality_stats: dict[str, ServerQualityStats]) -> None:
        self._quality_stats = dict(quality_stats)
        self._refresh_smart_panel()
        self._refresh_quality_panel()

    def _refresh_quality_panel(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self._set_empty_quality_panel("Сервер не выбран")
            return

        stats = self._quality_stats.get(profile.id)
        self.quality_server_label.setText(f"{profile.name} · {profile.address}:{profile.port}")
        if not stats:
            self.quality_success_label.setText("Success: —")
            style_badge_label(self.quality_success_label, "muted")
            self.quality_latency_label.setText("Latency: —")
            self.quality_failures_label.setText("Ошибки: —")
            self.quality_checked_label.setText("Проверка: —")
            self.quality_usage_label.setText("Использование: —")
            self._set_empty_quality_history_row("История качества пока пуста")
            return

        success_percent = int(stats.success_rate * 100)
        recent_percent = int(stats.recent_success_rate * 100)
        self.quality_success_label.setText(f"Success: {success_percent}% · recent {recent_percent}%")
        if stats.consecutive_failures >= 2 or recent_percent < SERVER_QUALITY_OK_PERCENT:
            style_badge_label(self.quality_success_label, "danger")
        elif recent_percent < SERVER_QUALITY_GOOD_PERCENT:
            style_badge_label(self.quality_success_label, "warning")
        else:
            style_badge_label(self.quality_success_label, "success")

        self.quality_latency_label.setText(
            "Latency: "
            f"last {self._latency_value_label(stats.last_latency_ms)} · "
            f"avg {self._latency_value_label(stats.recent_average_latency_ms)} · "
            f"ewma {self._latency_value_label(int(stats.latency_ewma_ms) if stats.latency_ewma_ms is not None else None)}"
        )
        cooldown = f" · cooldown до {self._short_timestamp(stats.cooldown_until)}" if stats.cooldown_until else ""
        self.quality_failures_label.setText(
            f"Ошибки: {stats.failure_count} · подряд {stats.consecutive_failures}{cooldown}"
        )
        self.quality_checked_label.setText(f"Проверка: {self._short_timestamp(stats.last_checked_at)}")
        total_bytes = stats.total_download_bytes + stats.total_upload_bytes
        self.quality_usage_label.setText(
            f"Использование: {stats.connection_count} запусков · "
            f"{self._duration_label(stats.total_connected_seconds)} · {self._bytes_label(total_bytes)}"
        )
        self._refresh_quality_history_table(stats)

    def _selected_profile(self) -> VlessProfile | None:
        selected = self.selected_id()
        if selected:
            return self._profile_by_id.get(selected)
        return None

    def _set_empty_quality_panel(self, message: str) -> None:
        self.quality_server_label.setText(message)
        self.quality_success_label.setText("Success: —")
        style_badge_label(self.quality_success_label, "muted")
        self.quality_latency_label.setText("Latency: —")
        self.quality_failures_label.setText("Ошибки: —")
        self.quality_checked_label.setText("Проверка: —")
        self.quality_usage_label.setText("Использование: —")
        self._set_empty_quality_history_row("Нет выбранного сервера")

    def _refresh_quality_history_table(self, stats: ServerQualityStats) -> None:
        events = list(reversed(stats.history[-12:]))
        self.quality_history_table.clearContents()
        self.quality_history_table.setRowCount(max(1, len(events)))
        if not events:
            self._set_empty_quality_history_row("История качества пока пуста")
            return
        for row, event in enumerate(events):
            latency = self._latency_value_label(event.latency_ms)
            values = [
                self._short_timestamp(event.timestamp),
                QUALITY_EVENT_LABELS.get(event.event, event.event),
                "OK" if event.success else "FAIL",
                latency,
                event.message or "—",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col in (1, 2, 3):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if event.success:
                    item.setForeground(QColor("#85E89D") if col == 2 else QColor("#F2F2F2"))
                else:
                    item.setForeground(QColor("#FFB4A2") if col in (1, 2, 4) else QColor("#F2F2F2"))
                self.quality_history_table.setItem(row, col, item)
        self.quality_history_table.resizeRowsToContents()

    def _set_empty_quality_history_row(self, message: str) -> None:
        self.quality_history_table.clearContents()
        self.quality_history_table.setRowCount(1)
        values = ["—", "—", "—", "—", message]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setForeground(QColor(150, 150, 150))
            if col in (1, 2, 3):
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.quality_history_table.setItem(0, col, item)

    @staticmethod
    def _latency_value_label(value: int | None) -> str:
        return f"{int(value)} ms" if value is not None else "—"

    def _refresh_smart_panel(self) -> None:
        enabled_text = "включен" if self._smart_connect_enabled else "выключен"
        active_groups = [group for group in self._smart_groups if group.enabled]
        self.smart_status_label.setText(f"Smart Connect: {enabled_text}")
        style_badge_label(self.smart_status_label, "success" if self._smart_connect_enabled else "danger")
        advanced_count = sum(
            1
            for group in self._smart_groups
            if group.mode in {SMART_GROUP_MODE_MULTI_HOP, SMART_GROUP_MODE_LOAD_BALANCE}
        )
        self.smart_summary_label.setText(f"Группы: {len(active_groups)}/{len(self._smart_groups)} · advanced: {advanced_count}")
        style_badge_label(self.smart_summary_label, "accent" if active_groups else "muted")
        self.smart_groups_table.setRowCount(max(1, len(self._smart_groups)))
        if not self._smart_groups:
            self._set_empty_smart_group_row()
            return
        for row, group in enumerate(self._smart_groups):
            members = self._group_member_profiles(group)
            values = [
                group.name,
                SMART_GROUP_MODE_LABELS.get(group.mode, group.mode),
                SMART_STRATEGY_LABELS.get(group.strategy, group.strategy),
                str(len(members)),
                "Включена" if group.enabled else "Отключена",
                self._short_timestamp(group.updated_at),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, group.id)
                item.setToolTip(self._smart_group_tooltip(group, members))
                if col in (1, 2, 3, 4, 5):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if not group.enabled:
                    item.setForeground(QColor(150, 150, 150))
                elif self._active_id and self._active_id in group.profile_ids:
                    item.setForeground(QColor(130, 200, 255))
                elif col == 3:
                    item.setForeground(QColor("#85E89D"))
                self.smart_groups_table.setItem(row, col, item)
        self.smart_groups_table.resizeRowsToContents()

    def _set_empty_smart_group_row(self) -> None:
        self.smart_groups_table.clearContents()
        values = ["Группы еще не созданы", "—", "—", "0", "—", "—"]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setForeground(QColor(150, 150, 150))
            if col:
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.smart_groups_table.setItem(0, col, item)

    def _group_member_profiles(self, group: SmartGroup) -> list[VlessProfile]:
        members = [self._profile_by_id[profile_id] for profile_id in group.profile_ids if profile_id in self._profile_by_id]
        if members:
            return members
        subscription_id = str(group.subscription_id or "").strip()
        source_group = " ".join(str(group.source_group or "").split())
        return [
            profile
            for profile in self._profiles
            if (not subscription_id or profile.subscription_id == subscription_id)
            and (not source_group or " ".join(str(profile.group or "").split()) == source_group)
        ]

    def _smart_group_tooltip(self, group: SmartGroup, members: list[VlessProfile]) -> str:
        lines = [
            group.name,
            f"Стратегия: {SMART_STRATEGY_LABELS.get(group.strategy, group.strategy)}",
            f"Режим: {SMART_GROUP_MODE_LABELS.get(group.mode, group.mode)}",
            f"Статус: {'включена' if group.enabled else 'отключена'}",
        ]
        if group.mode == SMART_GROUP_MODE_LOAD_BALANCE:
            lines.append(
                f"Load Balance: interval {group.load_balance_interval}, tolerance {group.load_balance_tolerance_ms} ms"
            )
        if group.usage_connection_count:
            total_bytes = group.usage_total_download_bytes + group.usage_total_upload_bytes
            lines.append(
                f"Использование: {group.usage_connection_count} запусков, {self._duration_label(group.usage_total_seconds)}, "
                f"{self._bytes_label(total_bytes)}"
            )
        if group.subscription_id:
            subscription = self._subscription_names.get(group.subscription_id, group.subscription_id)
            lines.append(f"Подписка: {subscription}")
        if group.source_group:
            lines.append(f"Группа: {group.source_group}")
        if members:
            lines.append("Серверы:")
            for profile in members[:8]:
                latency = f" · {profile.latency_ms} ms" if profile.latency_ms is not None else ""
                lines.append(f"  {profile.name}{latency}")
            if len(members) > 8:
                lines.append(f"  еще {len(members) - 8}")
        return "\n".join(lines)

    @staticmethod
    def _short_timestamp(value: str | None) -> str:
        text = str(value or "").strip()
        if not text:
            return "—"
        return text.replace("T", " ")[:19]

    def set_active_id(self, active_id: str | None) -> None:
        if self._active_id == active_id:
            return
        previous_id = self._active_id
        self._active_id = active_id
        self._update_active_row(previous_id)
        self._update_active_row(active_id)
        self._refresh_smart_panel()
        self._refresh_quality_panel()

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._row_entries):
            entry_type, entry_id = self._row_entries[row]
            if entry_type == "profile":
                return entry_id
        return None

    def selected_smart_group_id(self) -> str | None:
        return self._selected_smart_group_id()

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
        self._refresh_quality_panel()

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
            f"  Использование: {stats.connection_count} запусков",
            f"  Время подключения: {ServersPage._duration_label(stats.total_connected_seconds)}",
            f"  Трафик: {ServersPage._bytes_label(stats.total_download_bytes + stats.total_upload_bytes)}",
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

    def _selected_smart_group_id(self) -> str | None:
        row = self.smart_groups_table.currentRow()
        if row < 0:
            return None
        item = self.smart_groups_table.item(row, 0)
        if not item:
            return None
        group_id = str(item.data(Qt.ItemDataRole.UserRole) or "").strip()
        return group_id or None

    def _emit_for_selected_group(self, signal: pyqtSignal) -> None:
        group_id = self._selected_smart_group_id()
        if group_id:
            signal.emit(group_id)

    @staticmethod
    def _duration_label(seconds: int) -> str:
        value = max(0, int(seconds))
        hours, remainder = divmod(value, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours:
            return f"{hours} ч {minutes} мин"
        if minutes:
            return f"{minutes} мин {secs} сек"
        return f"{secs} сек"

    @staticmethod
    def _bytes_label(byte_count: int) -> str:
        value = float(max(0, int(byte_count)))
        units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
        unit = units[0]
        for unit in units:
            if value < 1024 or unit == units[-1]:
                break
            value /= 1024
        return f"{value:.1f} {unit}" if unit != "Б" else f"{int(value)} {unit}"

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
        if self.selected_id() in set(profile_ids):
            self._refresh_quality_panel()

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
