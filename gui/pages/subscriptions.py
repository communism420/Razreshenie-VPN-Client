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

"""Страница управления подписками."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import FluentIcon as FIF, PrimaryPushButton, PushButton, SubtitleLabel, TableWidget

from models.profile import Subscription

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
