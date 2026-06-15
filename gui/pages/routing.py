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

"""Страница правил маршрутизации."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
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
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SearchLineEdit,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
)

from gui.common import apply_card_layout, apply_page_layout, polish_table, polish_toolbar_buttons, style_badge_label
from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    normalize_outbound,
)


ROUTE_LABELS = {
    ROUTE_OUTBOUND_PROXY: "Текущий сервер",
    ROUTE_OUTBOUND_DIRECT: "Напрямую",
}


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
        self._visible_rule_sets: list[RoutingRuleSet] = []
        self._resources: list[RouteRuleSetResource] = []
        self._resource_by_tag: dict[str, RouteRuleSetResource] = {}
        root = QVBoxLayout(self)
        apply_page_layout(root)
        root.addWidget(SubtitleLabel("Маршрутизация", self))
        group = CardWidget(self)
        group_layout = QVBoxLayout(group)
        apply_card_layout(group_layout)

        metrics = QHBoxLayout()
        metrics.setSpacing(8)
        self.total_label = CaptionLabel("Всего: 0", group)
        self.active_label = CaptionLabel("Активных: 0", group)
        self.default_label = CaptionLabel("Остальной трафик: —", group)
        self.resources_label = CaptionLabel("Resources: 0", group)
        for label in (self.total_label, self.active_label, self.default_label, self.resources_label):
            style_badge_label(label, "muted")
            metrics.addWidget(label)
        metrics.addStretch(1)

        filters = QHBoxLayout()
        filters.setSpacing(10)
        self.search = SearchLineEdit(group)
        self.search.setPlaceholderText("Поиск по правилам, SRS, geosite, geoip, процессам")
        self.search.setClearButtonEnabled(True)
        filters.addWidget(self.search, 1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.file_btn = PrimaryPushButton(FIF.FOLDER, "Файл / SRS", group)
        self.url_btn = PushButton(FIF.DOWNLOAD, "URL", group)
        self.app_btn = PushButton(FIF.APPLICATION, "Приложение", group)
        self.up_btn = PushButton(FIF.UP, "Выше", group)
        self.down_btn = PushButton(FIF.DOWN, "Ниже", group)
        self.clear_btn = PushButton(FIF.DELETE, "Очистить", group)
        polish_toolbar_buttons(self.file_btn, self.url_btn, self.app_btn, self.up_btn, self.down_btn, self.clear_btn)
        self.file_btn.setToolTip("Загрузить локальный JSON, TXT или SRS rule-set")
        self.url_btn.setToolTip("Добавить удаленный rule-set по URL")
        self.app_btn.setToolTip("Создать правило для приложения Windows")
        self.up_btn.setToolTip("Поднять выбранное правило выше по приоритету")
        self.down_btn.setToolTip("Опустить выбранное правило ниже по приоритету")
        self.clear_btn.setToolTip("Удалить пользовательские правила маршрутизации")
        buttons.addWidget(self.file_btn)
        buttons.addWidget(self.url_btn)
        buttons.addWidget(self.app_btn)
        buttons.addWidget(self.up_btn)
        buttons.addWidget(self.down_btn)
        buttons.addWidget(self.clear_btn)
        buttons.addStretch(1)
        group_layout.addWidget(StrongBodyLabel("Наборы маршрутизации", group))
        group_layout.addLayout(metrics)
        group_layout.addLayout(filters)
        group_layout.addLayout(buttons)
        root.addWidget(group)

        self.table = TableWidget(self)
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["#", "Приоритет", "Набор", "Туннелирование", "Элементов", "Включен", "Источник", "Действия"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        for col in (0, 1, 3, 4, 5, 7):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        polish_table(self.table, row_height=34)
        root.addWidget(self.table, 4)

        details_row = QHBoxLayout()
        details_row.setSpacing(12)

        resources_card = CardWidget(self)
        resources_layout = QVBoxLayout(resources_card)
        apply_card_layout(resources_layout)
        resources_layout.addWidget(BodyLabel("Rule-set resources", resources_card))
        self.resources_table = TableWidget(resources_card)
        self.resources_table.setColumnCount(4)
        self.resources_table.setHorizontalHeaderLabels(["Tag", "Тип", "Формат", "Источник"])
        self.resources_table.verticalHeader().setVisible(False)
        self.resources_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.resources_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.resources_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.resources_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.resources_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.resources_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.resources_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.resources_table.setMaximumHeight(150)
        polish_table(self.resources_table, row_height=28)
        resources_layout.addWidget(self.resources_table)
        details_row.addWidget(resources_card, 2)

        details_card = CardWidget(self)
        details_layout = QVBoxLayout(details_card)
        apply_card_layout(details_layout)
        details_layout.addWidget(BodyLabel("Детали выбранного правила", details_card))
        self.details = PlainTextEdit(details_card)
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(150)
        details_layout.addWidget(self.details)
        details_row.addWidget(details_card, 3)
        root.addLayout(details_row)

        self.summary = PlainTextEdit(self)
        self.summary.setReadOnly(True)
        self.summary.setMaximumHeight(170)
        root.addWidget(self.summary, 1)
        self.search.textChanged.connect(lambda _text: self._refresh_rule_table(self.selected_id()))
        self.file_btn.clicked.connect(self.load_file_requested)
        self.url_btn.clicked.connect(self.load_url_requested)
        self.app_btn.clicked.connect(self.per_app_rule_requested)
        self.up_btn.clicked.connect(lambda: self._emit_move(-1))
        self.down_btn.clicked.connect(lambda: self._emit_move(1))
        self.clear_btn.clicked.connect(self.clear_rules_requested)
        self.table.itemSelectionChanged.connect(self._refresh_selection_state)
        self._refresh_selection_state()

    def set_rules(self, rules: SplitRules, summary: str) -> None:
        selected_before = self.selected_id()
        self._rule_sets = self._ordered_rule_sets(rules.rule_sets)
        self._resources = list(rules.rule_set_resources)
        self._resource_by_tag = {
            resource.tag: resource
            for resource in rules.rule_set_resources
            if resource.tag
        }
        self._refresh_metrics(rules)
        self._refresh_resources_table()
        self._refresh_rule_table(selected_before)
        self.summary.setPlainText(summary)

    def _refresh_rule_table(self, preferred_id: str | None = None) -> None:
        query = self.search.text().strip().lower()
        self._visible_rule_sets = [
            rule_set
            for rule_set in self._rule_sets
            if self._rule_matches_query(rule_set, query)
        ]
        self._ids = [rule_set.id for rule_set in self._visible_rule_sets]
        self.table.setUpdatesEnabled(False)
        try:
            self.table.clearContents()
            self.table.setRowCount(len(self._visible_rule_sets))
            for row, rule_set in enumerate(self._visible_rule_sets):
                self._set_rule_row(row, rule_set)
        finally:
            self.table.setUpdatesEnabled(True)
        self.table.resizeRowsToContents()
        target_id = preferred_id if preferred_id in self._ids else (self._ids[0] if self._ids else None)
        if target_id:
            self.select_rule(target_id)
        else:
            self.table.clearSelection()
            self._refresh_selection_state()

    def _set_rule_row(self, row: int, rule_set: RoutingRuleSet) -> None:
        values = [
            str(row + 1),
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
            if col in (0, 1, 4):
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if col == 6:
                item.setToolTip(self._source_tooltip(rule_set))
            if not rule_set.enabled:
                item.setForeground(QColor(150, 150, 150))
            elif normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_PROXY:
                item.setForeground(QColor(0, 120, 212))
            else:
                item.setForeground(QColor(0, 150, 90))
            self.table.setItem(row, col, item)
        self.table.setCellWidget(row, 3, self._route_combo(rule_set))
        self.table.setCellWidget(row, 5, self._enabled_switch(rule_set))
        self.table.setCellWidget(row, 7, self._delete_button(rule_set))

    def _refresh_metrics(self, rules: SplitRules) -> None:
        active = len(rules.enabled_rule_sets)
        default_label = ROUTE_LABELS.get(rules.effective_default_outbound, rules.effective_default_outbound)
        usable_resources = len(rules.enabled_rule_set_resources)
        self.total_label.setText(f"Всего: {len(rules.rule_sets)}")
        self.active_label.setText(f"Активных: {active}")
        self.default_label.setText(f"Остальной трафик: {default_label}")
        self.resources_label.setText(f"Resources: {usable_resources}/{len(rules.rule_set_resources)}")
        style_badge_label(self.total_label, "accent" if rules.rule_sets else "muted")
        style_badge_label(self.active_label, "success" if active else "muted")
        style_badge_label(self.default_label, "success" if rules.effective_default_outbound == ROUTE_OUTBOUND_DIRECT else "accent")
        style_badge_label(self.resources_label, "success" if usable_resources else "muted")

    def _refresh_resources_table(self) -> None:
        self.resources_table.setRowCount(max(1, len(self._resources)))
        if not self._resources:
            values = ["Нет resources", "—", "—", "—"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setForeground(QColor(150, 150, 150))
                if col in (1, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.resources_table.setItem(0, col, item)
            return
        for row, resource in enumerate(self._resources):
            values = [
                resource.tag or "—",
                resource.type,
                resource.format,
                resource.url or resource.path or resource.source or "—",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(self._resource_tooltip(resource))
                if col in (1, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if not resource.enabled:
                    item.setForeground(QColor(150, 150, 150))
                elif resource.format == "binary":
                    item.setForeground(QColor(0, 150, 90))
                self.resources_table.setItem(row, col, item)
        self.resources_table.resizeRowsToContents()

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._ids):
            return self._ids[row]
        return None

    def select_rule(self, rule_set_id: str) -> None:
        if rule_set_id in self._ids:
            self.table.selectRow(self._ids.index(rule_set_id))
            self._refresh_selection_state()

    def _refresh_selection_state(self) -> None:
        selected = self.selected_id()
        has_selected = selected is not None
        row = self.table.currentRow()
        self.up_btn.setEnabled(has_selected and row > 0)
        self.down_btn.setEnabled(has_selected and 0 <= row < len(self._ids) - 1)
        self._refresh_details(selected)

    def _refresh_details(self, rule_set_id: str | None) -> None:
        rule_set = next((item for item in self._visible_rule_sets if item.id == rule_set_id), None)
        if rule_set is None:
            self.details.setPlainText("Правило не выбрано.")
            return
        self.details.setPlainText(self._details_text(rule_set))

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

    def _rule_matches_query(self, rule_set: RoutingRuleSet, query: str) -> bool:
        if not query:
            return True
        haystack = " ".join(
            [
                rule_set.name,
                rule_set.outbound_label,
                rule_set.source or "",
                rule_set.source_type or "",
                self._source_label(rule_set),
                self._source_tooltip(rule_set),
                *rule_set.domains,
                *rule_set.domain_suffix,
                *rule_set.domain_keyword,
                *rule_set.domain_regex,
                *[f"geosite:{item}" for item in rule_set.geosite],
                *[f"geoip:{item}" for item in rule_set.geoip],
                *rule_set.ip_cidr,
                *rule_set.process_name,
                *rule_set.process_path,
                *rule_set.process_path_regex,
                *[f"rule_set:{item}" for item in rule_set.rule_set_tags],
            ]
        ).lower()
        return query in haystack

    def _details_text(self, rule_set: RoutingRuleSet) -> str:
        preview = self._rule_preview(rule_set, limit=18)
        lines = [
            f"Набор: {rule_set.name}",
            f"Маршрут: {rule_set.outbound_label}",
            f"Статус: {'включено' if rule_set.enabled else 'отключено'}",
            f"Приоритет: {rule_set.priority}",
            f"Источник: {self._source_label(rule_set)}",
            f"Элементов: {rule_set.total_items}",
        ]
        if rule_set.rule_set_tags:
            lines.append(f"Rule-set tags: {', '.join(rule_set.rule_set_tags)}")
        if rule_set.process_name:
            lines.append(f"Process name: {', '.join(rule_set.process_name[:8])}")
        if rule_set.process_path:
            lines.append(f"Process path: {', '.join(rule_set.process_path[:4])}")
        if rule_set.process_path_regex:
            lines.append(f"Process path regex: {', '.join(rule_set.process_path_regex[:4])}")
        if preview:
            lines.append(f"Первые элементы: {', '.join(preview)}")
        return "\n".join(lines)

    @staticmethod
    def _rule_preview(rule_set: RoutingRuleSet, *, limit: int) -> list[str]:
        return (
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
        )[:limit]

    @staticmethod
    def _resource_tooltip(resource: RouteRuleSetResource) -> str:
        location = resource.url or resource.path or resource.source or "—"
        return "\n".join(
            [
                f"ID: {resource.id}",
                f"Name: {resource.name}",
                f"Tag: {resource.tag or '—'}",
                f"Type: {resource.type}",
                f"Format: {resource.format}",
                f"Enabled: {'yes' if resource.enabled else 'no'}",
                f"Location: {location}",
            ]
        )

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
