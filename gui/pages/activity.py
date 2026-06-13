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

"""Страница Live Activity с доменами из runtime-логов sing-box."""

from __future__ import annotations

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QProgressBar,
    QTableView,
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
)

from core.domain_activity import (
    DOMAIN_ACTIVITY_RULE_FILTER_ALL,
    DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT,
    DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT,
    DOMAIN_ACTIVITY_RULE_FILTER_MATCHED,
    DOMAIN_ACTIVITY_SORT_DOMAIN,
    DOMAIN_ACTIVITY_SORT_FIRST_SEEN,
    DOMAIN_ACTIVITY_SORT_HITS,
    DOMAIN_ACTIVITY_SORT_LAST_SEEN,
    DOMAIN_ACTIVITY_SORT_RULE,
    DomainActivityEntry,
    DomainActivitySummary,
    summarize_domain_activity,
)
from models.rules import ROUTE_OUTBOUND_DIRECT, ROUTE_OUTBOUND_PROXY, normalize_outbound


ACTIVITY_ACTION_PROXY_COLUMN = 7
ACTIVITY_ACTION_DIRECT_COLUMN = 8
ACTIVITY_COLUMNS = (
    "Домен / поддомен",
    "Маршрут",
    "Правило",
    "Запросов",
    "Доля",
    "Первый раз",
    "Последний раз",
    "VPN",
    "Direct",
)


class DomainActivityTableModel(QAbstractTableModel):
    """Легкая модель активности доменов без создания QWidget-элементов на каждую строку."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[str, str, str, str, str, str, str, str, str]] = []
        self._routes: list[str] = []
        self._entries: list[DomainActivityEntry] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(ACTIVITY_COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid():
            return None
        row = index.row()
        column = index.column()
        if row < 0 or row >= len(self._rows) or column < 0 or column >= len(ACTIVITY_COLUMNS):
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._rows[row][column]
        if role == Qt.ItemDataRole.ToolTipRole:
            entry = self._entries[row]
            if column == ACTIVITY_ACTION_PROXY_COLUMN:
                return f"Добавить домен {entry.domain} в правила через VPN"
            if column == ACTIVITY_ACTION_DIRECT_COLUMN:
                return f"Добавить домен {entry.domain} в правила напрямую"
            return f"{entry.domain}\n{entry.rule_name}\n{entry.hits} событий"
        if role == Qt.ItemDataRole.ForegroundRole:
            route = self._routes[row]
            if column == ACTIVITY_ACTION_PROXY_COLUMN:
                return QBrush(QColor(0, 180, 255))
            if column == ACTIVITY_ACTION_DIRECT_COLUMN:
                return QBrush(QColor(0, 220, 120))
            if route == ROUTE_OUTBOUND_PROXY:
                return QBrush(QColor(0, 180, 255))
            if route == ROUTE_OUTBOUND_DIRECT:
                return QBrush(QColor(0, 220, 120))
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in (0, 2):
                return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
            return Qt.AlignmentFlag.AlignCenter
        return None

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(ACTIVITY_COLUMNS):
            return ACTIVITY_COLUMNS[section]
        return None

    def set_entries(self, entries: list[DomainActivityEntry]) -> bool:
        total_hits = sum(max(0, int(entry.hits)) for entry in entries)
        rows = [
            (
                entry.domain,
                entry.route_label,
                entry.rule_name,
                str(entry.hits),
                self._share_label(entry.hits, total_hits),
                entry.first_seen_label,
                entry.last_seen_label,
                "VPN",
                "Direct",
            )
            for entry in entries
        ]
        routes = [entry.route for entry in entries]
        if rows == self._rows and routes == self._routes:
            self._entries = list(entries)
            return False

        self.beginResetModel()
        self._rows = rows
        self._routes = routes
        self._entries = list(entries)
        self.endResetModel()
        return True

    def entry_at(self, row: int) -> DomainActivityEntry | None:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    @staticmethod
    def _share_label(hits: int, total_hits: int) -> str:
        if total_hits <= 0:
            return "0%"
        return f"{round((max(0, int(hits)) / total_hits) * 100)}%"


class DomainActivityPage(QWidget):
    filters_changed = pyqtSignal()
    route_rule_requested = pyqtSignal(str, str, str)
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

        summary_grid = QGridLayout()
        summary_grid.setHorizontalSpacing(10)
        summary_grid.setVerticalSpacing(10)
        self.total_value, self.total_caption = self._create_summary_card(
            summary_grid,
            0,
            0,
            "Всего",
            "0",
            "доменов",
        )
        self.vpn_value, self.vpn_caption = self._create_summary_card(
            summary_grid,
            0,
            1,
            "Через VPN",
            "0",
            "событий",
        )
        self.direct_value, self.direct_caption = self._create_summary_card(
            summary_grid,
            0,
            2,
            "Напрямую",
            "0",
            "событий",
        )
        self.share_card = CardWidget(self)
        share_layout = QVBoxLayout(self.share_card)
        share_layout.setContentsMargins(14, 10, 14, 10)
        share_layout.setSpacing(4)
        share_layout.addWidget(StrongBodyLabel("VPN-доля", self.share_card))
        self.vpn_share_value = BodyLabel("0%", self.share_card)
        self.vpn_share_caption = CaptionLabel("по событиям Live Activity", self.share_card)
        self.vpn_share_bar = QProgressBar(self.share_card)
        self.vpn_share_bar.setRange(0, 100)
        self.vpn_share_bar.setTextVisible(False)
        self.vpn_share_bar.setFixedHeight(6)
        share_layout.addWidget(self.vpn_share_value)
        share_layout.addWidget(self.vpn_share_bar)
        share_layout.addWidget(self.vpn_share_caption)
        summary_grid.addWidget(self.share_card, 0, 3)
        for column in range(4):
            summary_grid.setColumnStretch(column, 1)
        root.addLayout(summary_grid)

        toolbar = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Поиск: домен, правило, маршрут")
        self.route_combo = ComboBox(self)
        self.route_combo.addItem("Все маршруты", userData="all")
        self.route_combo.addItem("Через VPN", userData=ROUTE_OUTBOUND_PROXY)
        self.route_combo.addItem("Напрямую", userData=ROUTE_OUTBOUND_DIRECT)
        self.rule_filter_combo = ComboBox(self)
        self.rule_filter_combo.addItem("Все правила", userData=DOMAIN_ACTIVITY_RULE_FILTER_ALL)
        self.rule_filter_combo.addItem("Сработало правило", userData=DOMAIN_ACTIVITY_RULE_FILTER_MATCHED)
        self.rule_filter_combo.addItem("По умолчанию", userData=DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT)
        self.rule_filter_combo.addItem("Из sing-box", userData=DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT)
        self.sort_combo = ComboBox(self)
        self.sort_combo.addItem("Новые", userData=DOMAIN_ACTIVITY_SORT_LAST_SEEN)
        self.sort_combo.addItem("Больше запросов", userData=DOMAIN_ACTIVITY_SORT_HITS)
        self.sort_combo.addItem("Домен", userData=DOMAIN_ACTIVITY_SORT_DOMAIN)
        self.sort_combo.addItem("Правило", userData=DOMAIN_ACTIVITY_SORT_RULE)
        self.sort_combo.addItem("Первый раз", userData=DOMAIN_ACTIVITY_SORT_FIRST_SEEN)
        self.rule_match_combo = ComboBox(self)
        self.rule_match_combo.addItem("Домен", userData="domain")
        self.rule_match_combo.addItem("Зона", userData="domain_suffix")
        self.rule_outbound_combo = ComboBox(self)
        self.rule_outbound_combo.addItem("Напрямую", userData=ROUTE_OUTBOUND_DIRECT)
        self.rule_outbound_combo.addItem("Через VPN", userData=ROUTE_OUTBOUND_PROXY)
        self.create_rule_btn = PrimaryPushButton(FIF.ADD, "В правило", self)
        self.create_rule_btn.setEnabled(False)
        self.clear_btn = PushButton(FIF.DELETE, "Очистить", self)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.route_combo)
        toolbar.addWidget(self.rule_filter_combo)
        toolbar.addWidget(self.sort_combo)
        toolbar.addWidget(self.rule_match_combo)
        toolbar.addWidget(self.rule_outbound_combo)
        toolbar.addWidget(self.create_rule_btn)
        toolbar.addWidget(self.clear_btn)
        root.addLayout(toolbar)

        self.activity_model = DomainActivityTableModel(self)
        self.table = QTableView(self)
        self.table.setModel(self.activity_model)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col in (1, 3, 4, 5, 6, 7, 8):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        root.addWidget(self.table, 1)

        self.search.textChanged.connect(lambda _text: self.filters_changed.emit())
        self.route_combo.currentIndexChanged.connect(lambda _index: self.filters_changed.emit())
        self.rule_filter_combo.currentIndexChanged.connect(lambda _index: self.filters_changed.emit())
        self.sort_combo.currentIndexChanged.connect(lambda _index: self.filters_changed.emit())
        self.create_rule_btn.clicked.connect(self._emit_selected_route_rule)
        self.table.clicked.connect(self._handle_table_click)
        self.table.doubleClicked.connect(self._handle_table_double_click)
        self.table.customContextMenuRequested.connect(self._open_context_menu)
        self.table.selectionModel().selectionChanged.connect(lambda _selected, _deselected: self._sync_actions())
        self.clear_btn.clicked.connect(self.clear_requested)

    def _create_summary_card(
        self,
        grid: QGridLayout,
        row: int,
        column: int,
        title: str,
        value: str,
        caption: str,
    ) -> tuple[BodyLabel, CaptionLabel]:
        card = CardWidget(self)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)
        layout.addWidget(StrongBodyLabel(title, card))
        value_label = BodyLabel(value, card)
        caption_label = CaptionLabel(caption, card)
        layout.addWidget(value_label)
        layout.addWidget(caption_label)
        grid.addWidget(card, row, column)
        return value_label, caption_label

    def query(self) -> str:
        return self.search.text().strip()

    def route_filter(self) -> str:
        return str(self.route_combo.currentData() or "all")

    def rule_filter(self) -> str:
        return str(self.rule_filter_combo.currentData() or DOMAIN_ACTIVITY_RULE_FILTER_ALL)

    def sort_mode(self) -> str:
        return str(self.sort_combo.currentData() or DOMAIN_ACTIVITY_SORT_LAST_SEEN)

    def set_entries(self, entries: list[DomainActivityEntry]) -> None:
        self._set_summary(summarize_domain_activity(entries))
        scroll_bar = self.table.verticalScrollBar()
        previous_scroll = scroll_bar.value()
        changed = self.activity_model.set_entries(entries)
        if changed and previous_scroll > 0:
            QTimer.singleShot(
                0,
                lambda value=previous_scroll: self.table.verticalScrollBar().setValue(
                    min(value, self.table.verticalScrollBar().maximum())
                ),
            )
        self._sync_actions()

    def selected_entry(self) -> DomainActivityEntry | None:
        index = self.table.currentIndex()
        if not index.isValid():
            selected_rows = self.table.selectionModel().selectedRows()
            if selected_rows:
                index = selected_rows[0]
        if not index.isValid():
            return None
        return self.activity_model.entry_at(index.row())

    def _sync_actions(self) -> None:
        self.create_rule_btn.setEnabled(self.selected_entry() is not None)

    def _set_summary(self, summary: DomainActivitySummary) -> None:
        self.total_value.setText(str(summary.total_domains))
        self.total_caption.setText(f"событий: {summary.total_hits}")
        self.vpn_value.setText(str(summary.proxy_domains))
        self.vpn_caption.setText(f"событий: {summary.proxy_hits}")
        self.direct_value.setText(str(summary.direct_domains))
        self.direct_caption.setText(f"событий: {summary.direct_hits}")
        self.vpn_share_value.setText(f"{summary.proxy_hit_percent}%")
        self.vpn_share_bar.setValue(summary.proxy_hit_percent)
        self.vpn_share_caption.setText(
            f"VPN {summary.proxy_hits} / direct {summary.direct_hits} событий"
            if summary.total_hits
            else "по событиям Live Activity"
        )

    def _handle_table_click(self, index: QModelIndex) -> None:
        if not index.isValid() or index.column() not in {ACTIVITY_ACTION_PROXY_COLUMN, ACTIVITY_ACTION_DIRECT_COLUMN}:
            return
        entry = self.activity_model.entry_at(index.row())
        if not entry:
            return
        outbound = ROUTE_OUTBOUND_PROXY if index.column() == ACTIVITY_ACTION_PROXY_COLUMN else ROUTE_OUTBOUND_DIRECT
        self._emit_route_rule(entry.domain, "domain", outbound)

    def _handle_table_double_click(self, index: QModelIndex) -> None:
        if index.isValid() and index.column() in {ACTIVITY_ACTION_PROXY_COLUMN, ACTIVITY_ACTION_DIRECT_COLUMN}:
            return
        self._emit_selected_route_rule()

    def _emit_selected_route_rule(self) -> None:
        entry = self.selected_entry()
        if not entry:
            return
        self._emit_route_rule(entry.domain, self._rule_match_kind(), self._rule_outbound())

    def _emit_route_rule(self, domain: str, match_kind: str, outbound: str) -> None:
        self.route_rule_requested.emit(domain, match_kind, normalize_outbound(outbound))

    def _rule_match_kind(self) -> str:
        value = str(self.rule_match_combo.currentData() or "domain")
        return "domain_suffix" if value == "domain_suffix" else "domain"

    def _rule_outbound(self) -> str:
        return normalize_outbound(str(self.rule_outbound_combo.currentData() or ROUTE_OUTBOUND_DIRECT))

    def _entry_at_point(self, point) -> DomainActivityEntry | None:
        index = self.table.indexAt(point)
        if not index.isValid():
            return None
        self.table.selectRow(index.row())
        return self.activity_model.entry_at(index.row())

    def _open_context_menu(self, point) -> None:
        entry = self._entry_at_point(point)
        if not entry:
            return
        menu = QMenu(self)
        direct_domain = menu.addAction("Напрямую: домен")
        proxy_domain = menu.addAction("Через VPN: домен")
        menu.addSeparator()
        direct_suffix = menu.addAction("Напрямую: зона")
        proxy_suffix = menu.addAction("Через VPN: зона")
        menu.addSeparator()
        copy_domain = menu.addAction("Копировать домен")

        direct_domain.triggered.connect(lambda _checked=False, domain=entry.domain: self._emit_route_rule(domain, "domain", ROUTE_OUTBOUND_DIRECT))
        proxy_domain.triggered.connect(lambda _checked=False, domain=entry.domain: self._emit_route_rule(domain, "domain", ROUTE_OUTBOUND_PROXY))
        direct_suffix.triggered.connect(lambda _checked=False, domain=entry.domain: self._emit_route_rule(domain, "domain_suffix", ROUTE_OUTBOUND_DIRECT))
        proxy_suffix.triggered.connect(lambda _checked=False, domain=entry.domain: self._emit_route_rule(domain, "domain_suffix", ROUTE_OUTBOUND_PROXY))
        copy_domain.triggered.connect(lambda _checked=False, domain=entry.domain: QApplication.clipboard().setText(domain))
        menu.exec(self.table.viewport().mapToGlobal(point))
