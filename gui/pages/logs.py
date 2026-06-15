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

"""Страница просмотра логов."""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import PlainTextEdit, PrimaryPushButton, PushButton, SearchLineEdit, SubtitleLabel

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
