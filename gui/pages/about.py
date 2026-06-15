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

"""Страница информации о приложении."""

from __future__ import annotations

import webbrowser

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    PrimaryPushButton,
    PushButton,
    StrongBodyLabel,
    SubtitleLabel,
)

from gui.common import ACCENT, create_logo_label
from utils.version import (
    APP_NAME,
    APP_REPOSITORY,
    APP_VERSION,
    FLAG_ICONS_REPOSITORY,
    RUSSIA_MOBILE_WHITELIST_REPOSITORY,
    ZAPRET_KVN_REPOSITORY,
)

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
