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

"""Общие GUI-константы, флаги, логотип и форматирование серверов."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFont, QFontDatabase, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import QLabel, QWidget

from models.profile import ServerProfile
from utils import paths


ACCENT = "#0078D4"
DANGER = "#D83B01"
SUCCESS = "#16C60C"
EMOJI_FONT_CANDIDATES = (
    "Segoe UI Emoji",
    "Segoe UI Symbol",
    "Noto Color Emoji",
    "Noto Emoji",
    "Twemoji Mozilla",
    "Apple Color Emoji",
)
REGIONAL_INDICATOR_A = 0x1F1E6
REGIONAL_INDICATOR_Z = 0x1F1FF
FLAG_ICON_SIZE = QSize(24, 18)
PROTOCOL_LABELS = {
    "vless": "VLESS",
    "trojan": "Trojan",
    "vmess": "VMess",
    "hysteria2": "HY2",
    "tuic": "TUIC",
    "shadowsocks": "SS",
    "wireguard": "WG",
}

_EMOJI_FONT_FAMILY: str | None = None
_EMOJI_FONT_FAMILY_LOADED = False
_FLAG_ICON_CACHE: dict[tuple[str, ...], QIcon] = {}


def _is_regional_indicator(char: str) -> bool:
    return REGIONAL_INDICATOR_A <= ord(char) <= REGIONAL_INDICATOR_Z


def _regional_pair_to_country_code(first: str, second: str) -> str:
    return "".join(
        chr(ord(char) - REGIONAL_INDICATOR_A + ord("a"))
        for char in (first, second)
    )


def extract_flag_country_codes(text: str) -> tuple[tuple[str, ...], str]:
    """Извлекает Unicode-флаги стран и возвращает ISO-коды плюс текст без этих пар."""
    source = str(text or "")
    codes: list[str] = []
    clean_chars: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if (
            _is_regional_indicator(char)
            and index + 1 < len(source)
            and _is_regional_indicator(source[index + 1])
        ):
            codes.append(_regional_pair_to_country_code(char, source[index + 1]))
            index += 2
            continue
        clean_chars.append(char)
        index += 1
    clean_text = " ".join("".join(clean_chars).split())
    return tuple(codes), clean_text


def flag_icon_path(country_code: str) -> Path:
    return paths.resource_path("assets", "flags", "4x3", f"{country_code.lower()}.svg")


def flag_icon(country_codes: tuple[str, ...]) -> QIcon | None:
    existing_codes = tuple(
        code.lower()
        for code in country_codes[:3]
        if len(code) == 2 and flag_icon_path(code).exists()
    )
    if not existing_codes:
        return None
    cached = _FLAG_ICON_CACHE.get(existing_codes)
    if cached is not None:
        return cached

    icons = [QIcon(str(flag_icon_path(code))) for code in existing_codes]
    icons = [icon for icon in icons if not icon.isNull()]
    if not icons:
        return None
    if len(icons) == 1:
        _FLAG_ICON_CACHE[existing_codes] = icons[0]
        return icons[0]

    width = FLAG_ICON_SIZE.width() * len(icons) + 2 * (len(icons) - 1)
    height = FLAG_ICON_SIZE.height()
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        x = 0
        for icon in icons:
            painter.drawPixmap(x, 0, icon.pixmap(FLAG_ICON_SIZE))
            x += FLAG_ICON_SIZE.width() + 2
    finally:
        painter.end()
    composite = QIcon(pixmap)
    _FLAG_ICON_CACHE[existing_codes] = composite
    return composite


def server_display_text_and_icon(name: str, fallback: str = "") -> tuple[str, QIcon | None]:
    country_codes, clean_name = extract_flag_country_codes(name)
    display_text = clean_name or str(fallback or name or "").strip() or "Сервер"
    return display_text, flag_icon(country_codes)


def server_label_html(text: str) -> str:
    country_codes, clean_text = extract_flag_country_codes(text)
    icon_paths = [flag_icon_path(code) for code in country_codes[:3] if flag_icon_path(code).exists()]
    if not icon_paths:
        return text
    escaped_text = (
        clean_text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    images = " ".join(
        f'<img src="{path.resolve().as_uri().replace("&", "&amp;")}" width="24" height="18">'
        for path in icon_paths
    )
    return f"{images} {escaped_text}".strip()


def protocol_label(profile: ServerProfile) -> str:
    protocol = str(profile.protocol or "").lower()
    if protocol == "shadowsocks":
        method = str(profile.params.get("method") or "").lower()
        if method.startswith("2022-"):
            return "SS2022"
    return PROTOCOL_LABELS.get(protocol, protocol.upper() or "—")


def emoji_font_family() -> str | None:
    global _EMOJI_FONT_FAMILY, _EMOJI_FONT_FAMILY_LOADED
    if _EMOJI_FONT_FAMILY_LOADED:
        return _EMOJI_FONT_FAMILY
    available = set(QFontDatabase.families())
    _EMOJI_FONT_FAMILY = next((family for family in EMOJI_FONT_CANDIDATES if family in available), None)
    _EMOJI_FONT_FAMILY_LOADED = True
    return _EMOJI_FONT_FAMILY


def install_emoji_font_fallbacks() -> None:
    emoji_family = emoji_font_family()
    if not emoji_family:
        return
    for base_family in ("Segoe UI", "Microsoft YaHei UI", "Microsoft YaHei", "Arial", "Sans Serif"):
        QFont.insertSubstitutions(base_family, [emoji_family])


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
