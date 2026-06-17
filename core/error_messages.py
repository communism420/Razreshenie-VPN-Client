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

"""Пользовательские сообщения об ошибках без утечки технических секретов."""

from __future__ import annotations

from dataclasses import dataclass
import re
import traceback
from typing import Any

from core.diagnostics import redact_diagnostics_text


MAX_ERROR_DETAILS = 420


@dataclass(frozen=True, slots=True)
class UserErrorMessage:
    category: str
    summary: str
    details: str = ""

    @property
    def display_text(self) -> str:
        if not self.details:
            return self.summary
        if self.details == self.summary:
            return self.summary
        return f"{self.summary}: {self.details}"


def format_user_error(error: BaseException | str, *, context: str = "") -> UserErrorMessage:
    """Возвращает короткое безопасное сообщение для UI."""
    raw = str(error or "").strip()
    if not raw and isinstance(error, BaseException):
        raw = error.__class__.__name__
    text = sanitize_error_text(raw)
    lowered = text.lower()
    class_name = error.__class__.__name__ if isinstance(error, BaseException) else ""
    category_hint = f"{class_name} {context} {lowered}".lower()
    prefix = f"{context}: " if context else ""

    if _has_any(category_hint, "access is denied", "permission denied", "отказано в доступе", "администратор", "uac"):
        return UserErrorMessage(
            "permission",
            f"{prefix}Недостаточно прав",
            "Запустите приложение от имени администратора и повторите действие.",
        )
    if _has_any(category_hint, "firewall kill switch", "windows firewall", "netfirewall"):
        return UserErrorMessage(
            "firewall",
            f"{prefix}Не удалось применить Firewall Kill Switch",
            text,
        )
    if _has_any(category_hint, "proxy-порт", "proxy port", "address already in use", "already in use", "порт") and _has_any(
        category_hint,
        "занят",
        "already",
        "in use",
    ):
        return UserErrorMessage(
            "port",
            f"{prefix}Локальный proxy-порт занят",
            "Закройте приложение, которое использует этот порт, или измените порт в настройках.",
        )
    if _looks_like_reality_error(category_hint):
        return UserErrorMessage(
            "reality",
            f"{prefix}Некорректные параметры Reality",
            _join_details(
                "Проверьте pbk/publicKey, sid/short_id, SNI и fingerprint в параметрах сервера.",
                _tail(text),
            ),
        )
    if _looks_like_group_error(category_hint):
        return UserErrorMessage(
            "group",
            f"{prefix}Не удалось собрать группу серверов",
            _join_details(
                "Проверьте состав группы, порядок серверов и доступность всех участников.",
                _tail(text),
            ),
        )
    if class_name == "AppUpdateError" or _looks_like_app_update_error(category_hint):
        return UserErrorMessage(
            "update",
            f"{prefix}Не удалось обновить приложение",
            _join_details(
                "Проверьте доступ к GitHub Releases, скачанный файл и checksum обновления.",
                _tail(text),
            ),
        )
    if _has_any(category_hint, "sing-box отклонил конфигурацию", "invalid config", "config"):
        return UserErrorMessage(
            "config",
            f"{prefix}sing-box отклонил конфигурацию",
            _tail(text),
        )
    if _has_any(category_hint, "wintun", "tun", "adapter", "route already exists", "другого vpn", "маршрут уже"):
        return UserErrorMessage(
            "tun",
            f"{prefix}Не удалось поднять TUN",
            _join_details(
                "Проверьте права администратора, закройте другие VPN-клиенты и попробуйте ещё раз.",
                _tail(text),
            ),
        )
    if _has_any(
        category_hint,
        "timeout",
        "timed out",
        "connection refused",
        "connection reset",
        "no route",
        "getaddrinfo",
        "dns",
        "resolve",
        "сервер недоступен",
        "проверка выхода",
        "clash api delay",
    ):
        return UserErrorMessage(
            "connectivity",
            f"{prefix}Нет устойчивого соединения с сервером",
            _tail(text),
        )
    if class_name == "SubscriptionError" or _has_any(category_hint, "подписк", "subscription"):
        return UserErrorMessage(
            "subscription",
            f"{prefix}Не удалось обработать подписку",
            _tail(text),
        )
    if class_name == "RulesImportError" or _has_any(category_hint, "ruleset", "rule-set", "правил маршрутизации"):
        return UserErrorMessage(
            "routing",
            f"{prefix}Не удалось обработать правила маршрутизации",
            _tail(text),
        )
    if _has_any(category_hint, "json", "decode"):
        return UserErrorMessage(
            "json",
            f"{prefix}Некорректный JSON",
            _tail(text),
        )
    if isinstance(error, (FileNotFoundError, IsADirectoryError, NotADirectoryError, OSError)):
        return UserErrorMessage(
            "file",
            f"{prefix}Не удалось прочитать или записать файл",
            _tail(text),
        )
    return UserErrorMessage(
        "unknown",
        f"{prefix}Непредвиденная ошибка. Подробности сохранены в логах.",
        "",
    )


def sanitize_error_text(text: Any) -> str:
    """Редактирует секреты и сжимает ошибку до безопасной однострочной формы."""
    value = redact_diagnostics_text(str(text or ""))
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) <= MAX_ERROR_DETAILS:
        return value
    return value[: MAX_ERROR_DETAILS - 1].rstrip() + "…"


def format_safe_traceback(error: BaseException) -> str:
    """Форматирует traceback без raw URI/password/token в логах приложения."""
    formatted = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    return redact_diagnostics_text(formatted)


def _tail(text: str) -> str:
    if not text:
        return ""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    if not lines:
        return ""
    return sanitize_error_text(" ".join(lines[-2:]))


def _has_any(text: str, *needles: str) -> bool:
    return any(needle.lower() in text for needle in needles)


def _join_details(*parts: str) -> str:
    seen: set[str] = set()
    result: list[str] = []
    for part in parts:
        text = sanitize_error_text(part)
        if text and text not in seen:
            result.append(text)
            seen.add(text)
    return " ".join(result)


def _looks_like_reality_error(text: str) -> bool:
    return (
        "reality" in text
        or "pbk/publickey" in text
        or "pbk/public_key" in text
        or " pbk" in text
        or "public key" in text
        or "publickey" in text
        or "short_id" in text
        or "short id" in text
        or "shortid" in text
        or "sid/short_id" in text
    )


def _looks_like_group_error(text: str) -> bool:
    return _has_any(
        text,
        "multi-hop",
        "multi_hop",
        "load balance",
        "load_balance",
        "group outbound",
        "group-конфигурац",
        "цепочк",
    )


def _looks_like_app_update_error(text: str) -> bool:
    return _has_any(
        text,
        "обновление приложения",
        "обновления приложения",
        "github releases",
        "github release",
        "checksum обновления",
        "checksum release",
        "скачанный файл обновления",
        "файл обновления",
        "замену приложения",
        "sha256 скачанного обновления",
    )
