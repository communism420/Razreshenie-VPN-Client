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

"""Импорт и разбор VLESS URI."""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlparse
from uuid import UUID

from models.profile import VlessProfile


class VlessParseError(ValueError):
    """Ошибка пользовательского VLESS-ключа."""


def _validate_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise VlessParseError("Некорректный UUID в VLESS-ключе") from exc


def _decode_karing_component(value: str) -> str:
    """Повторяет Karing-style decode: URI component decode, без замены '+' на пробел."""
    name = unquote(value).strip()
    return " ".join(name.split())


def get_karing_server_name(uri: str) -> str:
    """Возвращает имя сервера тем же приоритетом, что Karing: fragment -> remarks -> name -> host."""
    parsed = urlparse(uri.strip())
    params: dict[str, str] = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        params[unquote(key)] = unquote(value)

    remarks = ""
    if parsed.fragment:
        remarks = parsed.fragment
    elif params.get("remarks"):
        remarks = params["remarks"]
    elif params.get("name"):
        remarks = params["name"]

    if remarks:
        decoded = _decode_karing_component(remarks)
        if decoded:
            return decoded
    return parsed.hostname or ""


def parse_vless_uri(uri: str, subscription_id: str | None = None) -> VlessProfile:
    raw = uri.strip()
    if not raw.startswith("vless://"):
        raise VlessParseError("Ключ должен начинаться с vless://")

    parsed = urlparse(raw)
    if parsed.scheme != "vless":
        raise VlessParseError("Поддерживается только схема vless://")
    if not parsed.username:
        raise VlessParseError("В VLESS-ключе отсутствует UUID")
    if not parsed.hostname:
        raise VlessParseError("В VLESS-ключе отсутствует адрес сервера")

    params: dict[str, str] = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        params[unquote(key)] = unquote(value)

    try:
        port = int(parsed.port or 443)
    except ValueError as exc:
        raise VlessParseError("Некорректный порт в VLESS-ключе") from exc

    name = get_karing_server_name(raw) or parsed.hostname
    return VlessProfile(
        name=name or parsed.hostname,
        address=parsed.hostname,
        port=port,
        uuid=_validate_uuid(unquote(parsed.username)),
        raw_url=raw,
        params=params,
        subscription_id=subscription_id,
    )
