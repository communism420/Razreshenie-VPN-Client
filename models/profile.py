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

"""Модели профилей подключений."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class VlessProfile:
    """Профиль сервера, импортированный из ключа, JSON outbound или подписки.

    Историческое имя класса сохранено для совместимости с уже существующим
    кодом и JSON-файлами пользователей. Поле ``protocol`` определяет реальный
    тип outbound: vless, trojan, vmess, hysteria2, tuic, shadowsocks или wireguard.
    """

    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = "Новый профиль"
    protocol: str = "vless"
    address: str = ""
    port: int = 443
    uuid: str = ""
    raw_url: str = ""
    params: dict[str, str] = field(default_factory=dict)
    subscription_id: str | None = None
    group: str | None = None
    tags: list[str] = field(default_factory=list)
    source_name: str | None = None
    latency_ms: int | None = None
    latency_checked_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VlessProfile":
        safe = dict(data)
        safe["protocol"] = str(safe.get("protocol") or "vless").strip().lower()
        safe["port"] = int(safe.get("port") or 443)
        if safe.get("latency_ms") is not None:
            safe["latency_ms"] = int(safe["latency_ms"])
        safe["uuid"] = str(safe.get("uuid") or "")
        safe["params"] = {
            str(key): "" if value is None else str(value)
            for key, value in dict(safe.get("params") or {}).items()
        }
        safe["group"] = str(safe.get("group") or "").strip() or None
        safe["source_name"] = str(safe.get("source_name") or "").strip() or None
        tags = safe.get("tags") or []
        if isinstance(tags, str):
            tags = [item.strip() for item in tags.split(",") if item.strip()]
        safe["tags"] = [str(item).strip() for item in tags if str(item).strip()]
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def label(self) -> str:
        host = f"{self.address}:{self.port}" if self.address else "без адреса"
        return f"{self.name}  ·  {host}"

    def touch(self) -> None:
        self.updated_at = utc_now_iso()


ServerProfile = VlessProfile


@dataclass(slots=True)
class Subscription:
    """Источник подписки с множеством серверных профилей."""

    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = "Подписка"
    url: str = ""
    update_interval_hours: int = 24
    enabled: bool = True
    last_update_at: str | None = None
    last_error: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    last_content_hash: str | None = None
    last_cached_at: str | None = None
    profile_count: int = 0
    created_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subscription":
        safe = dict(data)
        safe["update_interval_hours"] = int(safe.get("update_interval_hours") or 24)
        safe["profile_count"] = int(safe.get("profile_count") or 0)
        safe["enabled"] = bool(safe.get("enabled", True))
        for key in ("etag", "last_modified", "last_content_hash", "last_cached_at"):
            safe[key] = str(safe.get(key) or "").strip() or None
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
