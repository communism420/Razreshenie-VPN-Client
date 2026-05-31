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
    """Профиль VLESS, импортированный из ключа или подписки."""

    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = "Новый профиль"
    protocol: str = "vless"
    address: str = ""
    port: int = 443
    uuid: str = ""
    raw_url: str = ""
    params: dict[str, str] = field(default_factory=dict)
    subscription_id: str | None = None
    latency_ms: int | None = None
    latency_checked_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VlessProfile":
        safe = dict(data)
        safe["port"] = int(safe.get("port") or 443)
        if safe.get("latency_ms") is not None:
            safe["latency_ms"] = int(safe["latency_ms"])
        safe["params"] = dict(safe.get("params") or {})
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def label(self) -> str:
        host = f"{self.address}:{self.port}" if self.address else "без адреса"
        return f"{self.name}  ·  {host}"

    def touch(self) -> None:
        self.updated_at = utc_now_iso()


@dataclass(slots=True)
class Subscription:
    """Источник подписки с множеством VLESS-профилей."""

    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = "Подписка"
    url: str = ""
    update_interval_hours: int = 24
    enabled: bool = True
    last_update_at: str | None = None
    last_error: str | None = None
    profile_count: int = 0
    created_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subscription":
        safe = dict(data)
        safe["update_interval_hours"] = int(safe.get("update_interval_hours") or 24)
        safe["profile_count"] = int(safe.get("profile_count") or 0)
        safe["enabled"] = bool(safe.get("enabled", True))
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
