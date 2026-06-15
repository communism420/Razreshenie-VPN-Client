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

"""Модели Smart Connect, failover-групп и статистики качества серверов."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from models.profile import utc_now_iso


SMART_STRATEGY_SMART = "smart"
SMART_STRATEGY_LATENCY = "latency"
SMART_STRATEGY_FAILOVER_ORDER = "failover_order"
SMART_GROUP_STRATEGIES = {
    SMART_STRATEGY_SMART,
    SMART_STRATEGY_LATENCY,
    SMART_STRATEGY_FAILOVER_ORDER,
}
SMART_GROUP_MODE_FAILOVER = "failover"
SMART_GROUP_MODE_MULTI_HOP = "multi_hop"
SMART_GROUP_MODE_LOAD_BALANCE = "load_balance"
SMART_GROUP_MODES = {
    SMART_GROUP_MODE_FAILOVER,
    SMART_GROUP_MODE_MULTI_HOP,
    SMART_GROUP_MODE_LOAD_BALANCE,
}
SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT = "5m"
SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS = 50
SERVER_QUALITY_HISTORY_LIMIT = 50
QUALITY_EVENT_LATENCY = "latency"
QUALITY_EVENT_SUCCESS = "success"
QUALITY_EVENT_FAILURE = "failure"
QUALITY_EVENT_TYPES = {
    QUALITY_EVENT_LATENCY,
    QUALITY_EVENT_SUCCESS,
    QUALITY_EVENT_FAILURE,
}


def normalize_smart_strategy(value: str | None) -> str:
    text = str(value or "").strip().lower()
    return text if text in SMART_GROUP_STRATEGIES else SMART_STRATEGY_SMART


def normalize_smart_group_mode(value: str | None) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "chain": SMART_GROUP_MODE_MULTI_HOP,
        "multi": SMART_GROUP_MODE_MULTI_HOP,
        "multihop": SMART_GROUP_MODE_MULTI_HOP,
        "multi-hop": SMART_GROUP_MODE_MULTI_HOP,
        "lb": SMART_GROUP_MODE_LOAD_BALANCE,
        "balance": SMART_GROUP_MODE_LOAD_BALANCE,
        "balancer": SMART_GROUP_MODE_LOAD_BALANCE,
        "urltest": SMART_GROUP_MODE_LOAD_BALANCE,
    }
    text = aliases.get(text, text)
    return text if text in SMART_GROUP_MODES else SMART_GROUP_MODE_FAILOVER


def _clean_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item or "").strip()
        if text and text not in seen:
            result.append(text)
            seen.add(text)
    return result


def _optional_str(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


@dataclass(slots=True)
class ServerQualityEvent:
    """Одно событие качества сервера: latency, success или failure."""

    timestamp: str
    event: str
    success: bool
    latency_ms: int | None = None
    message: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerQualityEvent":
        safe = dict(data)
        timestamp = _optional_str(safe.get("timestamp")) or utc_now_iso()
        event = str(safe.get("event") or "").strip().lower()
        default_success = event != QUALITY_EVENT_FAILURE if event in QUALITY_EVENT_TYPES else False
        success = _bool_value(safe.get("success"), default_success)
        if event not in QUALITY_EVENT_TYPES:
            event = QUALITY_EVENT_SUCCESS if success else QUALITY_EVENT_FAILURE
        latency_ms = _optional_int(safe.get("latency_ms"))
        message = _optional_str(safe.get("message"))
        return cls(timestamp=timestamp, event=event, success=success, latency_ms=latency_ms, message=message)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ServerQualityStats:
    """Накопленная статистика качества одного серверного профиля."""

    profile_id: str
    latency_ewma_ms: float | None = None
    last_latency_ms: int | None = None
    samples: int = 0
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_checked_at: str | None = None
    cooldown_until: str | None = None
    history: list[ServerQualityEvent] = field(default_factory=list)
    connection_count: int = 0
    total_connected_seconds: int = 0
    total_download_bytes: int = 0
    total_upload_bytes: int = 0
    last_connected_at: str | None = None
    last_disconnected_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerQualityStats":
        safe = dict(data)
        safe["profile_id"] = str(safe.get("profile_id") or "").strip()
        safe["latency_ewma_ms"] = _optional_float(safe.get("latency_ewma_ms"))
        safe["last_latency_ms"] = _optional_int(safe.get("last_latency_ms"))
        for key in (
            "samples",
            "success_count",
            "failure_count",
            "consecutive_failures",
            "connection_count",
            "total_connected_seconds",
            "total_download_bytes",
            "total_upload_bytes",
        ):
            try:
                safe[key] = max(0, int(safe.get(key) or 0))
            except (TypeError, ValueError):
                safe[key] = 0
        for key in (
            "last_success_at",
            "last_failure_at",
            "last_checked_at",
            "cooldown_until",
            "last_connected_at",
            "last_disconnected_at",
        ):
            safe[key] = _optional_str(safe.get(key))
        raw_history = safe.get("history") or []
        if not isinstance(raw_history, list):
            raw_history = []
        safe["history"] = [
            ServerQualityEvent.from_dict(item)
            for item in raw_history[-SERVER_QUALITY_HISTORY_LIMIT:]
            if isinstance(item, dict)
        ]
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def add_event(
        self,
        event: str,
        *,
        timestamp: str | None = None,
        success: bool,
        latency_ms: int | None = None,
        message: str | None = None,
    ) -> None:
        clean_event = str(event or "").strip().lower()
        if clean_event not in QUALITY_EVENT_TYPES:
            clean_event = QUALITY_EVENT_SUCCESS if success else QUALITY_EVENT_FAILURE
        clean_latency = max(1, int(latency_ms)) if latency_ms is not None else None
        self.history.append(
            ServerQualityEvent(
                timestamp=timestamp or utc_now_iso(),
                event=clean_event,
                success=bool(success),
                latency_ms=clean_latency,
                message=_optional_str(message),
            )
        )
        if len(self.history) > SERVER_QUALITY_HISTORY_LIMIT:
            self.history = self.history[-SERVER_QUALITY_HISTORY_LIMIT:]

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total <= 0:
            return 0.5
        return self.success_count / total

    @property
    def recent_success_rate(self) -> float:
        if not self.history:
            return self.success_rate
        return sum(1 for event in self.history if event.success) / len(self.history)

    @property
    def recent_average_latency_ms(self) -> int | None:
        values = [event.latency_ms for event in self.history if event.success and event.latency_ms is not None]
        if not values:
            return None
        return max(1, int(sum(values) / len(values)))

    @property
    def last_event(self) -> ServerQualityEvent | None:
        return self.history[-1] if self.history else None

    def record_usage(
        self,
        *,
        connected_seconds: int,
        download_bytes: int,
        upload_bytes: int,
        connected_at: str | None = None,
        disconnected_at: str | None = None,
    ) -> None:
        self.connection_count += 1
        self.total_connected_seconds += max(0, int(connected_seconds))
        self.total_download_bytes += max(0, int(download_bytes))
        self.total_upload_bytes += max(0, int(upload_bytes))
        self.last_connected_at = _optional_str(connected_at) or self.last_connected_at
        self.last_disconnected_at = _optional_str(disconnected_at) or utc_now_iso()


@dataclass(slots=True)
class SmartGroup:
    """Пользовательская группа: failover, multi-hop chain или load-balance target."""

    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = "Smart Group"
    enabled: bool = True
    profile_ids: list[str] = field(default_factory=list)
    subscription_id: str | None = None
    source_group: str | None = None
    mode: str = SMART_GROUP_MODE_FAILOVER
    strategy: str = SMART_STRATEGY_SMART
    load_balance_interval: str = SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT
    load_balance_tolerance_ms: int = SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS
    usage_connection_count: int = 0
    usage_total_seconds: int = 0
    usage_total_download_bytes: int = 0
    usage_total_upload_bytes: int = 0
    usage_last_connected_at: str | None = None
    usage_last_disconnected_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SmartGroup":
        safe = dict(data)
        safe["id"] = str(safe.get("id") or uuid4().hex).strip() or uuid4().hex
        safe["name"] = str(safe.get("name") or "Smart Group").strip() or "Smart Group"
        safe["enabled"] = _bool_value(safe.get("enabled"), True)
        safe["profile_ids"] = _clean_string_list(safe.get("profile_ids"))
        safe["subscription_id"] = _optional_str(safe.get("subscription_id"))
        safe["source_group"] = _optional_str(safe.get("source_group"))
        safe["mode"] = normalize_smart_group_mode(safe.get("mode"))
        safe["strategy"] = normalize_smart_strategy(safe.get("strategy"))
        interval = _optional_str(safe.get("load_balance_interval")) or SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT
        safe["load_balance_interval"] = interval
        tolerance = _optional_int(safe.get("load_balance_tolerance_ms"))
        safe["load_balance_tolerance_ms"] = (
            tolerance if tolerance is not None and tolerance >= 0 else SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS
        )
        for key in (
            "usage_connection_count",
            "usage_total_seconds",
            "usage_total_download_bytes",
            "usage_total_upload_bytes",
        ):
            try:
                safe[key] = max(0, int(safe.get(key) or 0))
            except (TypeError, ValueError):
                safe[key] = 0
        safe["usage_last_connected_at"] = _optional_str(safe.get("usage_last_connected_at"))
        safe["usage_last_disconnected_at"] = _optional_str(safe.get("usage_last_disconnected_at"))
        safe["created_at"] = _optional_str(safe.get("created_at")) or utc_now_iso()
        safe["updated_at"] = _optional_str(safe.get("updated_at")) or safe["created_at"]
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mode"] = normalize_smart_group_mode(self.mode)
        data["strategy"] = normalize_smart_strategy(self.strategy)
        data["profile_ids"] = _clean_string_list(self.profile_ids)
        data["load_balance_interval"] = _optional_str(self.load_balance_interval) or SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT
        data["load_balance_tolerance_ms"] = max(0, int(self.load_balance_tolerance_ms))
        return data

    def touch(self) -> None:
        self.updated_at = utc_now_iso()

    def record_usage(
        self,
        *,
        connected_seconds: int,
        download_bytes: int,
        upload_bytes: int,
        connected_at: str | None = None,
        disconnected_at: str | None = None,
    ) -> None:
        self.usage_connection_count += 1
        self.usage_total_seconds += max(0, int(connected_seconds))
        self.usage_total_download_bytes += max(0, int(download_bytes))
        self.usage_total_upload_bytes += max(0, int(upload_bytes))
        self.usage_last_connected_at = _optional_str(connected_at) or self.usage_last_connected_at
        self.usage_last_disconnected_at = _optional_str(disconnected_at) or utc_now_iso()
        self.touch()
