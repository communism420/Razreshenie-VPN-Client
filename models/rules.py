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

"""Модель правил раздельного туннелирования."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from utils.paths import resource_path


SPLIT_PROXY_ONLY = "proxy_only"
SPLIT_BYPASS = "bypass"
ROUTE_OUTBOUND_PROXY = "proxy"
ROUTE_OUTBOUND_DIRECT = "direct"
ROUTE_OUTBOUNDS = {ROUTE_OUTBOUND_PROXY, ROUTE_OUTBOUND_DIRECT}
BUILTIN_DIRECT_RULE_ID = "builtin-direct-russian-sites"
BUILTIN_DIRECT_RULE_NAME = "Встроенный bypass: whitelist"
BUILTIN_DIRECT_SOURCE = "assets/rules/builtin_bypass_whitelist.json"
BUILTIN_DIRECT_FALLBACK_DOMAIN_SUFFIXES = (
    "wildberries.ru",
    "wb.ru",
    "wbbasket.ru",
    "wbstatic.net",
)
BUILTIN_DOMAIN_KEYS = {
    "domain",
    "domains",
    "domain_suffix",
    "domain_suffixes",
    "host",
    "hosts",
}


def _new_rule_id() -> str:
    return uuid.uuid4().hex


def normalize_outbound(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if text in {"proxy", "vpn", "server", "current", "current_server", "текущий сервер", "сервер"}:
        return ROUTE_OUTBOUND_PROXY
    if text in {"direct", "bypass", "напрямую", "прямой"}:
        return ROUTE_OUTBOUND_DIRECT
    return ROUTE_OUTBOUND_PROXY


def _clean_builtin_domain(value: str) -> str:
    text = value.strip().lower()
    text = text.removeprefix("regexp:")
    text = text.removeprefix("geosite:")
    text = text.removeprefix("domain:")
    text = text.removeprefix("full:")
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or ""
    text = text.split("/")[0].strip()
    text = text.removeprefix("*.").removeprefix(".")
    return text


def _walk_builtin_domains(value: Any, key: str | None, domains: set[str]) -> None:
    normalized_key = (key or "").lower().replace("-", "_")
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            _walk_builtin_domains(item_value, item_key, domains)
        return
    if isinstance(value, list):
        for item in value:
            _walk_builtin_domains(item, key, domains)
        return
    if normalized_key not in BUILTIN_DOMAIN_KEYS:
        return
    text = _clean_builtin_domain(str(value))
    if text and "." in text:
        domains.add(text)


def _load_builtin_direct_domain_suffixes() -> tuple[str, ...]:
    domains = set(BUILTIN_DIRECT_FALLBACK_DOMAIN_SUFFIXES)
    path = resource_path("assets", "rules", "builtin_bypass_whitelist.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return tuple(sorted(domains))
    _walk_builtin_domains(data, None, domains)
    return tuple(sorted(domains))


BUILTIN_DIRECT_DOMAIN_SUFFIXES = _load_builtin_direct_domain_suffixes()


def builtin_direct_rule_sets() -> list["RoutingRuleSet"]:
    """Встроенный bypass для сайтов, которые часто блокируют VPN-адреса."""
    return [
        RoutingRuleSet(
            id=BUILTIN_DIRECT_RULE_ID,
            name=BUILTIN_DIRECT_RULE_NAME,
            enabled=True,
            outbound=ROUTE_OUTBOUND_DIRECT,
            source_type="builtin",
            source=BUILTIN_DIRECT_SOURCE,
            domain_suffix=list(BUILTIN_DIRECT_DOMAIN_SUFFIXES),
        )
    ]


@dataclass(slots=True)
class RoutingRuleSet:
    """Один JSON-набор правил с собственным маршрутом."""

    id: str = field(default_factory=_new_rule_id)
    name: str = "Правила"
    enabled: bool = True
    outbound: str = ROUTE_OUTBOUND_PROXY
    source_type: str | None = None
    source: str | None = None
    domains: list[str] = field(default_factory=list)
    domain_suffix: list[str] = field(default_factory=list)
    domain_keyword: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    process_name: list[str] = field(default_factory=list)
    process_path_regex: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RoutingRuleSet":
        safe = dict(data)
        for key in (
            "domains",
            "domain_suffix",
            "domain_keyword",
            "ip_cidr",
            "process_name",
            "process_path_regex",
        ):
            value = safe.get(key) or []
            if isinstance(value, str):
                value = [value]
            safe[key] = [str(item).strip() for item in value if str(item).strip()]
        safe["id"] = str(safe.get("id") or _new_rule_id())
        safe["name"] = str(safe.get("name") or safe.get("source") or "Правила")
        safe["enabled"] = bool(safe.get("enabled", True))
        safe["outbound"] = normalize_outbound(str(safe.get("outbound") or safe.get("route") or ROUTE_OUTBOUND_PROXY))
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["outbound"] = normalize_outbound(self.outbound)
        return data

    @property
    def total_items(self) -> int:
        return (
            len(self.domains)
            + len(self.domain_suffix)
            + len(self.domain_keyword)
            + len(self.ip_cidr)
            + len(self.process_name)
            + len(self.process_path_regex)
        )

    @property
    def is_empty(self) -> bool:
        return self.total_items == 0

    @property
    def outbound_label(self) -> str:
        return "Текущий сервер" if normalize_outbound(self.outbound) == ROUTE_OUTBOUND_PROXY else "Напрямую"


@dataclass(slots=True)
class SplitRules:
    """Коллекция JSON-наборов правил для генерации sing-box routing."""

    enabled: bool = False
    default_outbound: str = ROUTE_OUTBOUND_PROXY
    rule_sets: list[RoutingRuleSet] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SplitRules":
        if not data:
            return cls(enabled=False)
        safe = dict(data)
        if "rule_sets" in safe:
            rule_sets = [
                RoutingRuleSet.from_dict(item)
                for item in safe.get("rule_sets") or []
                if isinstance(item, dict)
            ]
            return cls(
                enabled=bool(safe.get("enabled", True)) and any(not item.is_empty for item in rule_sets),
                default_outbound=normalize_outbound(safe.get("default_outbound")),
                rule_sets=[item for item in rule_sets if not item.is_empty],
            )

        legacy = {
            "name": safe.get("source") or "Импортированные правила",
            "enabled": bool(safe.get("enabled", False)),
            "outbound": ROUTE_OUTBOUND_PROXY if safe.get("mode") == SPLIT_PROXY_ONLY else ROUTE_OUTBOUND_DIRECT,
            "source_type": safe.get("source_type"),
            "source": safe.get("source"),
        }
        for key in (
            "domains",
            "domain_suffix",
            "domain_keyword",
            "ip_cidr",
            "process_name",
            "process_path_regex",
        ):
            value = safe.get(key) or []
            if isinstance(value, str):
                value = [value]
            legacy[key] = [str(item).strip() for item in value if str(item).strip()]
        rule_set = RoutingRuleSet.from_dict(legacy)
        default_outbound = ROUTE_OUTBOUND_DIRECT if safe.get("mode") == SPLIT_PROXY_ONLY else ROUTE_OUTBOUND_PROXY
        if rule_set.is_empty:
            return cls(enabled=False, default_outbound=default_outbound)
        return cls(enabled=rule_set.enabled, default_outbound=default_outbound, rule_sets=[rule_set])

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "default_outbound": normalize_outbound(self.default_outbound),
            "rule_sets": [rule_set.to_dict() for rule_set in self.rule_sets],
        }

    @property
    def enabled_rule_sets(self) -> list[RoutingRuleSet]:
        if not self.enabled:
            return []
        return [rule_set for rule_set in self.rule_sets if rule_set.enabled and not rule_set.is_empty]

    @property
    def effective_default_outbound(self) -> str:
        """Автоматически выбирает маршрут для трафика вне JSON-наборов."""
        active = self.enabled_rule_sets
        if not active:
            return ROUTE_OUTBOUND_PROXY

        has_proxy_rules = any(normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_PROXY for rule_set in active)
        has_direct_rules = any(normalize_outbound(rule_set.outbound) == ROUTE_OUTBOUND_DIRECT for rule_set in active)
        if has_proxy_rules and not has_direct_rules:
            return ROUTE_OUTBOUND_DIRECT
        if has_direct_rules and not has_proxy_rules:
            return ROUTE_OUTBOUND_PROXY
        return normalize_outbound(self.default_outbound)

    @property
    def total_items(self) -> int:
        return sum(rule_set.total_items for rule_set in self.rule_sets)

    @property
    def is_empty(self) -> bool:
        return self.total_items == 0
