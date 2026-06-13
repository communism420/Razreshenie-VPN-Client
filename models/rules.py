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
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from utils.paths import resource_path


SPLIT_PROXY_ONLY = "proxy_only"
SPLIT_BYPASS = "bypass"
ROUTE_OUTBOUND_PROXY = "proxy"
ROUTE_OUTBOUND_DIRECT = "direct"
ROUTE_OUTBOUNDS = {ROUTE_OUTBOUND_PROXY, ROUTE_OUTBOUND_DIRECT}
RULE_SET_RESOURCE_TYPES = {"inline", "local", "remote"}
RULE_SET_RESOURCE_FORMATS = {"source", "binary"}
WINDOWS_ENV_VAR_RE = re.compile(r"%([^%]+)%")
WINDOWS_DRIVE_PATH_RE = re.compile(r"^[a-zA-Z]:[\\/]")
WINDOWS_EXE_RE = re.compile(r"(?i)\.exe\b")
BUILTIN_DIRECT_RULE_ID = "builtin-direct-russian-sites"
BUILTIN_DIRECT_RULE_NAME = "Встроенный bypass: whitelist"
BUILTIN_DIRECT_SOURCE = "assets/rules/builtin_bypass_whitelist.json"
BUILTIN_DIRECT_FALLBACK_DOMAIN_SUFFIXES = (
    "ozon.by",
    "ozon.kz",
    "ozon.ru",
    "ozone.ru",
    "ozonusercontent.com",
    "ozon-st.cdn.ngenix.net",
    "ozon-st.cdnvideo.ru",
    "wildberries.am",
    "wildberries.by",
    "wildberries.kz",
    "wildberries.ru",
    "wildberries.uz",
    "wb.ru",
    "wbdl.ru",
    "wbbasket.ru",
    "wbstatic.ru",
    "wbstatic.net",
    "wbxcdn.com",
)
BUILTIN_DOMAIN_KEYS = {
    "domain",
    "domains",
    "domain_suffix",
    "domain_suffixes",
    "host",
    "hosts",
}
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.il",
    "co.jp",
    "co.kr",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.ru",
    "com.tr",
    "com.ua",
    "net.au",
    "net.ru",
    "net.ua",
    "ne.jp",
    "org.uk",
    "org.ru",
    "org.ua",
}


def _new_rule_id() -> str:
    return uuid.uuid4().hex


def _new_rule_set_resource_id() -> str:
    return uuid.uuid4().hex


def normalize_outbound(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if text in {"proxy", "vpn", "server", "current", "current_server", "текущий сервер", "сервер"}:
        return ROUTE_OUTBOUND_PROXY
    if text in {"direct", "bypass", "напрямую", "прямой"}:
        return ROUTE_OUTBOUND_DIRECT
    return ROUTE_OUTBOUND_PROXY


def normalize_rule_set_resource_type(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if text in {"inline"}:
        return "inline"
    if text in {"remote", "url", "http", "https"}:
        return "remote"
    return "local"


def normalize_rule_set_resource_format(value: str | None, source: str | None = None) -> str:
    text = str(value or "").strip().lower()
    if text in RULE_SET_RESOURCE_FORMATS:
        return text
    suffix = Path(str(source or "")).suffix.lower()
    if suffix == ".srs":
        return "binary"
    return "source"


def _clean_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            result.append(text)
    return result


def _clean_quoted_text(value: Any) -> str:
    text = str(value or "").strip().strip("\ufeff")
    while len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
        text = text[1:-1].strip()
    return text.strip("'\"`").strip()


def normalize_domain_match(value: Any, *, keep_prefix: bool = False) -> str:
    """Normalize user-entered domain patterns without changing their meaning."""
    text = _clean_quoted_text(value).lower()
    if not text:
        return ""

    prefix = ""
    if ":" in text:
        raw_prefix, _, tail = text.partition(":")
        normalized_prefix = raw_prefix.strip().lower().replace("-", "_")
        if normalized_prefix in {"domain", "full", "keyword"}:
            prefix = normalized_prefix
            text = tail.strip()

    if prefix == "keyword":
        keyword = text.strip().strip(".")
        return f"{prefix}:{keyword}" if keep_prefix and keyword else keyword

    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or ""

    text = re.split(r"[/?#]", text, maxsplit=1)[0].strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        host, separator, port = text.rpartition(":")
        if separator and host and port.isdigit():
            text = host
    text = text.removeprefix("*.").removeprefix(".").strip(".")
    if not text:
        return ""
    return f"{prefix}:{text}" if keep_prefix and prefix else text


def domain_site_suffix(value: Any) -> str:
    """Return the registrable site zone used for one-click bypass rules."""
    domain = normalize_domain_match(value)
    if not domain or "." not in domain:
        return domain
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return domain
    last_two = ".".join(parts[-2:])
    if last_two in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def clean_domain_matches(values: Any) -> list[str]:
    return _unique_sorted_casefold(
        [domain for domain in (normalize_domain_match(item) for item in _clean_string_list(values)) if domain]
    )


def _is_ip_literal(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def effective_rule_domains(rule_set: Any) -> list[str]:
    return clean_domain_matches(getattr(rule_set, "domains", []))


def effective_rule_domain_suffixes(rule_set: Any, *, expand_direct_domains: bool = True) -> list[str]:
    suffixes = clean_domain_matches(getattr(rule_set, "domain_suffix", []))
    if expand_direct_domains and normalize_outbound(getattr(rule_set, "outbound", None)) == ROUTE_OUTBOUND_DIRECT:
        suffixes.extend(
            suffix
            for suffix in (domain_site_suffix(domain) for domain in getattr(rule_set, "domains", []))
            if suffix and "." in suffix and not _is_ip_literal(suffix)
        )
    return _unique_sorted_casefold(suffixes)


def _trim_windows_executable_arguments(value: str) -> str:
    match = WINDOWS_EXE_RE.search(value)
    if match:
        return value[: match.end()].strip()
    return value


def _expand_windows_env_vars(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), match.group(0))

    return os.path.expandvars(WINDOWS_ENV_VAR_RE.sub(replace, value))


def _looks_like_windows_path(value: str) -> bool:
    text = value.strip()
    return (
        bool(WINDOWS_DRIVE_PATH_RE.match(text))
        or text.startswith(("\\\\", ".\\", "..\\"))
        or "\\" in text
    )


def _unique_sorted_casefold(values: list[str]) -> list[str]:
    by_key: dict[str, str] = {}
    for value in values:
        text = str(value or "").strip()
        if text:
            by_key.setdefault(text.casefold(), text)
    return [by_key[key] for key in sorted(by_key)]


def normalize_process_name(value: Any) -> str:
    text = _trim_windows_executable_arguments(_clean_quoted_text(value))
    if not text:
        return ""
    if "\\" in text or "/" in text or WINDOWS_DRIVE_PATH_RE.match(text):
        text = text.replace("/", "\\")
        text = PureWindowsPath(text).name
    return _clean_quoted_text(text)


def normalize_process_path(value: Any) -> str:
    text = _clean_quoted_text(value)
    if not text:
        return ""
    text = _trim_windows_executable_arguments(_expand_windows_env_vars(text))
    if _looks_like_windows_path(text):
        text = str(PureWindowsPath(text.replace("/", "\\")))
    return _clean_quoted_text(text)


def normalize_process_path_regex(value: Any) -> str:
    return _clean_quoted_text(value)


def clean_process_names(value: Any) -> list[str]:
    return _unique_sorted_casefold([normalize_process_name(item) for item in _clean_string_list(value)])


def clean_process_paths(value: Any) -> list[str]:
    return _unique_sorted_casefold([normalize_process_path(item) for item in _clean_string_list(value)])


def clean_process_path_regexes(value: Any) -> list[str]:
    return _unique_sorted_casefold([normalize_process_path_regex(item) for item in _clean_string_list(value)])


def _clean_rule_set_tag(value: str) -> str:
    text = str(value or "").strip()
    if text:
        return text
    return f"rule-set-{uuid.uuid4().hex[:12]}"


def _source_stem(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        path_name = Path(parsed.path).stem
        return path_name or parsed.netloc
    return Path(text).stem


def _source_tag(value: str | None) -> str:
    stem = _source_stem(value)
    if not stem:
        return _clean_rule_set_tag("")
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", stem).strip("-._")
    return _clean_rule_set_tag(slug.lower() or "")


def _clean_builtin_domain(value: str) -> str:
    text = _clean_quoted_text(value).lower()
    text = text.removeprefix("regexp:")
    text = text.removeprefix("geosite:")
    text = text.removeprefix("domain:")
    text = text.removeprefix("full:")
    return normalize_domain_match(text)


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
            priority=9000,
            domain_suffix=list(BUILTIN_DIRECT_DOMAIN_SUFFIXES),
        )
    ]


@dataclass(slots=True)
class RouteRuleSetResource:
    """sing-box route.rule_set resource: local/remote .srs, source JSON or inline."""

    id: str = field(default_factory=_new_rule_set_resource_id)
    name: str = "Rule Set"
    enabled: bool = True
    type: str = "local"
    tag: str = ""
    format: str = "binary"
    path: str | None = None
    url: str | None = None
    update_interval: str = "1d"
    source: str | None = None
    rules: list[dict[str, Any]] = field(default_factory=list)
    last_update_at: str | None = None
    last_error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteRuleSetResource":
        safe = dict(data)
        resource_type = normalize_rule_set_resource_type(safe.get("type") or safe.get("source_type"))
        source = str(safe.get("source") or safe.get("path") or safe.get("url") or "").strip() or None
        safe["type"] = resource_type
        safe["path"] = str(safe.get("path") or "").strip() or None
        safe["url"] = str(safe.get("url") or "").strip() or None
        if resource_type == "remote" and not safe["url"] and source:
            safe["url"] = source
        if resource_type == "local" and not safe["path"] and source:
            safe["path"] = source
        safe["source"] = source
        safe["format"] = normalize_rule_set_resource_format(safe.get("format"), source)
        safe["tag"] = _clean_rule_set_tag(str(safe.get("tag") or _source_tag(source)))
        safe["name"] = str(safe.get("name") or _source_stem(source) or safe["tag"] or "Rule Set")
        safe["enabled"] = bool(safe.get("enabled", True))
        safe["update_interval"] = str(safe.get("update_interval") or "1d").strip() or "1d"
        safe["rules"] = [item for item in safe.get("rules") or [] if isinstance(item, dict)]
        for key in ("last_update_at", "last_error"):
            safe[key] = str(safe.get(key) or "").strip() or None
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["type"] = normalize_rule_set_resource_type(self.type)
        data["format"] = normalize_rule_set_resource_format(self.format, self.path or self.url or self.source)
        data["tag"] = _clean_rule_set_tag(self.tag)
        return data

    @property
    def is_usable(self) -> bool:
        if not self.enabled or not self.tag:
            return False
        resource_type = normalize_rule_set_resource_type(self.type)
        if resource_type == "inline":
            return bool(self.rules)
        if resource_type == "remote":
            return bool(self.url)
        return bool(self.path)


@dataclass(slots=True)
class RoutingRuleSet:
    """Один JSON-набор правил с собственным маршрутом."""

    id: str = field(default_factory=_new_rule_id)
    name: str = "Правила"
    enabled: bool = True
    outbound: str = ROUTE_OUTBOUND_PROXY
    source_type: str | None = None
    source: str | None = None
    priority: int = 1000
    domains: list[str] = field(default_factory=list)
    domain_suffix: list[str] = field(default_factory=list)
    domain_keyword: list[str] = field(default_factory=list)
    domain_regex: list[str] = field(default_factory=list)
    geosite: list[str] = field(default_factory=list)
    geoip: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    process_name: list[str] = field(default_factory=list)
    process_path: list[str] = field(default_factory=list)
    process_path_regex: list[str] = field(default_factory=list)
    rule_set_tags: list[str] = field(default_factory=list)
    rule_set_ip_cidr_match_source: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RoutingRuleSet":
        safe = dict(data)
        for key in (
            "domains",
            "domain_suffix",
            "domain_keyword",
            "domain_regex",
            "geosite",
            "geoip",
            "ip_cidr",
            "process_name",
            "process_path",
            "process_path_regex",
            "rule_set_tags",
        ):
            safe[key] = _clean_string_list(safe.get(key))
        safe["process_name"] = clean_process_names(safe["process_name"])
        safe["process_path"] = clean_process_paths(safe["process_path"])
        safe["process_path_regex"] = clean_process_path_regexes(safe["process_path_regex"])
        if not safe["rule_set_tags"]:
            safe["rule_set_tags"] = _clean_string_list(safe.get("rule_set"))
        safe["id"] = str(safe.get("id") or _new_rule_id())
        safe["name"] = str(safe.get("name") or safe.get("source") or "Правила")
        safe["enabled"] = bool(safe.get("enabled", True))
        safe["outbound"] = normalize_outbound(str(safe.get("outbound") or safe.get("route") or ROUTE_OUTBOUND_PROXY))
        try:
            safe["priority"] = int(safe.get("priority") or 1000)
        except (TypeError, ValueError):
            safe["priority"] = 1000
        safe["rule_set_ip_cidr_match_source"] = bool(
            safe.get("rule_set_ip_cidr_match_source")
            or safe.get("rule_set_ipcidr_match_source")
        )
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["outbound"] = normalize_outbound(self.outbound)
        data["process_name"] = clean_process_names(self.process_name)
        data["process_path"] = clean_process_paths(self.process_path)
        data["process_path_regex"] = clean_process_path_regexes(self.process_path_regex)
        return data

    @property
    def total_items(self) -> int:
        return (
            len(self.domains)
            + len(self.domain_suffix)
            + len(self.domain_keyword)
            + len(self.domain_regex)
            + len(self.geosite)
            + len(self.geoip)
            + len(self.ip_cidr)
            + len(self.process_name)
            + len(self.process_path)
            + len(self.process_path_regex)
            + len(self.rule_set_tags)
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
    rule_set_resources: list[RouteRuleSetResource] = field(default_factory=list)

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
            rule_set_resources = [
                RouteRuleSetResource.from_dict(item)
                for item in safe.get("rule_set_resources") or []
                if isinstance(item, dict)
            ]
            return cls(
                enabled=bool(safe.get("enabled", True)) and any(not item.is_empty for item in rule_sets),
                default_outbound=normalize_outbound(safe.get("default_outbound")),
                rule_sets=[item for item in rule_sets if not item.is_empty],
                rule_set_resources=rule_set_resources,
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
            "domain_regex",
            "geosite",
            "geoip",
            "ip_cidr",
            "process_name",
            "process_path",
            "process_path_regex",
            "rule_set_tags",
        ):
            legacy[key] = _clean_string_list(safe.get(key))
        legacy["process_name"] = clean_process_names(legacy["process_name"])
        legacy["process_path"] = clean_process_paths(legacy["process_path"])
        legacy["process_path_regex"] = clean_process_path_regexes(legacy["process_path_regex"])
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
            "rule_set_resources": [resource.to_dict() for resource in self.rule_set_resources],
        }

    @property
    def enabled_rule_sets(self) -> list[RoutingRuleSet]:
        if not self.enabled:
            return []
        active = [rule_set for rule_set in self.rule_sets if rule_set.enabled and not rule_set.is_empty]
        return [item for _index, item in sorted(enumerate(active), key=lambda pair: (pair[1].priority, pair[0]))]

    @property
    def enabled_rule_set_resources(self) -> list[RouteRuleSetResource]:
        if not self.enabled:
            return []
        return [resource for resource in self.rule_set_resources if resource.is_usable]

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
