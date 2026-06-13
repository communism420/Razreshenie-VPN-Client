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

"""Импорт JSON/TXT-правил и нормализация для sing-box routing."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from models.rules import (
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    clean_process_names,
    clean_process_path_regexes,
    clean_process_paths,
    normalize_domain_match,
    normalize_outbound,
    normalize_process_name,
    normalize_process_path,
    normalize_process_path_regex,
)


class RulesImportError(ValueError):
    """Ошибка файла или URL с правилами."""


DOMAIN_KEYS = {
    "domain",
    "domains",
    "domain_suffix",
    "domain_suffixes",
    "domainkeyword",
    "domain_keyword",
    "domain_keywords",
    "host",
    "hosts",
}
IP_KEYS = {"ip", "ips", "ip_cidr", "ip-cidr", "cidr", "ipcidr", "ip_cidrs"}
PROCESS_KEYS = {"process", "processes", "process_name", "process_names"}
PROCESS_PATH_KEYS = {"process_path", "process_paths", "process_pathes", "process_executable", "process_executables"}
PROCESS_PATH_REGEX_KEYS = {"process_path_regex", "process_path_regexes", "process_path_regexps"}
DOMAIN_REGEX_KEYS = {"domain_regex", "domain-regex", "regexp", "regex"}
GEOSITE_KEYS = {"geosite", "geo_site"}
GEOIP_KEYS = {"geoip", "geo_ip"}
RULE_SET_KEYS = {"rule_set", "rule_sets", "ruleset", "rulesets"}
PROCESS_EXE_NAME_RE = re.compile(r"(?i)^[^\\/:\s]+\.exe$")
WINDOWS_PATH_RE = re.compile(r"(?i)^(?:[a-z]:[\\/]|\\\\|\.{1,2}[\\/]|%[^%]+%[\\/])")


@dataclass(slots=True)
class RulesImportResult:
    rule_sets: list[RoutingRuleSet] = field(default_factory=list)
    rule_set_resources: list[RouteRuleSetResource] = field(default_factory=list)

    @property
    def primary_rule_set(self) -> RoutingRuleSet | None:
        return self.rule_sets[0] if self.rule_sets else None


class RulesManager:
    def from_file(self, path: Path, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        result = self.import_file(path, outbound)
        return self._require_primary_rule_set(result, allow_rule_set_resources=False)

    def import_file(self, path: Path, outbound: str = ROUTE_OUTBOUND_PROXY) -> RulesImportResult:
        path = Path(path)
        if path.suffix.lower() == ".srs":
            return self._from_srs_file(path, outbound)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise RulesImportError(f"Не удалось прочитать файл правил: {exc}") from exc
        rules = self._from_text_or_json(text, outbound, source_hint=path.suffix)
        rules.name = path.stem
        rules.source_type = "file"
        rules.source = str(path)
        return RulesImportResult(rule_sets=[rules])

    def from_url(self, url: str, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        result = self.import_url(url, outbound)
        return self._require_primary_rule_set(result, allow_rule_set_resources=False)

    def import_url(self, url: str, outbound: str = ROUTE_OUTBOUND_PROXY) -> RulesImportResult:
        parsed = urlparse(url)
        suffix = Path(parsed.path).suffix.lower()
        if suffix == ".srs":
            return self._from_srs_url(url, outbound)
        try:
            response = requests.get(url, timeout=20, headers={"User-Agent": "RazreshenieVPN/1.0"})
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RulesImportError(f"Не удалось загрузить правила: {exc}") from exc
        rules = self._from_text_or_json(response.text, outbound, source_hint=Path(parsed.path).suffix)
        rules.name = Path(parsed.path).stem or parsed.netloc or "URL-правила"
        rules.source_type = "url"
        rules.source = url
        return RulesImportResult(rule_sets=[rules])

    def _from_srs_file(self, path: Path, outbound: str) -> RulesImportResult:
        if not path.exists():
            raise RulesImportError(f"SRS-файл не найден: {path}")
        resource = RouteRuleSetResource.from_dict(
            {
                "name": path.stem,
                "type": "local",
                "format": "binary",
                "path": str(path),
                "source": str(path),
            }
        )
        rule_set = self._rule_set_for_resource(resource, outbound, source_type="file", source=str(path))
        return RulesImportResult(rule_sets=[rule_set], rule_set_resources=[resource])

    def _from_srs_url(self, url: str, outbound: str) -> RulesImportResult:
        parsed = urlparse(url)
        resource = RouteRuleSetResource.from_dict(
            {
                "name": Path(parsed.path).stem or parsed.netloc or "remote-srs",
                "type": "remote",
                "format": "binary",
                "url": url,
                "source": url,
                "update_interval": "1d",
            }
        )
        rule_set = self._rule_set_for_resource(resource, outbound, source_type="url", source=url)
        return RulesImportResult(rule_sets=[rule_set], rule_set_resources=[resource])

    def _rule_set_for_resource(
        self,
        resource: RouteRuleSetResource,
        outbound: str,
        *,
        source_type: str,
        source: str,
    ) -> RoutingRuleSet:
        return RoutingRuleSet(
            name=resource.name,
            enabled=True,
            outbound=normalize_outbound(outbound),
            source_type=source_type,
            source=source,
            rule_set_tags=[resource.tag],
        )

    @staticmethod
    def _require_primary_rule_set(
        result: RulesImportResult,
        *,
        allow_rule_set_resources: bool,
    ) -> RoutingRuleSet:
        if result.rule_set_resources and not allow_rule_set_resources:
            raise RulesImportError("SRS ruleset требует нового import_file/import_url API")
        if result.primary_rule_set is None:
            raise RulesImportError("Импорт не вернул правил маршрутизации")
        return result.primary_rule_set

    def _from_text_or_json(self, text: str, outbound: str, source_hint: str = "") -> RoutingRuleSet:
        suffix = source_hint.lower()
        if suffix == ".txt":
            return self.from_text(text, outbound)
        try:
            return self.from_json(json.loads(text), outbound)
        except json.JSONDecodeError as json_error:
            if suffix == ".json":
                raise RulesImportError(f"Не удалось прочитать JSON-правила: {json_error}") from json_error
            return self.from_text(text, outbound)

    def from_json(self, data: Any, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        rules = RoutingRuleSet(enabled=True, outbound=normalize_outbound(outbound))
        self._walk(data, None, rules)
        self._deduplicate(rules)
        if rules.is_empty:
            raise RulesImportError("JSON не содержит доменов, IP/CIDR или process-правил")
        return rules

    def from_text(self, text: str, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        rules = RoutingRuleSet(enabled=True, outbound=normalize_outbound(outbound))
        invalid_count = 0
        for line in text.splitlines():
            item = self._clean_text_line(line)
            if not item:
                continue
            if self._looks_like_cidr(item):
                self._add_ip(item, rules)
            elif self._is_geosite(item):
                self._add_geosite(item, rules)
            elif self._is_geoip(item):
                self._add_geoip(item, rules)
            elif self._is_domain_regex(item):
                self._add_domain_regex(item, rules)
            elif self._is_process_path_regex(item):
                rules.process_path_regex.append(normalize_process_path_regex(self._strip_prefix(item)))
            elif self._is_process_path(item):
                rules.process_path.append(normalize_process_path(self._strip_prefix(item)))
            elif self._is_process_name(item):
                rules.process_name.append(normalize_process_name(self._strip_prefix(item)))
            elif self._looks_like_process_path(item):
                rules.process_path.append(normalize_process_path(item))
            elif self._looks_like_process_name(item):
                rules.process_name.append(normalize_process_name(item))
            elif self._looks_like_domain(item):
                self._add_domain(item, "domain", rules)
            else:
                invalid_count += 1
        self._deduplicate(rules)
        if rules.is_empty:
            detail = f"; пропущено строк: {invalid_count}" if invalid_count else ""
            raise RulesImportError(f"TXT не содержит доменов или IP/CIDR{detail}")
        return rules

    @staticmethod
    def _clean_text_line(line: str) -> str:
        text = line.strip()
        if not text or text.startswith(("#", ";", "//")):
            return ""
        for marker in (" #", " ;", " //"):
            if marker in text:
                text = text.split(marker, 1)[0].strip()
        return text

    def _walk(self, value: Any, key: str | None, rules: RoutingRuleSet) -> None:
        normalized_key = (key or "").lower().replace("-", "_")
        if isinstance(value, dict):
            for item_key, item_value in value.items():
                self._walk(item_value, item_key, rules)
            return
        if isinstance(value, list):
            for item in value:
                self._walk(item, key, rules)
            return
        if value is None:
            return

        text = str(value).strip()
        if not text:
            return

        if normalized_key in GEOIP_KEYS or self._is_geoip(text):
            self._add_geoip(text, rules)
        elif normalized_key in GEOSITE_KEYS or self._is_geosite(text):
            self._add_geosite(text, rules)
        elif normalized_key in DOMAIN_REGEX_KEYS or self._is_domain_regex(text):
            self._add_domain_regex(text, rules)
        elif normalized_key in IP_KEYS or self._looks_like_cidr(text):
            self._add_ip(text, rules)
        elif normalized_key in PROCESS_KEYS:
            rules.process_name.append(normalize_process_name(text))
        elif normalized_key in PROCESS_PATH_KEYS:
            rules.process_path.append(normalize_process_path(text))
        elif normalized_key in PROCESS_PATH_REGEX_KEYS:
            rules.process_path_regex.append(normalize_process_path_regex(text))
        elif normalized_key in RULE_SET_KEYS:
            rules.rule_set_tags.append(text)
        elif self._looks_like_process_path(text):
            rules.process_path.append(normalize_process_path(text))
        elif self._looks_like_process_name(text):
            rules.process_name.append(normalize_process_name(text))
        elif normalized_key in DOMAIN_KEYS or self._looks_like_domain(text):
            self._add_domain(text, normalized_key, rules)

    def _add_domain(self, value: str, key: str, rules: RoutingRuleSet) -> None:
        raw = value.strip().lower()
        if self._is_geosite(raw):
            self._add_geosite(raw, rules)
            return
        if self._is_geoip(raw):
            self._add_geoip(raw, rules)
            return
        if self._is_domain_regex(raw):
            self._add_domain_regex(raw, rules)
            return
        text = self._clean_domain(raw)
        if not text:
            return
        if text.startswith("keyword:"):
            rules.domain_keyword.append(text.removeprefix("keyword:"))
            return
        if text.startswith("domain:"):
            rules.domain_suffix.append(text.removeprefix("domain:"))
            return
        if text.startswith("full:"):
            rules.domains.append(text.removeprefix("full:"))
            return
        if key in {"domain_keyword", "domain_keywords", "domainkeyword"}:
            rules.domain_keyword.append(text)
            return
        if key in {"domain", "domains", "domain_suffix", "domain_suffixes", "host", "hosts"}:
            rules.domain_suffix.append(text)
            return
        rules.domain_suffix.append(text)

    def _add_geosite(self, value: str, rules: RoutingRuleSet) -> None:
        text = self._strip_prefix(value).strip().lower()
        if text:
            rules.geosite.append(text)

    def _add_geoip(self, value: str, rules: RoutingRuleSet) -> None:
        text = self._strip_prefix(value).strip().lower()
        if text:
            rules.geoip.append(text)

    def _add_domain_regex(self, value: str, rules: RoutingRuleSet) -> None:
        text = self._strip_prefix(value).strip()
        if text:
            rules.domain_regex.append(text)

    def _add_ip(self, value: str, rules: RoutingRuleSet) -> None:
        text = value.removeprefix("ip-cidr:").removeprefix("ip_cidr:").strip()
        try:
            if "/" in text:
                rules.ip_cidr.append(str(ipaddress.ip_network(text, strict=False)))
            else:
                ip = ipaddress.ip_address(text)
                suffix = 32 if ip.version == 4 else 128
                rules.ip_cidr.append(f"{ip}/{suffix}")
        except ValueError:
            return

    def _clean_domain(self, value: str) -> str:
        return normalize_domain_match(value, keep_prefix=True)

    def _looks_like_domain(self, value: str) -> bool:
        if self._has_known_prefix(value):
            return False
        text = normalize_domain_match(value)
        return bool(re.match(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$", text))

    def _looks_like_cidr(self, value: str) -> bool:
        try:
            text = value.removeprefix("ip-cidr:").removeprefix("ip_cidr:")
            if "/" in text:
                ipaddress.ip_network(text, strict=False)
            else:
                ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_known_prefix(value: str) -> bool:
        return RulesManager._prefix_name(value) in {
            "geosite",
            "geoip",
            "regexp",
            "regex",
            "domain_regex",
            "process",
            "process_name",
            "process_path",
            "process_path_regex",
        }

    @staticmethod
    def _prefix_name(value: str) -> str:
        text = str(value or "").strip()
        if ":" not in text:
            return ""
        prefix, _, _tail = text.partition(":")
        return prefix.strip().lower().replace("-", "_")

    @staticmethod
    def _strip_prefix(value: str) -> str:
        text = str(value or "").strip()
        if ":" not in text:
            return text
        prefix, _, tail = text.partition(":")
        if prefix.strip().lower().replace("-", "_") in {
            "geosite",
            "geoip",
            "regexp",
            "regex",
            "domain_regex",
            "process",
            "process_name",
            "process_path",
            "process_path_regex",
        }:
            return tail.strip()
        return text

    @staticmethod
    def _is_geosite(value: str) -> bool:
        return str(value or "").strip().lower().startswith("geosite:")

    @staticmethod
    def _is_geoip(value: str) -> bool:
        return str(value or "").strip().lower().startswith("geoip:")

    @staticmethod
    def _is_domain_regex(value: str) -> bool:
        prefix = RulesManager._prefix_name(value)
        return prefix in {"regexp", "regex", "domain_regex"}

    @staticmethod
    def _is_process_name(value: str) -> bool:
        return RulesManager._prefix_name(value) in {"process", "process_name"}

    @staticmethod
    def _is_process_path(value: str) -> bool:
        return RulesManager._prefix_name(value) in PROCESS_PATH_KEYS

    @staticmethod
    def _is_process_path_regex(value: str) -> bool:
        return RulesManager._prefix_name(value) in PROCESS_PATH_REGEX_KEYS

    @staticmethod
    def _looks_like_process_name(value: str) -> bool:
        if RulesManager._has_known_prefix(value):
            return False
        return bool(PROCESS_EXE_NAME_RE.match(normalize_process_name(value)))

    @staticmethod
    def _looks_like_process_path(value: str) -> bool:
        text = str(value or "").strip().strip("'\"")
        if not text or "://" in text:
            return False
        normalized = normalize_process_path(text)
        return bool(
            normalized
            and ".exe" in normalized.lower()
            and (WINDOWS_PATH_RE.match(text) or "\\" in text or "/" in text)
        )

    @staticmethod
    def _deduplicate(rules: RoutingRuleSet) -> None:
        rules.domains = sorted(set(rules.domains))
        rules.domain_suffix = sorted(set(rules.domain_suffix))
        rules.domain_keyword = sorted(set(rules.domain_keyword))
        rules.domain_regex = sorted(set(rules.domain_regex))
        rules.geosite = sorted(set(rules.geosite))
        rules.geoip = sorted(set(rules.geoip))
        rules.ip_cidr = sorted(set(rules.ip_cidr))
        rules.process_name = clean_process_names(rules.process_name)
        rules.process_path = clean_process_paths(rules.process_path)
        rules.process_path_regex = clean_process_path_regexes(rules.process_path_regex)
        rules.rule_set_tags = sorted(set(rules.rule_set_tags))
