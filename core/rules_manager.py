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
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from models.rules import ROUTE_OUTBOUND_PROXY, RoutingRuleSet, normalize_outbound


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
PROCESS_PATH_KEYS = {"process_path_regex", "process_path", "process_paths"}


class RulesManager:
    def from_file(self, path: Path, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise RulesImportError(f"Не удалось прочитать файл правил: {exc}") from exc
        rules = self._from_text_or_json(text, outbound, source_hint=path.suffix)
        rules.name = path.stem
        rules.source_type = "file"
        rules.source = str(path)
        return rules

    def from_url(self, url: str, outbound: str = ROUTE_OUTBOUND_PROXY) -> RoutingRuleSet:
        try:
            response = requests.get(url, timeout=20, headers={"User-Agent": "RazreshenieVPN/1.0"})
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RulesImportError(f"Не удалось загрузить правила: {exc}") from exc
        parsed = urlparse(url)
        rules = self._from_text_or_json(response.text, outbound, source_hint=Path(parsed.path).suffix)
        rules.name = Path(parsed.path).stem or parsed.netloc or "URL-правила"
        rules.source_type = "url"
        rules.source = url
        return rules

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
        rules.domains = sorted(set(rules.domains))
        rules.domain_suffix = sorted(set(rules.domain_suffix))
        rules.domain_keyword = sorted(set(rules.domain_keyword))
        rules.ip_cidr = sorted(set(rules.ip_cidr))
        rules.process_name = sorted(set(rules.process_name))
        rules.process_path_regex = sorted(set(rules.process_path_regex))
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
            elif self._looks_like_domain(item):
                self._add_domain(item, "domain", rules)
            else:
                invalid_count += 1
        rules.domains = sorted(set(rules.domains))
        rules.domain_suffix = sorted(set(rules.domain_suffix))
        rules.ip_cidr = sorted(set(rules.ip_cidr))
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

        if normalized_key in IP_KEYS or self._looks_like_cidr(text):
            self._add_ip(text, rules)
        elif normalized_key in PROCESS_KEYS:
            rules.process_name.append(text)
        elif normalized_key in PROCESS_PATH_KEYS:
            rules.process_path_regex.append(text)
        elif normalized_key in DOMAIN_KEYS or self._looks_like_domain(text):
            self._add_domain(text, normalized_key, rules)

    def _add_domain(self, value: str, key: str, rules: RoutingRuleSet) -> None:
        text = self._clean_domain(value)
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
        text = value.strip().lower()
        text = text.removeprefix("regexp:")
        text = text.removeprefix("geosite:")
        if "://" in text:
            parsed = urlparse(text)
            text = parsed.hostname or ""
        text = text.split("/")[0].strip()
        text = text.removeprefix("*.").removeprefix(".")
        return text

    def _looks_like_domain(self, value: str) -> bool:
        text = self._clean_domain(value)
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
