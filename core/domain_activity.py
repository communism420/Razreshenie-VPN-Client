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

"""Live-журнал доменов из runtime-логов sing-box."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from threading import RLock

from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RoutingRuleSet,
    SplitRules,
    builtin_direct_rule_sets,
    normalize_outbound,
)


DOMAIN_RE = re.compile(
    r"(?<![a-z0-9_-])"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
    r"(?![a-z0-9_-])",
    re.IGNORECASE,
)

OUTBOUND_RE = re.compile(
    r"(?:outbound[/=\s:]+(?:[a-z0-9_-]+\[)?|detour[/=\s:]+|=>\s*)"
    r"(?P<route>proxy|direct)\]?",
    re.IGNORECASE,
)

IGNORED_DOMAINS: set[str] = set()


@dataclass(slots=True)
class DomainActivityEntry:
    domain: str
    route: str
    rule_name: str
    first_seen: float
    last_seen: float
    hits: int = 1

    @property
    def route_label(self) -> str:
        return "VPN" if self.route == ROUTE_OUTBOUND_PROXY else "Напрямую"

    @property
    def last_seen_label(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.last_seen))

    @property
    def first_seen_label(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.first_seen))


class DomainActivityTracker:
    """Хранит свежие домены, которые sing-box упоминал в runtime-логах."""

    def __init__(self, max_entries: int = 1000, max_age_seconds: int = 900) -> None:
        self.max_entries = max_entries
        self.max_age_seconds = max_age_seconds
        self._entries: dict[str, DomainActivityEntry] = {}
        self._lock = RLock()

    def ingest_log_line(self, message: str, split_rules: SplitRules) -> bool:
        if "[sing-box]" not in message:
            return False
        domains = self._extract_domains(message)
        if not domains:
            return False
        now = time.time()
        explicit_route = self._route_from_line(message)
        changed = False
        with self._lock:
            self._prune_locked(now)
            for domain in domains:
                route, rule_name = self._classify_domain(domain, split_rules)
                if explicit_route:
                    route = explicit_route
                    if rule_name == "Маршрут по умолчанию":
                        rule_name = "sing-box"
                current = self._entries.get(domain)
                if current:
                    current.route = route
                    current.rule_name = rule_name
                    current.last_seen = now
                    current.hits += 1
                else:
                    self._entries[domain] = DomainActivityEntry(
                        domain=domain,
                        route=route,
                        rule_name=rule_name,
                        first_seen=now,
                        last_seen=now,
                    )
                changed = True
            self._trim_locked()
        return changed

    def refresh_routes(self, split_rules: SplitRules) -> None:
        with self._lock:
            for entry in self._entries.values():
                entry.route, entry.rule_name = self._classify_domain(entry.domain, split_rules)

    def snapshot(self, query: str = "", route_filter: str = "all") -> list[DomainActivityEntry]:
        query = query.strip().lower()
        route_filter = normalize_outbound(route_filter) if route_filter in {ROUTE_OUTBOUND_PROXY, ROUTE_OUTBOUND_DIRECT} else "all"
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            entries = list(self._entries.values())
        if query:
            words = [word for word in query.split() if word]
            entries = [entry for entry in entries if all(word in entry.domain for word in words)]
        if route_filter != "all":
            entries = [entry for entry in entries if entry.route == route_filter]
        return sorted(entries, key=lambda entry: entry.last_seen, reverse=True)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def _extract_domains(self, message: str) -> list[str]:
        lower = message.lower()
        domains = []
        for match in DOMAIN_RE.finditer(lower):
            domain = match.group(1).strip(".")
            if domain in IGNORED_DOMAINS:
                continue
            if domain.startswith(("127.", "10.", "192.168.")):
                continue
            domains.append(domain)
        return sorted(set(domains))

    def _route_from_line(self, message: str) -> str | None:
        lower = message.lower()
        match = OUTBOUND_RE.search(lower)
        if match:
            return normalize_outbound(match.group("route"))
        if "outbound/direct" in lower or "[direct]" in lower:
            return ROUTE_OUTBOUND_DIRECT
        if "outbound/vless" in lower or "[proxy]" in lower:
            return ROUTE_OUTBOUND_PROXY
        return None

    def _classify_domain(self, domain: str, split_rules: SplitRules) -> tuple[str, str]:
        for rule_set in [*split_rules.enabled_rule_sets, *builtin_direct_rule_sets()]:
            if self._matches_rule_set(domain, rule_set):
                return normalize_outbound(rule_set.outbound), rule_set.name
        return split_rules.effective_default_outbound, "Маршрут по умолчанию"

    def _matches_rule_set(self, domain: str, rule_set: RoutingRuleSet) -> bool:
        if domain in set(rule_set.domains):
            return True
        for suffix in rule_set.domain_suffix:
            clean = suffix.strip().lower().removeprefix("*.").removeprefix(".")
            if domain == clean or domain.endswith(f".{clean}"):
                return True
        for keyword in rule_set.domain_keyword:
            if keyword.strip().lower() in domain:
                return True
        return False

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.max_age_seconds
        self._entries = {
            domain: entry
            for domain, entry in self._entries.items()
            if entry.last_seen >= cutoff
        }

    def _trim_locked(self) -> None:
        if len(self._entries) <= self.max_entries:
            return
        keep = sorted(self._entries.values(), key=lambda entry: entry.last_seen, reverse=True)[: self.max_entries]
        self._entries = {entry.domain: entry for entry in keep}
