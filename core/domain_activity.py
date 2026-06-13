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
DOMAIN_ACTIVITY_SORT_LAST_SEEN = "last_seen"
DOMAIN_ACTIVITY_SORT_HITS = "hits"
DOMAIN_ACTIVITY_SORT_DOMAIN = "domain"
DOMAIN_ACTIVITY_SORT_FIRST_SEEN = "first_seen"
DOMAIN_ACTIVITY_SORT_RULE = "rule"
DOMAIN_ACTIVITY_SORT_MODES = {
    DOMAIN_ACTIVITY_SORT_LAST_SEEN,
    DOMAIN_ACTIVITY_SORT_HITS,
    DOMAIN_ACTIVITY_SORT_DOMAIN,
    DOMAIN_ACTIVITY_SORT_FIRST_SEEN,
    DOMAIN_ACTIVITY_SORT_RULE,
}
DOMAIN_ACTIVITY_RULE_FILTER_ALL = "all"
DOMAIN_ACTIVITY_RULE_FILTER_MATCHED = "matched"
DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT = "default"
DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT = "explicit"
DOMAIN_ACTIVITY_RULE_FILTERS = {
    DOMAIN_ACTIVITY_RULE_FILTER_ALL,
    DOMAIN_ACTIVITY_RULE_FILTER_MATCHED,
    DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT,
    DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT,
}


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


@dataclass(slots=True)
class DomainActivitySummary:
    total_domains: int = 0
    total_hits: int = 0
    proxy_domains: int = 0
    direct_domains: int = 0
    proxy_hits: int = 0
    direct_hits: int = 0

    @property
    def proxy_hit_percent(self) -> int:
        if self.total_hits <= 0:
            return 0
        return round((self.proxy_hits / self.total_hits) * 100)

    @property
    def direct_hit_percent(self) -> int:
        if self.total_hits <= 0:
            return 0
        return round((self.direct_hits / self.total_hits) * 100)


def summarize_domain_activity(entries: list[DomainActivityEntry]) -> DomainActivitySummary:
    summary = DomainActivitySummary(total_domains=len(entries))
    for entry in entries:
        hits = max(0, int(entry.hits))
        summary.total_hits += hits
        if entry.route == ROUTE_OUTBOUND_PROXY:
            summary.proxy_domains += 1
            summary.proxy_hits += hits
        else:
            summary.direct_domains += 1
            summary.direct_hits += hits
    return summary


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

    def snapshot(
        self,
        query: str = "",
        route_filter: str = "all",
        rule_filter: str = DOMAIN_ACTIVITY_RULE_FILTER_ALL,
        sort_mode: str = DOMAIN_ACTIVITY_SORT_LAST_SEEN,
    ) -> list[DomainActivityEntry]:
        query = query.strip().lower()
        route_filter = normalize_outbound(route_filter) if route_filter in {ROUTE_OUTBOUND_PROXY, ROUTE_OUTBOUND_DIRECT} else "all"
        rule_filter = rule_filter if rule_filter in DOMAIN_ACTIVITY_RULE_FILTERS else DOMAIN_ACTIVITY_RULE_FILTER_ALL
        sort_mode = sort_mode if sort_mode in DOMAIN_ACTIVITY_SORT_MODES else DOMAIN_ACTIVITY_SORT_LAST_SEEN
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            entries = list(self._entries.values())
        if query:
            words = [word for word in query.split() if word]
            entries = [
                entry
                for entry in entries
                if all(self._entry_matches_query(entry, word) for word in words)
            ]
        if route_filter != "all":
            entries = [entry for entry in entries if entry.route == route_filter]
        if rule_filter != DOMAIN_ACTIVITY_RULE_FILTER_ALL:
            entries = [entry for entry in entries if self._entry_matches_rule_filter(entry, rule_filter)]
        return self._sort_entries(entries, sort_mode)

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

    @staticmethod
    def _entry_matches_query(entry: DomainActivityEntry, word: str) -> bool:
        return (
            word in entry.domain
            or word in entry.rule_name.lower()
            or word in entry.route_label.lower()
            or word in entry.route.lower()
        )

    @staticmethod
    def _entry_matches_rule_filter(entry: DomainActivityEntry, rule_filter: str) -> bool:
        rule_name = entry.rule_name.strip().lower()
        if rule_filter == DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT:
            return rule_name == "маршрут по умолчанию"
        if rule_filter == DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT:
            return rule_name == "sing-box"
        if rule_filter == DOMAIN_ACTIVITY_RULE_FILTER_MATCHED:
            return rule_name not in {"маршрут по умолчанию", "sing-box"}
        return True

    @staticmethod
    def _sort_entries(entries: list[DomainActivityEntry], sort_mode: str) -> list[DomainActivityEntry]:
        if sort_mode == DOMAIN_ACTIVITY_SORT_HITS:
            return sorted(entries, key=lambda entry: (-entry.hits, entry.domain))
        if sort_mode == DOMAIN_ACTIVITY_SORT_DOMAIN:
            return sorted(entries, key=lambda entry: entry.domain)
        if sort_mode == DOMAIN_ACTIVITY_SORT_FIRST_SEEN:
            return sorted(entries, key=lambda entry: (entry.first_seen, entry.domain))
        if sort_mode == DOMAIN_ACTIVITY_SORT_RULE:
            return sorted(entries, key=lambda entry: (entry.rule_name.lower(), entry.domain))
        return sorted(entries, key=lambda entry: entry.last_seen, reverse=True)

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
        clean_domain = domain.strip().lower().strip(".")
        exact_domains = {item.strip().lower().strip(".") for item in rule_set.domains}
        if clean_domain in exact_domains:
            return True
        for suffix in rule_set.domain_suffix:
            clean = suffix.strip().lower().removeprefix("*.").removeprefix(".")
            if clean_domain == clean or clean_domain.endswith(f".{clean}"):
                return True
        for keyword in rule_set.domain_keyword:
            if keyword.strip().lower() in clean_domain:
                return True
        for pattern in rule_set.domain_regex:
            try:
                if re.search(pattern, clean_domain, re.IGNORECASE):
                    return True
            except re.error:
                continue
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
