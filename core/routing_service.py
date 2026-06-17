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

"""State mutations for split-tunneling rules."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from core.rules_manager import RulesImportResult
from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    domain_site_suffix,
    normalize_outbound,
)


MATCH_KIND_PROCESS_NAME = "process_name"
MATCH_KIND_PROCESS_PATH = "process_path"
MATCH_KIND_PROCESS_PATH_REGEX = "process_path_regex"
LIVE_ACTIVITY_RULE_SOURCE_TYPE = "live_activity"
LIVE_ACTIVITY_RULE_SOURCE = "Live Activity"
PER_APP_RULE_SOURCE_TYPE = "per_app"
PER_APP_RULE_SOURCE = "Per-app routing"


class RoutingServiceError(ValueError):
    """Invalid routing mutation request."""


@dataclass(frozen=True, slots=True)
class RoutingMutationResult:
    changed: bool
    selected_rule_id: str = ""
    status_level: str = "success"
    status_message: str = ""
    restart_required: bool = False


class RoutingService:
    def add_import_result(self, split_rules: SplitRules, result: RulesImportResult) -> RoutingMutationResult:
        if not result.rule_sets:
            raise RoutingServiceError("Импорт не вернул правил маршрутизации")
        self._append_rule_set_resources(split_rules, result.rule_set_resources)
        for rule_set in result.rule_sets:
            rule_set.priority = self._next_rule_priority(split_rules)
            split_rules.rule_sets.append(rule_set)
        split_rules.enabled = True
        resource_count = len(result.rule_set_resources)
        resource_text = f" · resources: {resource_count}" if resource_count else ""
        item_count = sum(rule_set.total_items for rule_set in result.rule_sets)
        return RoutingMutationResult(
            changed=True,
            selected_rule_id=result.rule_sets[0].id,
            status_message=f"Добавлены правила: {len(result.rule_sets)} · элементов: {item_count}{resource_text}",
            restart_required=True,
        )

    def upsert_per_app_rule(
        self,
        split_rules: SplitRules,
        *,
        name: str,
        outbound: str,
        match_kind: str,
        value: str,
    ) -> RoutingMutationResult:
        normalized_rule = self._build_per_app_rule(split_rules, name, outbound, match_kind, value)
        if not normalized_rule:
            raise RoutingServiceError("Не удалось нормализовать правило приложения")

        existing = self._find_per_app_rule(split_rules, match_kind, value)
        if existing:
            self._apply_per_app_match(existing, match_kind, value)
            existing.name = name
            existing.outbound = normalize_outbound(outbound)
            existing.enabled = True
            existing.source_type = PER_APP_RULE_SOURCE_TYPE
            existing.source = PER_APP_RULE_SOURCE
            target_rule = RoutingRuleSet.from_dict(existing.to_dict())
            split_rules.rule_sets = [
                target_rule if item.id == existing.id else item
                for item in split_rules.rule_sets
            ]
            status = "обновлено"
        else:
            split_rules.rule_sets.append(normalized_rule)
            target_rule = normalized_rule
            status = "создано"

        split_rules.enabled = True
        return RoutingMutationResult(
            changed=True,
            selected_rule_id=target_rule.id,
            status_message=f"Per-app routing: {status}: {target_rule.name} -> {target_rule.outbound_label}",
            restart_required=True,
        )

    def set_rule_set_outbound(
        self,
        split_rules: SplitRules,
        rule_set_id: str,
        outbound: str,
    ) -> RoutingMutationResult:
        rule_set = self.rule_set_by_id(split_rules, rule_set_id)
        if not rule_set:
            return RoutingMutationResult(False)
        rule_set.outbound = normalize_outbound(outbound)
        split_rules.enabled = any(item.enabled for item in split_rules.rule_sets)
        return RoutingMutationResult(
            changed=True,
            status_message=f"{rule_set.name}: {rule_set.outbound_label}",
            restart_required=True,
        )

    def set_rule_set_enabled(
        self,
        split_rules: SplitRules,
        rule_set_id: str,
        enabled: bool,
    ) -> RoutingMutationResult:
        rule_set = self.rule_set_by_id(split_rules, rule_set_id)
        if not rule_set:
            return RoutingMutationResult(False)
        rule_set.enabled = bool(enabled)
        split_rules.enabled = any(item.enabled for item in split_rules.rule_sets)
        return RoutingMutationResult(changed=True, restart_required=True)

    def toggle_rule_set(self, split_rules: SplitRules, rule_set_id: str) -> RoutingMutationResult:
        rule_set = self.rule_set_by_id(split_rules, rule_set_id)
        if not rule_set:
            return RoutingMutationResult(False)
        return self.set_rule_set_enabled(split_rules, rule_set_id, not rule_set.enabled)

    def move_rule_set(self, split_rules: SplitRules, rule_set_id: str, direction: int) -> RoutingMutationResult:
        ordered = self._ordered_rule_sets(split_rules)
        current_index = next((index for index, item in enumerate(ordered) if item.id == rule_set_id), None)
        if current_index is None:
            return RoutingMutationResult(False)
        target_index = current_index + int(direction)
        if target_index < 0 or target_index >= len(ordered):
            return RoutingMutationResult(False)
        ordered[current_index], ordered[target_index] = ordered[target_index], ordered[current_index]
        split_rules.rule_sets = ordered
        self._renumber_rule_priorities(split_rules)
        return RoutingMutationResult(changed=True, selected_rule_id=rule_set_id, restart_required=True)

    def delete_rule_set(self, split_rules: SplitRules, rule_set_id: str) -> RoutingMutationResult:
        rule_set = self.rule_set_by_id(split_rules, rule_set_id)
        if not rule_set:
            return RoutingMutationResult(False)
        split_rules.rule_sets = [item for item in split_rules.rule_sets if item.id != rule_set_id]
        self._prune_unused_rule_set_resources(split_rules)
        split_rules.enabled = any(item.enabled for item in split_rules.rule_sets)
        return RoutingMutationResult(changed=True, restart_required=True)

    def clear_rule_sets(self, split_rules: SplitRules) -> RoutingMutationResult:
        if not split_rules.rule_sets and not split_rules.rule_set_resources:
            return RoutingMutationResult(False)
        split_rules.enabled = False
        split_rules.default_outbound = ROUTE_OUTBOUND_PROXY
        split_rules.rule_sets = []
        split_rules.rule_set_resources = []
        return RoutingMutationResult(changed=True, restart_required=True)

    def add_activity_rule(
        self,
        split_rules: SplitRules,
        *,
        domain: str,
        match_kind: str,
        outbound: str,
    ) -> RoutingMutationResult:
        clean_domain = self.normalize_activity_domain(domain)
        if not clean_domain:
            raise RoutingServiceError("Не удалось создать правило: домен не распознан")

        normalized_outbound = normalize_outbound(outbound)
        rule_set, created = self._activity_rule_set(split_rules, normalized_outbound)
        target_values, rule_value, label = self._activity_rule_target(rule_set, clean_domain, match_kind)
        was_enabled = rule_set.enabled and split_rules.enabled
        if rule_value.lower() in {item.lower() for item in target_values}:
            if not was_enabled:
                rule_set.enabled = True
                rule_set.outbound = normalized_outbound
                split_rules.enabled = True
                return RoutingMutationResult(
                    changed=True,
                    selected_rule_id=rule_set.id,
                    status_message=f"Live Activity: правило включено: {rule_value}",
                    restart_required=True,
                )
            return RoutingMutationResult(
                changed=False,
                selected_rule_id=rule_set.id,
                status_level="info",
                status_message=f"Правило уже есть: {rule_value}",
            )

        rule_set.enabled = True
        rule_set.outbound = normalized_outbound
        target_values.append(rule_value)
        target_values.sort(key=str.lower)
        split_rules.enabled = True
        created_text = "создан набор, " if created else ""
        return RoutingMutationResult(
            changed=True,
            selected_rule_id=rule_set.id,
            status_message=f"Live Activity: {created_text}{label} {rule_value} -> {rule_set.outbound_label}",
            restart_required=True,
        )

    @staticmethod
    def rule_set_by_id(split_rules: SplitRules, rule_set_id: str) -> RoutingRuleSet | None:
        return next((item for item in split_rules.rule_sets if item.id == rule_set_id), None)

    @staticmethod
    def ordered_rule_sets(split_rules: SplitRules) -> list[RoutingRuleSet]:
        return RoutingService._ordered_rule_sets(split_rules)

    def _build_per_app_rule(
        self,
        split_rules: SplitRules,
        name: str,
        outbound: str,
        match_kind: str,
        value: str,
    ) -> RoutingRuleSet | None:
        rule_set = RoutingRuleSet(
            name=name,
            enabled=True,
            outbound=normalize_outbound(outbound),
            source_type=PER_APP_RULE_SOURCE_TYPE,
            source=PER_APP_RULE_SOURCE,
            priority=self._next_rule_priority(split_rules),
        )
        if not self._apply_per_app_match(rule_set, match_kind, value):
            return None
        normalized = RoutingRuleSet.from_dict(rule_set.to_dict())
        return normalized if not normalized.is_empty else None

    @staticmethod
    def _apply_per_app_match(rule_set: RoutingRuleSet, match_kind: str, value: str) -> bool:
        clean_value = str(value or "").strip()
        if not clean_value:
            return False
        rule_set.process_name = []
        rule_set.process_path = []
        rule_set.process_path_regex = []
        if match_kind == MATCH_KIND_PROCESS_NAME:
            rule_set.process_name = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH:
            rule_set.process_path = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            rule_set.process_path_regex = [clean_value]
        else:
            return False
        return True

    def _find_per_app_rule(
        self,
        split_rules: SplitRules,
        match_kind: str,
        value: str,
    ) -> RoutingRuleSet | None:
        target = str(value or "").strip().casefold()
        if not target:
            return None
        for rule_set in split_rules.rule_sets:
            if rule_set.source_type != PER_APP_RULE_SOURCE_TYPE:
                continue
            values = self._per_app_values(rule_set, match_kind)
            if target in {item.casefold() for item in values}:
                return rule_set
        return None

    @staticmethod
    def _per_app_values(rule_set: RoutingRuleSet, match_kind: str) -> list[str]:
        if match_kind == MATCH_KIND_PROCESS_NAME:
            return rule_set.process_name
        if match_kind == MATCH_KIND_PROCESS_PATH:
            return rule_set.process_path
        if match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            return rule_set.process_path_regex
        return []

    @staticmethod
    def _append_rule_set_resources(split_rules: SplitRules, resources: list[RouteRuleSetResource]) -> None:
        if not resources:
            return
        by_tag = {resource.tag: resource for resource in split_rules.rule_set_resources if resource.tag}
        for resource in resources:
            if not resource.tag:
                continue
            by_tag[resource.tag] = resource
        split_rules.rule_set_resources = list(by_tag.values())

    @staticmethod
    def _next_rule_priority(split_rules: SplitRules) -> int:
        if not split_rules.rule_sets:
            return 1000
        return max((rule_set.priority for rule_set in split_rules.rule_sets), default=990) + 10

    @staticmethod
    def _ordered_rule_sets(split_rules: SplitRules) -> list[RoutingRuleSet]:
        return [
            item
            for _index, item in sorted(
                enumerate(split_rules.rule_sets),
                key=lambda pair: (pair[1].priority, pair[0]),
            )
        ]

    @staticmethod
    def _renumber_rule_priorities(split_rules: SplitRules) -> None:
        for index, rule_set in enumerate(split_rules.rule_sets, start=1):
            rule_set.priority = index * 10

    @staticmethod
    def _prune_unused_rule_set_resources(split_rules: SplitRules) -> None:
        used_tags = {
            tag
            for rule_set in split_rules.rule_sets
            for tag in rule_set.rule_set_tags
        }
        split_rules.rule_set_resources = [
            resource
            for resource in split_rules.rule_set_resources
            if resource.tag in used_tags
        ]

    def _activity_rule_set(self, split_rules: SplitRules, outbound: str) -> tuple[RoutingRuleSet, bool]:
        normalized_outbound = normalize_outbound(outbound)
        for rule_set in split_rules.rule_sets:
            if (
                rule_set.source_type == LIVE_ACTIVITY_RULE_SOURCE_TYPE
                and normalize_outbound(rule_set.outbound) == normalized_outbound
            ):
                return rule_set, False

        route_name = "напрямую" if normalized_outbound == ROUTE_OUTBOUND_DIRECT else "через VPN"
        rule_set = RoutingRuleSet(
            name=f"Live Activity: {route_name}",
            enabled=True,
            outbound=normalized_outbound,
            source_type=LIVE_ACTIVITY_RULE_SOURCE_TYPE,
            source=LIVE_ACTIVITY_RULE_SOURCE,
            priority=self._activity_rule_priority(split_rules, normalized_outbound),
        )
        split_rules.rule_sets.append(rule_set)
        return rule_set, True

    @staticmethod
    def _activity_rule_priority(split_rules: SplitRules, outbound: str) -> int:
        used_priorities = {rule_set.priority for rule_set in split_rules.rule_sets}
        priority = 100 if normalize_outbound(outbound) == ROUTE_OUTBOUND_DIRECT else 110
        while priority in used_priorities:
            priority += 1
        return priority

    @staticmethod
    def _activity_rule_target(
        rule_set: RoutingRuleSet,
        domain: str,
        match_kind: str,
    ) -> tuple[list[str], str, str]:
        if match_kind == "domain_suffix":
            return rule_set.domain_suffix, domain_site_suffix(domain), "зона"
        return rule_set.domains, domain, "домен"

    @staticmethod
    def normalize_activity_domain(domain: str) -> str:
        text = str(domain or "").strip().lower().strip(".")
        if "://" in text:
            text = urlparse(text).hostname or ""
        text = text.strip().strip(".")
        if not text or "." not in text:
            return ""
        if any(char.isspace() for char in text):
            return ""
        return text
