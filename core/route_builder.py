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

"""Route and route.rule_set section builder for sing-box configs."""

from __future__ import annotations

from typing import Any

from core.config_errors import ConfigBuildError
from models.rules import (
    ROUTE_OUTBOUNDS,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    builtin_direct_rule_sets,
    clean_process_names,
    clean_process_path_regexes,
    clean_process_paths,
    effective_rule_domain_suffixes,
    effective_rule_domains,
    normalize_outbound,
    normalize_rule_set_resource_format,
    normalize_rule_set_resource_type,
)


class RouteBuilder:
    """Builds sing-box route rules and external rule-set resources."""

    def build(self, split_rules: SplitRules) -> dict[str, Any]:
        route_rule_sets = self._build_route_rule_sets(split_rules)
        available_rule_set_tags = {item["tag"] for item in route_rule_sets}
        route_rules, final_outbound = self._build_route_rules(split_rules, available_rule_set_tags)
        route: dict[str, Any] = {
            "auto_detect_interface": True,
            "default_domain_resolver": "proxy-dns",
            "rules": route_rules,
            "final": final_outbound,
        }
        if route_rule_sets:
            route["rule_set"] = route_rule_sets
        return route

    def _build_route_rules(
        self,
        split_rules: SplitRules,
        available_rule_set_tags: set[str],
    ) -> tuple[list[dict[str, Any]], str]:
        rules: list[dict[str, Any]] = [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
        ]
        for rule_set in self._effective_rule_sets(split_rules):
            selector = self._build_rule_selector(rule_set, available_rule_set_tags)
            if selector:
                rules.append(selector)
        rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})
        return rules, split_rules.effective_default_outbound

    @staticmethod
    def _effective_rule_sets(split_rules: SplitRules) -> list[RoutingRuleSet]:
        """Пользовательские правила имеют приоритет над встроенными bypass-правилами."""
        return [*split_rules.enabled_rule_sets, *builtin_direct_rule_sets()]

    def _build_route_rule_sets(self, split_rules: SplitRules) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen_tags: dict[str, str] = {}
        for resource in split_rules.enabled_rule_set_resources:
            route_rule_set = self._build_route_rule_set(resource)
            tag = str(route_rule_set.get("tag") or "").strip()
            existing_name = seen_tags.get(tag)
            if existing_name is not None:
                # sing-box route.rule_set tags являются глобальными в config.
                # Дубликат tag сделал бы rule_set ссылки неоднозначными.
                raise ConfigBuildError(
                    f"Route rule-set tag '{tag}' используется повторно: {existing_name}, {resource.name}"
                )
            seen_tags[tag] = resource.name
            result.append(route_rule_set)
        return result

    def _build_route_rule_set(self, resource: RouteRuleSetResource) -> dict[str, Any]:
        resource_type = normalize_rule_set_resource_type(resource.type)
        tag = str(resource.tag or "").strip()
        if not tag:
            raise ConfigBuildError(f"У ruleset '{resource.name}' не задан tag")

        result: dict[str, Any] = {"type": resource_type, "tag": tag}
        if resource_type == "inline":
            if not resource.rules:
                raise ConfigBuildError(f"Inline ruleset '{resource.name}' пуст")
            result["rules"] = resource.rules
            return result

        result["format"] = normalize_rule_set_resource_format(
            resource.format,
            resource.path or resource.url or resource.source,
        )
        if resource_type == "remote":
            if not resource.url:
                raise ConfigBuildError(f"Remote ruleset '{resource.name}' не содержит URL")
            result["url"] = resource.url
            if resource.update_interval:
                result["update_interval"] = resource.update_interval
            return result

        if not resource.path:
            raise ConfigBuildError(f"Local ruleset '{resource.name}' не содержит путь")
        result["path"] = resource.path
        return result

    def _build_rule_selector(
        self,
        rule_set: RoutingRuleSet,
        available_rule_set_tags: set[str],
    ) -> dict[str, Any]:
        outbound = normalize_outbound(rule_set.outbound)
        if outbound not in ROUTE_OUTBOUNDS:
            raise ConfigBuildError(f"Неизвестный маршрут ruleset '{rule_set.name}'")

        selector: dict[str, Any] = {"action": "route", "outbound": outbound}
        domains = effective_rule_domains(rule_set)
        domain_suffix = effective_rule_domain_suffixes(rule_set)
        if domains:
            selector["domain"] = domains
        if domain_suffix:
            selector["domain_suffix"] = domain_suffix
        if rule_set.domain_keyword:
            selector["domain_keyword"] = sorted(set(rule_set.domain_keyword))
        if rule_set.domain_regex:
            selector["domain_regex"] = sorted(set(rule_set.domain_regex))
        if rule_set.geosite:
            selector["geosite"] = sorted(set(rule_set.geosite))
        if rule_set.geoip:
            selector["geoip"] = sorted(set(rule_set.geoip))
        if rule_set.ip_cidr:
            selector["ip_cidr"] = sorted(set(rule_set.ip_cidr))
        process_name = clean_process_names(rule_set.process_name)
        if process_name:
            selector["process_name"] = process_name
        process_path = clean_process_paths(rule_set.process_path)
        if process_path:
            selector["process_path"] = process_path
        process_path_regex = clean_process_path_regexes(rule_set.process_path_regex)
        if process_path_regex:
            selector["process_path_regex"] = process_path_regex
        if rule_set.rule_set_tags:
            rule_set_tags = sorted(set(rule_set.rule_set_tags))
            missing = [tag for tag in rule_set_tags if tag not in available_rule_set_tags]
            if missing:
                raise ConfigBuildError(f"Ruleset '{rule_set.name}' ссылается на неизвестный route.rule_set: {', '.join(missing)}")
            selector["rule_set"] = rule_set_tags
            if rule_set.rule_set_ip_cidr_match_source:
                selector["rule_set_ip_cidr_match_source"] = True
        return selector if len(selector) > 2 else {}
