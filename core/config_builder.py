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

"""Генератор sing-box config.json из профиля, режима и split rules."""

from __future__ import annotations

import os
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.outbound_builder import OutboundBuilder, OutboundBuildError
from models.profile import ServerProfile
from models.rules import (
    ROUTE_OUTBOUNDS,
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    builtin_direct_rule_sets,
    clean_process_names,
    clean_process_path_regexes,
    clean_process_paths,
    normalize_outbound,
    normalize_rule_set_resource_format,
    normalize_rule_set_resource_type,
)
from models.settings import AppSettings, normalize_dns_strategy


class ConfigBuildError(ValueError):
    """Ошибка генерации конфигурации sing-box."""


KARING_WINDOWS_TUN_STACK = "gvisor"
KARING_WINDOWS_TUN_MTU = 4064


class SingBoxConfigBuilder:
    """Собирает валидный конфиг sing-box без ручного редактирования JSON."""

    def __init__(self) -> None:
        self.outbound_builder = OutboundBuilder()

    def build(
        self,
        profile: ServerProfile,
        settings: AppSettings,
        split_rules: SplitRules,
        log_path: Path | None,
    ) -> dict[str, Any]:
        if settings.mode not in {"proxy", "tun"}:
            raise ConfigBuildError("Неизвестный режим подключения")

        try:
            proxy_outbound = self.outbound_builder.build(profile, tag="proxy")
        except OutboundBuildError as exc:
            raise ConfigBuildError(str(exc)) from exc

        dns = self._build_dns(settings, split_rules)
        outbounds = [
            proxy_outbound,
            {
                "type": "direct",
                "tag": "direct",
                "domain_resolver": "bootstrap-dns",
            },
        ]
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

        config: dict[str, Any] = {
            "log": {
                "level": settings.log_level,
                "timestamp": True,
            },
            "dns": dns,
            "inbounds": self._build_inbounds(settings),
            "outbounds": outbounds,
            "route": route,
        }
        # Не задаем sing-box log.output: stdout читает SingBoxManager, а приложение
        # уже сохраняет эти строки в общий лог и live-журнал доменов.
        _ = log_path
        return config

    def build_latency_test_outbound(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        """Собирает outbound с внешним tag для Karing-style delay API."""
        try:
            return self.outbound_builder.build(profile, tag=tag)
        except OutboundBuildError as exc:
            raise ConfigBuildError(str(exc)) from exc

    def _build_dns(self, settings: AppSettings, split_rules: SplitRules) -> dict[str, Any]:
        configured = [str(item).strip() for item in settings.dns_servers if str(item).strip()]
        if not configured:
            configured = ["1.1.1.1", "8.8.8.8"]

        bootstrap_address = configured[0]
        proxy_address = configured[1] if len(configured) > 1 else configured[0]
        servers = [
            self._build_dns_server(bootstrap_address, "bootstrap-dns", preferred_type="udp"),
            self._build_dns_server(proxy_address, "proxy-dns", preferred_type="tcp", detour="proxy"),
        ]
        if settings.mode == "tun":
            fakeip = {
                "type": "fakeip",
                "tag": "fakeip",
                "inet4_range": "198.18.0.0/15",
            }
            if settings.enable_ipv6:
                fakeip["inet6_range"] = "fc00::/18"
            servers.append(fakeip)
        final_server = "bootstrap-dns" if split_rules.effective_default_outbound == ROUTE_OUTBOUND_DIRECT else "proxy-dns"
        return {
            "servers": servers,
            "rules": self._build_dns_rules(settings, split_rules),
            "final": final_server,
            "strategy": normalize_dns_strategy(settings.dns_strategy, ipv6_enabled=settings.enable_ipv6),
            "reverse_mapping": True,
        }

    def _build_dns_rules(self, settings: AppSettings, split_rules: SplitRules) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for rule_set in self._effective_rule_sets(split_rules):
            selector = self._build_dns_rule_selector(
                rule_set,
                use_fakeip=settings.mode == "tun",
                enable_ipv6=settings.enable_ipv6,
            )
            if selector:
                rules.append(selector)
        if settings.mode == "tun":
            default_server = "fakeip" if split_rules.effective_default_outbound == ROUTE_OUTBOUND_PROXY else "bootstrap-dns"
            rules.append({"query_type": self._dns_query_types(settings), "action": "route", "server": default_server})
        return rules

    def _build_dns_rule_selector(
        self,
        rule_set: RoutingRuleSet,
        use_fakeip: bool = False,
        *,
        enable_ipv6: bool = True,
    ) -> dict[str, Any]:
        outbound = normalize_outbound(rule_set.outbound)
        if use_fakeip and outbound == ROUTE_OUTBOUND_PROXY:
            server = "fakeip"
        else:
            server = "proxy-dns" if outbound == ROUTE_OUTBOUND_PROXY else "bootstrap-dns"
        selector: dict[str, Any] = {"action": "route", "server": server}
        if server == "fakeip":
            selector["query_type"] = ["A", "AAAA"] if enable_ipv6 else ["A"]
        if rule_set.domains:
            selector["domain"] = sorted(set(rule_set.domains))
        if rule_set.domain_suffix:
            selector["domain_suffix"] = sorted(set(rule_set.domain_suffix))
        if rule_set.domain_keyword:
            selector["domain_keyword"] = sorted(set(rule_set.domain_keyword))
        if rule_set.domain_regex:
            selector["domain_regex"] = sorted(set(rule_set.domain_regex))
        if rule_set.geosite:
            selector["geosite"] = sorted(set(rule_set.geosite))
        return selector if len(selector) > 2 else {}

    @staticmethod
    def _dns_query_types(settings: AppSettings) -> list[str]:
        return ["A", "AAAA"] if settings.enable_ipv6 else ["A"]

    def _build_dns_server(
        self,
        address: str,
        tag: str,
        preferred_type: str = "udp",
        detour: str | None = None,
    ) -> dict[str, Any]:
        value = str(address or "").strip()
        if not value:
            value = "1.1.1.1"

        if value == "local":
            dns_server = {"type": "local", "tag": tag}
            return self._with_dns_detour(dns_server, detour)

        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme in {"udp", "tcp", "tls", "quic", "https", "h3"}:
            server = parsed.hostname or parsed.netloc or parsed.path
            dns_server: dict[str, Any] = {"type": scheme, "tag": tag, "server": server}
            port = self._parsed_port(parsed)
            if port:
                dns_server["server_port"] = port
            if scheme in {"https", "h3"} and parsed.path and parsed.path != "/":
                dns_server["path"] = parsed.path
            return self._with_dns_detour(dns_server, detour)

        if scheme == "dhcp":
            dns_server = {"type": "dhcp", "tag": tag}
            interface = parsed.netloc or parsed.path
            if interface and interface != "auto":
                dns_server["interface"] = interface
            return self._with_dns_detour(dns_server, detour)

        if scheme == "rcode":
            dns_server = {"type": "rcode", "tag": tag, "rcode": parsed.netloc or parsed.path or "refused"}
            return self._with_dns_detour(dns_server, detour)

        if value == "fakeip":
            dns_server = {"type": "fakeip", "tag": tag}
            return self._with_dns_detour(dns_server, detour)

        server, port = self._split_host_port(value)
        dns_server = {"type": preferred_type, "tag": tag, "server": server}
        if port:
            dns_server["server_port"] = port
        return self._with_dns_detour(dns_server, detour)

    @staticmethod
    def _with_dns_detour(dns_server: dict[str, Any], detour: str | None) -> dict[str, Any]:
        if detour and dns_server.get("type") not in {"local", "dhcp", "fakeip", "rcode"}:
            dns_server["detour"] = detour
        return dns_server

    @staticmethod
    def _split_host_port(value: str) -> tuple[str, int | None]:
        if value.startswith("["):
            host, _, tail = value[1:].partition("]")
            if tail.startswith(":") and tail[1:].isdigit():
                return host, int(tail[1:])
            return host or value, None

        try:
            ip_address(value)
            return value, None
        except ValueError:
            pass

        host, separator, port = value.rpartition(":")
        if separator and host and port.isdigit() and value.count(":") == 1:
            return host, int(port)
        return value, None

    @staticmethod
    def _parsed_port(parsed) -> int | None:
        try:
            return parsed.port
        except ValueError:
            return None

    def _build_inbounds(self, settings: AppSettings) -> list[dict[str, Any]]:
        mixed = {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": settings.mixed_listen_host,
            "listen_port": int(settings.mixed_port),
        }
        if settings.mode == "proxy":
            return [mixed]

        tun_addresses = [settings.tun_address]
        if settings.enable_ipv6 and str(settings.tun_ipv6_address or "").strip():
            tun_addresses.append(str(settings.tun_ipv6_address).strip())

        tun = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": settings.tun_interface_name,
            "address": tun_addresses,
            "mtu": self._tun_mtu(settings),
            "auto_route": True,
            "strict_route": bool(settings.kill_switch),
            "stack": self._tun_stack(),
            "endpoint_independent_nat": True,
        }
        return [tun]

    @staticmethod
    def _tun_stack() -> str:
        if os.name == "nt":
            return KARING_WINDOWS_TUN_STACK
        return "mixed"

    @staticmethod
    def _tun_mtu(settings: AppSettings) -> int:
        try:
            mtu = int(settings.tun_mtu)
        except (TypeError, ValueError):
            mtu = KARING_WINDOWS_TUN_MTU
        if os.name == "nt":
            return min(max(1280, mtu), KARING_WINDOWS_TUN_MTU)
        return max(1280, mtu)

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
        return [self._build_route_rule_set(resource) for resource in split_rules.enabled_rule_set_resources]

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
        if rule_set.domains:
            selector["domain"] = sorted(set(rule_set.domains))
        if rule_set.domain_suffix:
            selector["domain_suffix"] = sorted(set(rule_set.domain_suffix))
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
