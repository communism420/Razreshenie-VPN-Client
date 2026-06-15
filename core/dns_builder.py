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

"""DNS and FakeIP section builder for sing-box configs."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RoutingRuleSet,
    SplitRules,
    builtin_direct_rule_sets,
    effective_rule_domain_suffixes,
    effective_rule_domains,
    normalize_outbound,
)
from models.settings import AppSettings, normalize_dns_strategy


class DnsBuilder:
    """Builds the sing-box DNS section from app settings and route rules."""

    def build(self, settings: AppSettings, split_rules: SplitRules) -> dict[str, Any]:
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
        domains = effective_rule_domains(rule_set)
        domain_suffix = effective_rule_domain_suffixes(rule_set)
        has_domain_selector = any(
            (
                domains,
                domain_suffix,
                rule_set.domain_keyword,
                rule_set.domain_regex,
                rule_set.geosite,
            )
        )
        if use_fakeip and has_domain_selector:
            server = "fakeip"
        else:
            server = "proxy-dns" if outbound == ROUTE_OUTBOUND_PROXY else "bootstrap-dns"
        selector: dict[str, Any] = {"action": "route", "server": server}
        if server == "fakeip":
            selector["query_type"] = ["A", "AAAA"] if enable_ipv6 else ["A"]
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
        return selector if len(selector) > 2 else {}

    @staticmethod
    def _effective_rule_sets(split_rules: SplitRules) -> list[RoutingRuleSet]:
        return [*split_rules.enabled_rule_sets, *builtin_direct_rule_sets()]

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
