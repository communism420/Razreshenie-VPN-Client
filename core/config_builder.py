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

from pathlib import Path
from typing import Any

from models.profile import VlessProfile
from models.rules import ROUTE_OUTBOUNDS, ROUTE_OUTBOUND_PROXY, RoutingRuleSet, SplitRules, normalize_outbound
from models.settings import AppSettings


class ConfigBuildError(ValueError):
    """Ошибка генерации конфигурации sing-box."""


def _truthy(value: str | None) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class SingBoxConfigBuilder:
    """Собирает валидный конфиг sing-box без ручного редактирования JSON."""

    def build(
        self,
        profile: VlessProfile,
        settings: AppSettings,
        split_rules: SplitRules,
        log_path: Path | None,
    ) -> dict[str, Any]:
        if settings.mode not in {"proxy", "tun"}:
            raise ConfigBuildError("Неизвестный режим подключения")

        outbounds = [
            self._build_vless_outbound(profile),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ]
        route_rules, final_outbound = self._build_route_rules(split_rules)

        config: dict[str, Any] = {
            "log": {
                "level": settings.log_level,
                "timestamp": True,
            },
            "dns": self._build_dns(settings),
            "inbounds": self._build_inbounds(settings),
            "outbounds": outbounds,
            "route": {
                "auto_detect_interface": True,
                "rules": route_rules,
                "final": final_outbound,
            },
        }
        # Не задаем sing-box log.output: stdout читает SingBoxManager, а приложение
        # уже сохраняет эти строки в общий лог и live-журнал доменов.
        _ = log_path
        return config

    def _param(self, profile: VlessProfile, *names: str) -> str | None:
        lower_map = {key.lower(): value for key, value in profile.params.items()}
        for name in names:
            value = lower_map.get(name.lower())
            if value is not None and value != "":
                return value
        return None

    def _build_vless_outbound(self, profile: VlessProfile) -> dict[str, Any]:
        outbound: dict[str, Any] = {
            "type": "vless",
            "tag": "proxy",
            "server": profile.address,
            "server_port": int(profile.port),
            "uuid": profile.uuid,
        }

        flow = self._param(profile, "flow")
        if flow:
            outbound["flow"] = flow

        packet_encoding = self._param(profile, "packetEncoding", "packet_encoding")
        if packet_encoding:
            outbound["packet_encoding"] = packet_encoding

        tls = self._build_tls(profile)
        if tls:
            outbound["tls"] = tls

        transport = self._build_transport(profile)
        if transport:
            outbound["transport"] = transport

        multiplex = self._build_multiplex(profile)
        if multiplex:
            outbound["multiplex"] = multiplex

        return outbound

    def _build_tls(self, profile: VlessProfile) -> dict[str, Any] | None:
        security = (self._param(profile, "security") or "none").lower()
        if security not in {"tls", "reality"}:
            return None

        tls: dict[str, Any] = {"enabled": True}
        server_name = self._param(profile, "sni", "serverName", "server_name") or profile.address
        if server_name:
            tls["server_name"] = server_name

        alpn = _split_csv(self._param(profile, "alpn"))
        if alpn:
            tls["alpn"] = alpn

        fingerprint = self._param(profile, "fp", "fingerprint")
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

        if _truthy(self._param(profile, "allowInsecure", "allow_insecure", "insecure")):
            tls["insecure"] = True

        if security == "reality":
            public_key = self._param(profile, "pbk", "publicKey", "public_key")
            if not public_key:
                raise ConfigBuildError("VLESS Reality требует параметр pbk/publicKey")
            reality: dict[str, Any] = {"enabled": True, "public_key": public_key}
            short_id = self._param(profile, "sid", "shortId", "short_id")
            spider_x = self._param(profile, "spx", "spiderX", "spider_x")
            if short_id:
                reality["short_id"] = short_id
            if spider_x:
                reality["spider_x"] = spider_x
            tls["reality"] = reality

        return tls

    def _build_transport(self, profile: VlessProfile) -> dict[str, Any] | None:
        network = (self._param(profile, "type", "network") or "tcp").lower()
        path = self._param(profile, "path")
        host = self._param(profile, "host", "authority")

        if network in {"tcp", "raw"}:
            header_type = (self._param(profile, "headerType", "header_type") or "").lower()
            if header_type == "http":
                transport: dict[str, Any] = {"type": "http"}
                if host:
                    transport["host"] = _split_csv(host) or [host]
                if path:
                    transport["path"] = path
                return transport
            return None

        if network in {"ws", "websocket"}:
            transport = {"type": "ws"}
            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
            return transport

        if network in {"grpc", "gun"}:
            service_name = self._param(profile, "serviceName", "service_name") or ""
            return {"type": "grpc", "service_name": service_name}

        if network in {"http", "h2"}:
            transport = {"type": "http"}
            if host:
                transport["host"] = _split_csv(host) or [host]
            if path:
                transport["path"] = path
            return transport

        if network in {"quic"}:
            return {"type": "quic"}

        if network in {"httpupgrade", "http_upgrade"}:
            transport = {"type": "httpupgrade"}
            if host:
                transport["host"] = host
            if path:
                transport["path"] = path
            return transport

        raise ConfigBuildError(f"Транспорт VLESS '{network}' пока не поддержан генератором sing-box")

    def _build_multiplex(self, profile: VlessProfile) -> dict[str, Any] | None:
        if not _truthy(self._param(profile, "mux", "multiplex")):
            return None
        protocol = self._param(profile, "muxProtocol", "mux_protocol") or "smux"
        max_connections = self._param(profile, "muxMaxConnections", "mux_max_connections")
        multiplex: dict[str, Any] = {"enabled": True, "protocol": protocol}
        if max_connections and max_connections.isdigit():
            multiplex["max_connections"] = int(max_connections)
        return multiplex

    def _build_dns(self, settings: AppSettings) -> dict[str, Any]:
        servers = []
        for index, address in enumerate(settings.dns_servers or ["1.1.1.1"]):
            servers.append({"tag": f"dns-{index}", "address": address, "detour": "direct"})
        return {
            "servers": servers,
            "final": servers[0]["tag"],
            "strategy": "prefer_ipv4",
        }

    def _build_inbounds(self, settings: AppSettings) -> list[dict[str, Any]]:
        mixed = {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": settings.mixed_listen_host,
            "listen_port": int(settings.mixed_port),
            "sniff": True,
            "sniff_override_destination": True,
        }
        if settings.mode == "proxy":
            return [mixed]

        tun = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": settings.tun_interface_name,
            "address": [settings.tun_address],
            "mtu": int(settings.tun_mtu),
            "auto_route": True,
            "strict_route": bool(settings.kill_switch),
            "stack": "system",
            "sniff": True,
            "sniff_override_destination": True,
            "endpoint_independent_nat": True,
        }
        return [mixed, tun]

    def _build_route_rules(self, split_rules: SplitRules) -> tuple[list[dict[str, Any]], str]:
        rules: list[dict[str, Any]] = [
            {"protocol": "dns", "outbound": "dns-out"},
            {"ip_is_private": True, "outbound": "direct"},
        ]
        for rule_set in split_rules.enabled_rule_sets:
            selector = self._build_rule_selector(rule_set)
            if selector:
                rules.append(selector)
        return rules, ROUTE_OUTBOUND_PROXY

    def _build_rule_selector(self, rule_set: RoutingRuleSet) -> dict[str, Any]:
        outbound = normalize_outbound(rule_set.outbound)
        if outbound not in ROUTE_OUTBOUNDS:
            raise ConfigBuildError(f"Неизвестный маршрут ruleset '{rule_set.name}'")

        selector: dict[str, Any] = {"outbound": outbound}
        if rule_set.domains:
            selector["domain"] = sorted(set(rule_set.domains))
        if rule_set.domain_suffix:
            selector["domain_suffix"] = sorted(set(rule_set.domain_suffix))
        if rule_set.domain_keyword:
            selector["domain_keyword"] = sorted(set(rule_set.domain_keyword))
        if rule_set.ip_cidr:
            selector["ip_cidr"] = sorted(set(rule_set.ip_cidr))
        if rule_set.process_name:
            selector["process_name"] = sorted(set(rule_set.process_name))
        if rule_set.process_path_regex:
            selector["process_path_regex"] = sorted(set(rule_set.process_path_regex))
        return selector if len(selector) > 1 else {}
