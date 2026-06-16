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

"""Пользовательские настройки приложения."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
from typing import Any

from core.connectivity import (
    DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS,
    DEFAULT_CONNECTIVITY_CHECK_URLS,
    normalize_connectivity_timeout_ms,
    normalize_connectivity_urls,
)


BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS = 30
BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS = 10
BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS = 3600
BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD = 3
BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD = 1
BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD = 10
SELF_HEALING_DEFAULT_MAX_ATTEMPTS = 3
SELF_HEALING_MIN_MAX_ATTEMPTS = 1
SELF_HEALING_MAX_MAX_ATTEMPTS = 8
SELF_HEALING_DEFAULT_COOLDOWN_SECONDS = 120
SELF_HEALING_MIN_COOLDOWN_SECONDS = 30
SELF_HEALING_MAX_COOLDOWN_SECONDS = 3600
DEFAULT_TUN_IPV6_ADDRESS = "fdfe:dcba:9876::1/126"
DNS_STRATEGY_PREFER_IPV4 = "prefer_ipv4"
DNS_STRATEGY_PREFER_IPV6 = "prefer_ipv6"
DNS_STRATEGY_IPV4_ONLY = "ipv4_only"
DNS_STRATEGY_IPV6_ONLY = "ipv6_only"
DNS_STRATEGIES = {
    DNS_STRATEGY_PREFER_IPV4,
    DNS_STRATEGY_PREFER_IPV6,
    DNS_STRATEGY_IPV4_ONLY,
    DNS_STRATEGY_IPV6_ONLY,
}
APP_UPDATE_MODE_DOWNLOAD_ONLY = "download_only"
APP_UPDATE_MODE_REPLACE_CURRENT = "replace_current"
APP_UPDATE_MODES = {
    APP_UPDATE_MODE_DOWNLOAD_ONLY,
    APP_UPDATE_MODE_REPLACE_CURRENT,
}


def _clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(default)
    return max(int(minimum), min(int(maximum), number))


def _optional_bool(value: Any, default: bool) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "да"}:
        return True
    if text in {"0", "false", "no", "off", "нет"}:
        return False
    return bool(default)


def normalize_dns_strategy(value: Any, *, ipv6_enabled: bool = True) -> str:
    if not ipv6_enabled:
        return DNS_STRATEGY_IPV4_ONLY
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "ipv4": DNS_STRATEGY_IPV4_ONLY,
        "4": DNS_STRATEGY_IPV4_ONLY,
        "ipv6": DNS_STRATEGY_IPV6_ONLY,
        "6": DNS_STRATEGY_IPV6_ONLY,
        "prefer4": DNS_STRATEGY_PREFER_IPV4,
        "prefer_4": DNS_STRATEGY_PREFER_IPV4,
        "prefer6": DNS_STRATEGY_PREFER_IPV6,
        "prefer_6": DNS_STRATEGY_PREFER_IPV6,
    }
    strategy = aliases.get(text, text)
    if strategy not in DNS_STRATEGIES:
        strategy = DNS_STRATEGY_PREFER_IPV4
    return strategy


def normalize_app_update_mode(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "download": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "download_only": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "manual": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "manual_install": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "standalone": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "скачать": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "скачать_отдельно": APP_UPDATE_MODE_DOWNLOAD_ONLY,
        "replace": APP_UPDATE_MODE_REPLACE_CURRENT,
        "replace_current": APP_UPDATE_MODE_REPLACE_CURRENT,
        "in_place": APP_UPDATE_MODE_REPLACE_CURRENT,
        "install_in_place": APP_UPDATE_MODE_REPLACE_CURRENT,
        "заменить": APP_UPDATE_MODE_REPLACE_CURRENT,
        "заменить_текущий_exe": APP_UPDATE_MODE_REPLACE_CURRENT,
    }
    return aliases.get(text, text) if aliases.get(text, text) in APP_UPDATE_MODES else APP_UPDATE_MODE_DOWNLOAD_ONLY


@dataclass(slots=True)
class AppSettings:
    app_name: str = "Razreshenie VPN Client"
    slogan: str = "Разреши себе доступ к любым сайтам"
    mode: str = "proxy"
    active_profile_id: str | None = None
    window_geometry: str = "1180x760"
    mixed_listen_host: str = "127.0.0.1"
    mixed_port: int = 2080
    tun_interface_name: str = "Razreshenie"
    tun_address: str = "172.19.0.1/30"
    tun_ipv6_address: str = DEFAULT_TUN_IPV6_ADDRESS
    tun_mtu: int = 4064
    enable_ipv6: bool = True
    dns_strategy: str = DNS_STRATEGY_PREFER_IPV4
    dns_servers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    connectivity_check_urls: list[str] = field(default_factory=lambda: list(DEFAULT_CONNECTIVITY_CHECK_URLS))
    connectivity_check_timeout_ms: int = DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS
    smart_connect_enabled: bool = True
    background_health_check_enabled: bool = True
    background_health_check_interval_seconds: int = BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS
    background_health_check_failure_threshold: int = BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD
    self_healing_enabled: bool = True
    self_healing_max_attempts: int = SELF_HEALING_DEFAULT_MAX_ATTEMPTS
    self_healing_cooldown_seconds: int = SELF_HEALING_DEFAULT_COOLDOWN_SECONDS
    kill_switch: bool = False
    firewall_kill_switch: bool = False
    enable_system_proxy_guard: bool = False
    auto_connect: bool = False
    auto_start_windows: bool = False
    always_run_as_admin: bool = False
    auto_check_app_updates: bool = False
    app_update_mode: str = APP_UPDATE_MODE_DOWNLOAD_ONLY
    auto_update_subscriptions: bool = True
    subscription_update_interval_hours: int = 24
    portable_mode: bool = False
    show_notifications: bool = True
    minimize_to_tray: bool = True
    first_run: bool = True
    log_level: str = "info"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppSettings":
        safe = dict(data)
        if isinstance(safe.get("dns_servers"), str):
            safe["dns_servers"] = [item.strip() for item in safe["dns_servers"].split(",") if item.strip()]
        safe["connectivity_check_urls"] = normalize_connectivity_urls(safe.get("connectivity_check_urls"))
        safe["connectivity_check_timeout_ms"] = normalize_connectivity_timeout_ms(
            safe.get("connectivity_check_timeout_ms")
        )
        safe["background_health_check_interval_seconds"] = _clamp_int(
            safe.get("background_health_check_interval_seconds"),
            BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS,
            BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
            BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
        )
        safe["background_health_check_failure_threshold"] = _clamp_int(
            safe.get("background_health_check_failure_threshold"),
            BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD,
            BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
            BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
        )
        safe["background_health_check_enabled"] = _optional_bool(
            safe.get("background_health_check_enabled"),
            True,
        )
        safe["self_healing_enabled"] = _optional_bool(safe.get("self_healing_enabled"), True)
        safe["self_healing_max_attempts"] = _clamp_int(
            safe.get("self_healing_max_attempts"),
            SELF_HEALING_DEFAULT_MAX_ATTEMPTS,
            SELF_HEALING_MIN_MAX_ATTEMPTS,
            SELF_HEALING_MAX_MAX_ATTEMPTS,
        )
        safe["self_healing_cooldown_seconds"] = _clamp_int(
            safe.get("self_healing_cooldown_seconds"),
            SELF_HEALING_DEFAULT_COOLDOWN_SECONDS,
            SELF_HEALING_MIN_COOLDOWN_SECONDS,
            SELF_HEALING_MAX_COOLDOWN_SECONDS,
        )
        safe["firewall_kill_switch"] = _optional_bool(safe.get("firewall_kill_switch"), False)
        safe["always_run_as_admin"] = _optional_bool(safe.get("always_run_as_admin"), False)
        safe["auto_check_app_updates"] = _optional_bool(safe.get("auto_check_app_updates"), False)
        safe["app_update_mode"] = normalize_app_update_mode(safe.get("app_update_mode"))
        safe["smart_connect_enabled"] = _optional_bool(safe.get("smart_connect_enabled"), True)
        safe["enable_ipv6"] = _optional_bool(safe.get("enable_ipv6"), True)
        safe["tun_ipv6_address"] = str(safe.get("tun_ipv6_address") or DEFAULT_TUN_IPV6_ADDRESS).strip()
        if not safe["tun_ipv6_address"]:
            safe["tun_ipv6_address"] = DEFAULT_TUN_IPV6_ADDRESS
        safe["dns_strategy"] = normalize_dns_strategy(
            safe.get("dns_strategy"),
            ipv6_enabled=bool(safe["enable_ipv6"]),
        )
        for key in ("mixed_port", "tun_mtu", "subscription_update_interval_hours"):
            if key in safe:
                safe[key] = int(safe[key])
        if os.name == "nt" and int(safe.get("tun_mtu") or 4064) > 4064:
            safe["tun_mtu"] = 4064
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
