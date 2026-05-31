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
    tun_mtu: int = 4064
    dns_servers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    kill_switch: bool = False
    enable_system_proxy_guard: bool = False
    auto_connect: bool = False
    auto_start_windows: bool = False
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
        for key in ("mixed_port", "tun_mtu", "subscription_update_interval_hours"):
            if key in safe:
                safe[key] = int(safe[key])
        if os.name == "nt" and int(safe.get("tun_mtu") or 4064) > 4064:
            safe["tun_mtu"] = 4064
        return cls(**{key: safe[key] for key in cls.__dataclass_fields__ if key in safe})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
