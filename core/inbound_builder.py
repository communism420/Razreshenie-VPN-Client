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

"""Inbound section builder for proxy and TUN modes."""

from __future__ import annotations

import os
from typing import Any

from models.settings import AppSettings


KARING_WINDOWS_TUN_STACK = "gvisor"
KARING_WINDOWS_TUN_MTU = 4064


class InboundBuilder:
    """Builds sing-box inbounds without route or outbound decisions."""

    def build(self, settings: AppSettings) -> list[dict[str, Any]]:
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
