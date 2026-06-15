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

"""Top-level sing-box config.json builder."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from core.config_errors import ConfigBuildError
from core.dns_builder import DnsBuilder
from core.group_outbound_builder import GroupOutboundBuilder, GroupOutboundBuildError
from core.inbound_builder import KARING_WINDOWS_TUN_MTU, KARING_WINDOWS_TUN_STACK, InboundBuilder
from core.outbound_builder import OutboundBuilder, OutboundBuildError
from core.route_builder import RouteBuilder
from models.connection import SmartGroup
from models.profile import ServerProfile
from models.rules import SplitRules
from models.settings import AppSettings


class SingBoxConfigBuilder:
    """Assembles sing-box config sections without protocol-specific coupling."""

    def __init__(self) -> None:
        self.outbound_builder = OutboundBuilder()
        self.group_outbound_builder = GroupOutboundBuilder(self.outbound_builder)
        self.dns_builder = DnsBuilder()
        self.inbound_builder = InboundBuilder()
        self.route_builder = RouteBuilder()

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

        outbounds = [proxy_outbound, self._direct_outbound()]
        return self._assemble_config(settings, split_rules, outbounds, log_path)

    def build_group(
        self,
        group: SmartGroup,
        profiles_by_id: Mapping[str, ServerProfile],
        settings: AppSettings,
        split_rules: SplitRules,
        log_path: Path | None,
    ) -> dict[str, Any]:
        if settings.mode not in {"proxy", "tun"}:
            raise ConfigBuildError("Неизвестный режим подключения")

        try:
            group_outbounds = self.group_outbound_builder.build(group, profiles_by_id).outbounds
        except GroupOutboundBuildError as exc:
            raise ConfigBuildError(str(exc)) from exc
        return self._assemble_config(settings, split_rules, [*group_outbounds, self._direct_outbound()], log_path)

    def _assemble_config(
        self,
        settings: AppSettings,
        split_rules: SplitRules,
        outbounds: list[dict[str, Any]],
        log_path: Path | None,
    ) -> dict[str, Any]:
        config: dict[str, Any] = {
            "log": {
                "level": settings.log_level,
                "timestamp": True,
            },
            "dns": self.dns_builder.build(settings, split_rules),
            "inbounds": self.inbound_builder.build(settings),
            "outbounds": outbounds,
            "route": self.route_builder.build(split_rules),
        }
        # sing-box stdout is consumed by SingBoxManager and persisted by the app.
        _ = log_path
        return config

    @staticmethod
    def _direct_outbound() -> dict[str, Any]:
        return {
            "type": "direct",
            "tag": "direct",
            "domain_resolver": "bootstrap-dns",
        }

    def build_latency_test_outbound(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        """Builds outbound with an external tag for Karing-style delay API."""
        try:
            return self.outbound_builder.build(profile, tag=tag)
        except OutboundBuildError as exc:
            raise ConfigBuildError(str(exc)) from exc


__all__ = [
    "ConfigBuildError",
    "KARING_WINDOWS_TUN_MTU",
    "KARING_WINDOWS_TUN_STACK",
    "SingBoxConfigBuilder",
]
