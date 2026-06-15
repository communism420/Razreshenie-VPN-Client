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

"""Multi-hop and load-balance outbound builders for sing-box."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from core.connectivity import DEFAULT_CONNECTIVITY_CHECK_URLS
from core.outbound_builder import OutboundBuilder, OutboundBuildError
from models.connection import (
    SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT,
    SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS,
    SMART_GROUP_MODE_LOAD_BALANCE,
    SMART_GROUP_MODE_MULTI_HOP,
    SmartGroup,
    normalize_smart_group_mode,
)
from models.profile import ServerProfile


class GroupOutboundBuildError(ValueError):
    """Ошибка генерации group outbound для sing-box."""


@dataclass(frozen=True, slots=True)
class GroupOutboundBuildResult:
    outbounds: list[dict[str, object]]
    member_profiles: list[ServerProfile]
    exit_profile: ServerProfile
    display_name: str
    mode: str

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(profile.id for profile in self.member_profiles)


class GroupOutboundBuilder:
    """Builds advanced sing-box outbound targets from SmartGroup members."""

    def __init__(self, outbound_builder: OutboundBuilder | None = None) -> None:
        self.outbound_builder = outbound_builder or OutboundBuilder()

    def build(
        self,
        group: SmartGroup,
        profiles_by_id: Mapping[str, ServerProfile],
    ) -> GroupOutboundBuildResult:
        mode = normalize_smart_group_mode(group.mode)
        if mode == SMART_GROUP_MODE_MULTI_HOP:
            return self._build_multi_hop(group, profiles_by_id)
        if mode == SMART_GROUP_MODE_LOAD_BALANCE:
            return self._build_load_balance(group, profiles_by_id)
        raise GroupOutboundBuildError("Failover-группа не является отдельным group outbound")

    def _build_multi_hop(
        self,
        group: SmartGroup,
        profiles_by_id: Mapping[str, ServerProfile],
    ) -> GroupOutboundBuildResult:
        members = self._member_profiles(group, profiles_by_id)
        if len(members) < 2:
            raise GroupOutboundBuildError("Multi-hop требует минимум два сервера в группе")

        outbounds: list[dict[str, object]] = []
        previous_tag = ""
        for index, profile in enumerate(members, start=1):
            is_exit = index == len(members)
            tag = "proxy" if is_exit else f"hop-{index}"
            outbound = self._build_profile_outbound(profile, tag)
            if previous_tag:
                outbound["detour"] = previous_tag
            outbounds.append(outbound)
            previous_tag = tag

        return GroupOutboundBuildResult(
            outbounds=outbounds,
            member_profiles=members,
            exit_profile=members[-1],
            display_name=f"{group.name} · Multi-hop",
            mode=SMART_GROUP_MODE_MULTI_HOP,
        )

    def _build_load_balance(
        self,
        group: SmartGroup,
        profiles_by_id: Mapping[str, ServerProfile],
    ) -> GroupOutboundBuildResult:
        members = self._member_profiles(group, profiles_by_id)
        if len(members) < 2:
            raise GroupOutboundBuildError("Load Balance требует минимум два сервера в группе")

        outbounds: list[dict[str, object]] = []
        tags: list[str] = []
        for index, profile in enumerate(members, start=1):
            tag = f"lb-{index}"
            outbounds.append(self._build_profile_outbound(profile, tag))
            tags.append(tag)

        interval = str(group.load_balance_interval or SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT).strip()
        if not interval:
            interval = SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT
        tolerance = max(
            0,
            int(group.load_balance_tolerance_ms or SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS),
        )
        outbounds.append(
            {
                "type": "urltest",
                "tag": "proxy",
                "outbounds": tags,
                "url": DEFAULT_CONNECTIVITY_CHECK_URLS[0],
                "interval": interval,
                "tolerance": tolerance,
            }
        )
        return GroupOutboundBuildResult(
            outbounds=outbounds,
            member_profiles=members,
            exit_profile=members[0],
            display_name=f"{group.name} · Load Balance",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
        )

    def _build_profile_outbound(self, profile: ServerProfile, tag: str) -> dict[str, object]:
        try:
            return self.outbound_builder.build(profile, tag=tag)
        except OutboundBuildError as exc:
            raise GroupOutboundBuildError(str(exc)) from exc

    @staticmethod
    def _member_profiles(
        group: SmartGroup,
        profiles_by_id: Mapping[str, ServerProfile],
    ) -> list[ServerProfile]:
        members = [profiles_by_id[profile_id] for profile_id in group.profile_ids if profile_id in profiles_by_id]
        if not members:
            raise GroupOutboundBuildError(f"Группа '{group.name}' не содержит доступных серверов")
        return members
