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

"""State and validation service for Smart/Advanced Groups."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from core.smart_connect import SmartConnectManager
from models.connection import (
    SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT,
    SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS,
    SMART_GROUP_MODE_FAILOVER,
    SMART_GROUP_MODE_LOAD_BALANCE,
    SMART_GROUP_MODE_MULTI_HOP,
    SMART_STRATEGY_FAILOVER_ORDER,
    SmartGroup,
    normalize_smart_group_mode,
    normalize_smart_strategy,
)
from models.profile import Subscription, VlessProfile
from models.settings import AppSettings


class SmartGroupServiceError(ValueError):
    """Raised when a group operation cannot be applied."""


@dataclass(frozen=True, slots=True)
class SmartGroupEdit:
    name: str
    enabled: bool
    mode: str
    strategy: str
    profile_ids: list[str]
    load_balance_interval: str
    load_balance_tolerance_ms: int


@dataclass(frozen=True, slots=True)
class SmartGroupMutationResult:
    group: SmartGroup
    members: list[VlessProfile] = field(default_factory=list)
    status_message: str = ""


@dataclass(frozen=True, slots=True)
class SmartGroupStartDecision:
    group: SmartGroup | None
    allowed: bool
    mode: str | None = None
    busy_text: str = ""
    status_level: str = "info"
    status_message: str = ""
    admin_required: bool = False
    admin_reason: str = ""


class SmartGroupService:
    """Pure group mutations and preflight checks, without GUI or file IO."""

    def __init__(self, smart_connect: SmartConnectManager) -> None:
        self.smart_connect = smart_connect

    def group_by_id(self, group_id: str | None) -> SmartGroup | None:
        target = str(group_id or "").strip()
        if not target:
            return None
        return next((group for group in self.smart_connect.smart_groups if group.id == target), None)

    def create_failover_group(
        self,
        *,
        profile_id: str,
        profiles: Sequence[VlessProfile],
        subscriptions: Sequence[Subscription],
    ) -> SmartGroupMutationResult:
        profile = self._profile_by_id(profiles, profile_id)
        if not profile:
            raise SmartGroupServiceError("Профиль не найден")

        members = self.smart_connect.group_profiles(profile, profiles)
        if len(members) < 2:
            raise SmartGroupServiceError("Для failover-группы нужно минимум два сервера в одной группе")

        group, members = self.smart_connect.create_or_update_failover_group(
            profile,
            profiles,
            name=self.failover_group_name(profile, subscriptions),
            strategy=SMART_STRATEGY_FAILOVER_ORDER,
        )
        return SmartGroupMutationResult(
            group=group,
            members=list(members),
            status_message=f"Failover-группа сохранена: {group.name} · серверов: {len(members)}",
        )

    def apply_edit(self, group: SmartGroup, edit: SmartGroupEdit) -> SmartGroupMutationResult:
        mode = normalize_smart_group_mode(edit.mode)
        profile_ids = self._clean_profile_ids(edit.profile_ids)
        minimum = 2 if mode in {SMART_GROUP_MODE_MULTI_HOP, SMART_GROUP_MODE_LOAD_BALANCE} else 1
        if len(profile_ids) < minimum:
            raise SmartGroupServiceError("Для выбранного режима недостаточно серверов в группе.")

        group.name = str(edit.name or "").strip() or "Smart Group"
        group.enabled = bool(edit.enabled)
        group.mode = mode
        group.strategy = normalize_smart_strategy(edit.strategy)
        group.profile_ids = profile_ids
        group.load_balance_interval = (
            str(edit.load_balance_interval or "").strip() or SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT
        )
        group.load_balance_tolerance_ms = self._non_negative_int(
            edit.load_balance_tolerance_ms,
            SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS,
        )
        group.touch()
        return SmartGroupMutationResult(group=group, status_message=f"Группа сохранена: {group.name}")

    def plan_start(
        self,
        *,
        group_id: str,
        settings: AppSettings,
        is_admin: bool,
        busy: bool,
    ) -> SmartGroupStartDecision:
        group = self.group_by_id(group_id)
        if not group:
            return SmartGroupStartDecision(
                group=None,
                allowed=False,
                status_level="warning",
                status_message="Группа не найдена",
            )
        if not group.enabled:
            return SmartGroupStartDecision(
                group=group,
                allowed=False,
                status_level="warning",
                status_message="Группа отключена",
            )

        mode = normalize_smart_group_mode(group.mode)
        if (settings.mode == "tun" or settings.firewall_kill_switch) and not is_admin:
            reason = (
                "Для подключения группы с Firewall Kill Switch нужны права администратора."
                if settings.firewall_kill_switch
                else "Для подключения группы в TUN-режиме нужны права администратора."
            )
            return SmartGroupStartDecision(
                group=group,
                allowed=False,
                mode=mode,
                admin_required=True,
                admin_reason=reason,
            )

        if busy:
            return SmartGroupStartDecision(
                group=group,
                allowed=False,
                mode=mode,
                status_level="info",
                status_message="Операция подключения уже выполняется",
            )

        return SmartGroupStartDecision(group=group, allowed=True, mode=mode, busy_text=self._start_busy_text(mode))

    def failover_group_name(self, profile: VlessProfile, subscriptions: Sequence[Subscription]) -> str:
        subscription = (
            self._subscription_by_id(subscriptions, profile.subscription_id)
            if profile.subscription_id
            else None
        )
        source_group = " ".join(str(profile.group or "").split())
        if subscription and source_group:
            return f"{subscription.name} / {source_group}"
        if subscription:
            return subscription.name
        if source_group:
            return f"Без подписки / {source_group}"
        return "Без подписки"

    @staticmethod
    def _start_busy_text(mode: str) -> str:
        if mode == SMART_GROUP_MODE_LOAD_BALANCE:
            return "Load Balance…"
        if mode == SMART_GROUP_MODE_FAILOVER:
            return "Подключение группы…"
        return "Multi-hop…"

    @staticmethod
    def _profile_by_id(profiles: Sequence[VlessProfile], profile_id: str | None) -> VlessProfile | None:
        target = str(profile_id or "").strip()
        if not target:
            return None
        return next((profile for profile in profiles if profile.id == target), None)

    @staticmethod
    def _subscription_by_id(subscriptions: Sequence[Subscription], subscription_id: str | None) -> Subscription | None:
        target = str(subscription_id or "").strip()
        if not target:
            return None
        return next((subscription for subscription in subscriptions if subscription.id == target), None)

    @staticmethod
    def _clean_profile_ids(profile_ids: Sequence[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for profile_id in profile_ids:
            text = str(profile_id or "").strip()
            if text and text not in seen:
                result.append(text)
                seen.add(text)
        return result

    @staticmethod
    def _non_negative_int(value: int, default: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return int(default)
        return max(0, number)
