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

"""Connection orchestration without GUI dependencies."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from core.error_messages import sanitize_error_text
from core.latency_scanner import LatencyScanner
from core.singbox_manager import SingBoxManager
from core.smart_connect import SmartConnectManager
from models.connection import (
    SMART_GROUP_MODE_FAILOVER,
    SMART_STRATEGY_FAILOVER_ORDER,
    SmartGroup,
    normalize_smart_group_mode,
    normalize_smart_strategy,
)
from models.profile import VlessProfile, utc_now_iso
from models.rules import SplitRules
from models.settings import AppSettings
from utils import windows


ProfileLatencyRecorder = Callable[[str, int | None, str], object]
StateSaver = Callable[[], None]


@dataclass(frozen=True, slots=True)
class ConnectionStartResult:
    """Result of a direct or Smart Connect start attempt."""

    anchor_profile: VlessProfile
    selected_profile: VlessProfile
    display_name: str = ""
    profile_ids: tuple[str, ...] = field(default_factory=tuple)
    group_id: str | None = None
    group_mode: str | None = None

    def __post_init__(self) -> None:
        if not self.display_name:
            object.__setattr__(self, "display_name", self.selected_profile.name)
        if not self.profile_ids:
            object.__setattr__(self, "profile_ids", (self.selected_profile.id,))


class ConnectionService:
    """Start/stop sing-box and choose Smart Connect candidates.

    The service intentionally has no Qt or app_state dependency. Persistence is
    passed in as callbacks so the GUI layer remains the owner of application
    state while connection mechanics live outside the main window class.
    """

    def __init__(
        self,
        *,
        singbox: SingBoxManager,
        smart_connect: SmartConnectManager,
        latency_scanner: LatencyScanner,
        logger: logging.Logger,
        scan_limit: int,
    ) -> None:
        self.singbox = singbox
        self.smart_connect = smart_connect
        self.latency_scanner = latency_scanner
        self.logger = logger
        self.scan_limit = max(1, int(scan_limit))

    def start_direct(
        self,
        profile: VlessProfile,
        *,
        settings: AppSettings,
        split_rules: SplitRules,
        save_quality_stats: StateSaver,
    ) -> ConnectionStartResult:
        try:
            self.start_profile_core(profile, settings=settings, split_rules=split_rules)
        except Exception:
            self.smart_connect.record_failure(profile.id)
            save_quality_stats()
            raise
        self.smart_connect.record_success(profile.id)
        save_quality_stats()
        return ConnectionStartResult(anchor_profile=profile, selected_profile=profile)

    def start_smart(
        self,
        anchor_profile: VlessProfile,
        *,
        profiles: Sequence[VlessProfile],
        settings: AppSettings,
        split_rules: SplitRules,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> ConnectionStartResult:
        selected = self.select_smart_profile(
            anchor_profile,
            profiles=profiles,
            settings=settings,
            record_latency=record_latency,
            save_profiles=save_profiles,
            save_quality_stats=save_quality_stats,
        )
        try:
            self.start_profile_core(selected, settings=settings, split_rules=split_rules)
        except Exception:
            self.smart_connect.record_failure(selected.id)
            save_quality_stats()
            raise
        self.smart_connect.record_success(selected.id)
        save_quality_stats()
        return ConnectionStartResult(anchor_profile=anchor_profile, selected_profile=selected)

    def start_group(
        self,
        group: SmartGroup,
        *,
        profiles: Sequence[VlessProfile],
        settings: AppSettings,
        split_rules: SplitRules,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> ConnectionStartResult:
        members = self._group_members(group, profiles)
        if not members:
            raise ValueError(f"Группа '{group.name}' не содержит доступных серверов")

        mode = normalize_smart_group_mode(group.mode)
        if mode == SMART_GROUP_MODE_FAILOVER:
            selected = self._select_failover_group_profile(
                group,
                members,
                settings=settings,
                record_latency=record_latency,
                save_profiles=save_profiles,
                save_quality_stats=save_quality_stats,
            )
            try:
                self.start_profile_core(selected, settings=settings, split_rules=split_rules)
            except Exception:
                self.smart_connect.record_failure(selected.id)
                save_quality_stats()
                raise
            self.smart_connect.record_success(selected.id)
            save_quality_stats()
            return ConnectionStartResult(
                anchor_profile=members[0],
                selected_profile=selected,
                display_name=f"{group.name} · {selected.name}",
                profile_ids=(selected.id,),
                group_id=group.id,
                group_mode=mode,
            )

        try:
            self.start_group_core(group, members, settings=settings, split_rules=split_rules)
        except Exception:
            for member in members:
                self.smart_connect.record_failure(member.id)
            save_quality_stats()
            raise
        for member in members:
            self.smart_connect.record_success(member.id)
        save_quality_stats()
        return ConnectionStartResult(
            anchor_profile=members[0],
            selected_profile=members[-1],
            display_name=f"{group.name} · {'Multi-hop' if mode == 'multi_hop' else 'Load Balance'}",
            profile_ids=tuple(member.id for member in members),
            group_id=group.id,
            group_mode=mode,
        )

    def select_smart_profile(
        self,
        anchor_profile: VlessProfile,
        *,
        profiles: Sequence[VlessProfile],
        settings: AppSettings,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> VlessProfile:
        candidates = self.smart_connect.candidate_profiles(
            anchor_profile,
            profiles,
            limit=self.scan_limit,
        )
        if not candidates:
            return anchor_profile
        if len(candidates) == 1:
            return candidates[0]

        try:
            scan_result = self.latency_scanner.scan_profiles_sync(candidates, settings=settings)
        except Exception as exc:
            self.logger.warning(
                "Smart Connect quick scan не выполнен, использую сохраненную статистику: %s",
                sanitize_error_text(exc),
            )
            decision = self.smart_connect.choose_best(
                anchor_profile,
                candidates,
                limit=self.scan_limit,
            )
            return decision.selected or anchor_profile

        checked_at = utc_now_iso()
        for candidate in candidates:
            record_latency(candidate.id, scan_result.results.get(candidate.id), checked_at)
        save_profiles()
        save_quality_stats()

        decision = self.smart_connect.choose_best(
            anchor_profile,
            candidates,
            latency_overrides=scan_result.results,
            limit=self.scan_limit,
        )
        selected = decision.selected or anchor_profile
        self.logger.info(
            "Smart Connect выбрал сервер: %s из %s кандидатов",
            selected.name,
            len(candidates),
        )
        return selected

    def start_profile_core(
        self,
        profile: VlessProfile,
        *,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> None:
        firewall_enabled = False
        core_started = False
        try:
            self.logger.info(
                "Запуск sing-box профиля: %s (%s://%s:%s) mode=%s",
                profile.name,
                profile.protocol,
                profile.address,
                profile.port,
                settings.mode,
            )
            if settings.firewall_kill_switch:
                self.enable_firewall_kill_switch()
                firewall_enabled = True
            if settings.enable_system_proxy_guard and settings.mode != "proxy":
                windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
            self.singbox.start(profile, settings, split_rules)
            core_started = True
            if settings.enable_system_proxy_guard and settings.mode == "proxy":
                windows.set_system_proxy(True, settings.mixed_listen_host, settings.mixed_port)
            elif settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
        except Exception:
            # Ошибка может случиться после включения firewall/proxy или частичного старта core.
            # Откат держит систему в понятном состоянии перед показом ошибки пользователю.
            self._cleanup_after_failed_start(settings, core_started=core_started, firewall_enabled=firewall_enabled)
            raise

    def start_group_core(
        self,
        group: SmartGroup,
        members: Sequence[VlessProfile],
        *,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> None:
        firewall_enabled = False
        core_started = False
        profiles_by_id = {profile.id: profile for profile in members}
        try:
            self.logger.info(
                "Запуск sing-box группы: %s mode=%s members=%s",
                group.name,
                normalize_smart_group_mode(group.mode),
                len(members),
            )
            if settings.firewall_kill_switch:
                self.enable_firewall_kill_switch()
                firewall_enabled = True
            if settings.enable_system_proxy_guard and settings.mode != "proxy":
                windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
            self.singbox.start_group(group, profiles_by_id, settings, split_rules)
            core_started = True
            if settings.enable_system_proxy_guard and settings.mode == "proxy":
                windows.set_system_proxy(True, settings.mixed_listen_host, settings.mixed_port)
            elif settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
        except Exception:
            self._cleanup_after_failed_start(settings, core_started=core_started, firewall_enabled=firewall_enabled)
            raise

    def _cleanup_after_failed_start(
        self,
        settings: AppSettings,
        *,
        core_started: bool,
        firewall_enabled: bool,
    ) -> None:
        if settings.enable_system_proxy_guard:
            try:
                windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
            except Exception as exc:
                self.logger.error("Не удалось откатить системный proxy после ошибки запуска: %s", sanitize_error_text(exc))
        if core_started:
            try:
                self.singbox.stop()
            except Exception as exc:
                self.logger.error("Не удалось остановить sing-box после частичного запуска: %s", sanitize_error_text(exc))
        if firewall_enabled:
            self.clear_firewall_kill_switch_safely()

    def stop(self, settings: AppSettings) -> None:
        self.singbox.stop()
        if settings.enable_system_proxy_guard:
            windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)
        self.clear_firewall_kill_switch_safely()

    def stop_for_restart(self, settings: AppSettings) -> None:
        self.singbox.stop()
        if settings.enable_system_proxy_guard:
            windows.set_system_proxy(False, settings.mixed_listen_host, settings.mixed_port)

    def enable_firewall_kill_switch(self) -> None:
        executable = self.singbox.ensure_binary()
        windows.set_firewall_kill_switch(
            True,
            executable,
            app_executable=windows.executable_for_pyinstaller(),
        )

    def clear_firewall_kill_switch_safely(self) -> None:
        if not windows.is_windows():
            return
        if not windows.is_admin():
            self.logger.warning("Firewall Kill Switch cleanup пропущен: нет прав администратора")
            return
        try:
            windows.clear_firewall_kill_switch()
        except Exception as exc:
            self.logger.error("Не удалось отключить Firewall Kill Switch: %s", sanitize_error_text(exc))

    @staticmethod
    def _group_members(group: SmartGroup, profiles: Sequence[VlessProfile]) -> list[VlessProfile]:
        by_id = {profile.id: profile for profile in profiles}
        return [by_id[profile_id] for profile_id in group.profile_ids if profile_id in by_id]

    def _select_failover_group_profile(
        self,
        group: SmartGroup,
        members: Sequence[VlessProfile],
        *,
        settings: AppSettings,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> VlessProfile:
        strategy = normalize_smart_strategy(group.strategy)
        if strategy == SMART_STRATEGY_FAILOVER_ORDER or len(members) == 1:
            return members[0]
        try:
            scan_result = self.latency_scanner.scan_profiles_sync(members, settings=settings)
        except Exception as exc:
            self.logger.warning(
                "Failover group quick scan не выполнен, использую сохраненную статистику: %s",
                sanitize_error_text(exc),
            )
            scan_results = None
        else:
            checked_at = utc_now_iso()
            for member in members:
                record_latency(member.id, scan_result.results.get(member.id), checked_at)
            save_profiles()
            save_quality_stats()
            scan_results = scan_result.results

        decision = self.smart_connect.choose_best(
            members[0],
            members,
            latency_overrides=scan_results,
            limit=len(members),
        )
        return decision.selected or members[0]
