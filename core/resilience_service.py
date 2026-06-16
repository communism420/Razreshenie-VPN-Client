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

"""Failover, health monitor and self-healing orchestration."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from core.connection_service import ConnectionService
from core.connectivity import ConnectivityCheckResult
from core.error_messages import format_user_error, sanitize_error_text
from models.profile import VlessProfile, utc_now_iso
from models.rules import SplitRules
from models.settings import (
    BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS,
    BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
    BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
    BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
    SELF_HEALING_DEFAULT_COOLDOWN_SECONDS,
    SELF_HEALING_DEFAULT_MAX_ATTEMPTS,
    SELF_HEALING_MAX_COOLDOWN_SECONDS,
    SELF_HEALING_MAX_MAX_ATTEMPTS,
    SELF_HEALING_MIN_COOLDOWN_SECONDS,
    SELF_HEALING_MIN_MAX_ATTEMPTS,
    AppSettings,
)


HEALTH_STATUS_IGNORE = "ignore"
HEALTH_STATUS_OK = "ok"
HEALTH_STATUS_FAILED = "failed"
HEALTH_STATUS_RECOVER = "recover"
RECOVERY_ACTION_NONE = "none"
RECOVERY_ACTION_FAILOVER = "failover"
RECOVERY_ACTION_RESTART = "restart"

ProfileLookup = Callable[[str], VlessProfile | None]
ProfileLatencyRecorder = Callable[[str, int | None, str], object]
StateSaver = Callable[[], None]


@dataclass(frozen=True, slots=True)
class FailoverAttemptResult:
    profile: VlessProfile | None
    error: str = ""


@dataclass(frozen=True, slots=True)
class HealthCheckOutcome:
    status: str
    profile_id: str = ""
    changed_profile_ids: tuple[str, ...] = ()
    reason: str = ""
    summary: str = ""
    failure_count: int = 0
    threshold: int = 0


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    action: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SelfHealingDecision:
    allowed: bool
    message: str = ""


class ResilienceService:
    """Owns connection recovery state and algorithms.

    The GUI remains responsible for timers, background execution and visual
    feedback. This service keeps the stateful recovery decisions out of the
    main window class.
    """

    def __init__(
        self,
        *,
        connection_service: ConnectionService,
        logger: logging.Logger,
        scan_limit: int,
    ) -> None:
        self.connection_service = connection_service
        self.smart_connect = connection_service.smart_connect
        self.latency_scanner = connection_service.latency_scanner
        self.logger = logger
        self.scan_limit = max(1, int(scan_limit))
        self.failover_anchor_profile_id: str | None = None
        self.failover_failed_ids: set[str] = set()
        self.failover_in_progress = False
        self.manual_disconnect_requested = False
        self.last_connection_running = False
        self.health_check_running = False
        self.health_failure_count = 0
        self.last_health_check = 0
        self.self_healing_attempts = 0
        self.self_healing_last_attempt_at = 0
        self.self_healing_cooldown_until = 0

    def mark_manual_disconnect_requested(self) -> None:
        self.manual_disconnect_requested = True

    def clear_manual_disconnect_requested(self) -> None:
        self.manual_disconnect_requested = False

    def on_connected(self) -> None:
        self.last_connection_running = True
        self.health_failure_count = 0
        self.last_health_check = int(time.time())

    def on_disconnected(self) -> None:
        self.clear_failover_session()
        self.reset_self_healing_state()
        self.last_connection_running = False
        self.health_check_running = False
        self.health_failure_count = 0

    def begin_failover_session(self, anchor_profile: VlessProfile) -> None:
        self.failover_anchor_profile_id = anchor_profile.id
        self.failover_failed_ids.clear()
        self.manual_disconnect_requested = False

    def clear_failover_session(self) -> None:
        self.failover_anchor_profile_id = None
        self.failover_failed_ids.clear()
        self.failover_in_progress = False
        self.manual_disconnect_requested = False

    def should_auto_failover(self, *, busy: bool, closing: bool) -> bool:
        return bool(
            self.failover_anchor_profile_id
            and not self.manual_disconnect_requested
            and not self.failover_in_progress
            and not busy
            and not closing
        )

    def begin_failover_after_drop(
        self,
        failed_profile: VlessProfile,
        *,
        busy: bool,
        closing: bool,
        save_quality_stats: StateSaver,
    ) -> bool:
        if not self.should_auto_failover(busy=busy, closing=closing):
            return False
        self.failover_in_progress = True
        self.failover_failed_ids.add(failed_profile.id)
        self.smart_connect.record_failure(failed_profile.id)
        save_quality_stats()
        self.logger.warning("Failover: сервер упал, ищу замену: %s", failed_profile.name)
        return True

    def run_failover_attempt(
        self,
        failed_profile: VlessProfile,
        *,
        profiles: Sequence[VlessProfile],
        settings: AppSettings,
        split_rules: SplitRules,
        profile_lookup: ProfileLookup,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> FailoverAttemptResult:
        anchor_profile = profile_lookup(self.failover_anchor_profile_id or "") or failed_profile
        candidates = self.smart_connect.failover_profiles(
            anchor_profile,
            profiles,
            current_profile=failed_profile,
            failed_ids=self.failover_failed_ids,
            limit=self.scan_limit,
        )
        if not candidates:
            self.logger.warning("Failover: нет кандидатов для %s", failed_profile.name)
            return FailoverAttemptResult(None, "Failover: нет доступных кандидатов в текущей группе")
        self.logger.info(
            "Failover: найдено кандидатов %s для замены %s",
            len(candidates),
            failed_profile.name,
        )

        latency_overrides: dict[str, int | None] | None = None
        try:
            scan_result = self.latency_scanner.scan_profiles_sync(candidates, settings=settings)
            checked_at = utc_now_iso()
            for candidate in candidates:
                record_latency(candidate.id, scan_result.results.get(candidate.id), checked_at)
            save_profiles()
            save_quality_stats()
            latency_overrides = scan_result.results
        except Exception as exc:
            self.logger.warning(
                "Failover quick scan не выполнен, использую сохраненную статистику: %s",
                sanitize_error_text(exc),
            )

        decision = self.smart_connect.choose_failover_next(
            anchor_profile,
            profiles,
            current_profile=failed_profile,
            failed_ids=self.failover_failed_ids,
            latency_overrides=latency_overrides,
            limit=self.scan_limit,
        )
        ordered = [candidate.profile for candidate in decision.candidates]
        if not ordered:
            return FailoverAttemptResult(None, "Failover: все кандидаты недоступны")

        last_error = ""
        for candidate in ordered:
            try:
                self.connection_service.start_profile_core(candidate, settings=settings, split_rules=split_rules)
            except Exception as exc:
                message = format_user_error(exc, context="Failover")
                last_error = message.display_text
                self.logger.warning("Failover: не удалось запустить %s: %s", candidate.name, sanitize_error_text(exc))
                self.failover_failed_ids.add(candidate.id)
                self.smart_connect.record_failure(candidate.id)
                save_quality_stats()
                continue
            self.smart_connect.record_success(candidate.id)
            save_quality_stats()
            self.logger.info("Failover: переключение выполнено на %s", candidate.name)
            return FailoverAttemptResult(candidate, "")
        message = last_error or "Failover: не удалось запустить ни один кандидат"
        self.logger.error("Failover: восстановление не удалось: %s", message)
        return FailoverAttemptResult(None, message)

    def finish_failover_attempt(self) -> None:
        self.failover_in_progress = False

    def start_health_check_if_due(
        self,
        *,
        now: int,
        running: bool,
        settings: AppSettings,
        busy: bool,
        closing: bool,
        active_profile: VlessProfile | None,
    ) -> VlessProfile | None:
        if not running or not settings.background_health_check_enabled:
            return None
        if self.health_check_running or busy or self.failover_in_progress:
            return None
        if self.manual_disconnect_requested or closing:
            return None
        interval = self.background_health_interval_seconds(settings)
        if now - self.last_health_check < interval:
            return None
        if not active_profile:
            return None
        self.last_health_check = now
        self.health_check_running = True
        return active_profile

    def handle_health_check_result(
        self,
        profile: VlessProfile | None,
        result: ConnectivityCheckResult,
        *,
        running: bool,
        closing: bool,
        settings: AppSettings,
        record_latency: ProfileLatencyRecorder,
        save_profiles: StateSaver,
        save_quality_stats: StateSaver,
    ) -> HealthCheckOutcome:
        self.health_check_running = False
        if closing or self.manual_disconnect_requested or not profile or not running:
            return HealthCheckOutcome(HEALTH_STATUS_IGNORE)

        if result.success:
            self.health_failure_count = 0
            attempt = result.successful_attempt
            timestamp = utc_now_iso()
            if attempt and attempt.latency_ms is not None:
                record_latency(profile.id, attempt.latency_ms, timestamp)
                save_profiles()
            else:
                self.smart_connect.record_success(profile.id, checked_at=timestamp)
            save_quality_stats()
            self.logger.debug("Health monitor OK: %s", result.summary)
            return HealthCheckOutcome(
                HEALTH_STATUS_OK,
                profile_id=profile.id,
                changed_profile_ids=(profile.id,),
                summary=result.summary,
            )

        self.health_failure_count += 1
        self.smart_connect.record_failure(profile.id)
        save_quality_stats()
        threshold = self.background_health_failure_threshold(settings)
        reason = sanitize_error_text(result.error)
        self.logger.warning(
            "Health monitor fail %s/%s: %s",
            self.health_failure_count,
            threshold,
            reason,
        )
        status = HEALTH_STATUS_RECOVER if self.health_failure_count >= threshold else HEALTH_STATUS_FAILED
        return HealthCheckOutcome(
            status,
            profile_id=profile.id,
            changed_profile_ids=(profile.id,),
            reason=reason,
            failure_count=self.health_failure_count,
            threshold=threshold,
        )

    def plan_health_recovery(
        self,
        profile: VlessProfile,
        reason: str,
        *,
        settings: AppSettings,
        profiles: Sequence[VlessProfile],
        profile_lookup: ProfileLookup,
        busy: bool,
        closing: bool,
    ) -> RecoveryPlan:
        if self.manual_disconnect_requested or busy or self.failover_in_progress:
            return RecoveryPlan(RECOVERY_ACTION_NONE, reason)
        self.health_failure_count = 0
        # Health recovery сначала ищет живого кандидата в failover-группе.
        # Если группы нет или кандидатов не осталось, безопаснее рестартовать текущий профиль.
        anchor_profile = profile_lookup(self.failover_anchor_profile_id or "") or profile
        candidates = self.smart_connect.failover_profiles(
            anchor_profile,
            profiles,
            current_profile=profile,
            failed_ids={profile.id},
            limit=self.scan_limit,
        )
        if candidates and self.should_auto_failover(busy=busy, closing=closing):
            return RecoveryPlan(RECOVERY_ACTION_FAILOVER, sanitize_error_text(reason))
        return RecoveryPlan(RECOVERY_ACTION_RESTART, sanitize_error_text(reason))

    def run_health_reconnect(
        self,
        profile: VlessProfile,
        *,
        settings: AppSettings,
        split_rules: SplitRules,
        save_quality_stats: StateSaver,
    ) -> FailoverAttemptResult:
        try:
            self.connection_service.stop_for_restart(settings)
            self.connection_service.start_profile_core(profile, settings=settings, split_rules=split_rules)
        except Exception as exc:
            self.smart_connect.record_failure(profile.id)
            save_quality_stats()
            return FailoverAttemptResult(None, format_user_error(exc, context="Health monitor").display_text)
        self.smart_connect.record_success(profile.id)
        save_quality_stats()
        return FailoverAttemptResult(profile, "")

    def mark_core_stopped(self) -> None:
        self.last_connection_running = False
        self.health_check_running = False

    def should_report_core_stop(self, *, closing: bool) -> bool:
        return bool(self.last_connection_running and not self.manual_disconnect_requested and not closing)

    def should_self_heal_after_drop(
        self,
        profile: VlessProfile | None,
        *,
        settings: AppSettings,
        busy: bool,
        closing: bool,
    ) -> bool:
        return bool(
            profile
            and settings.self_healing_enabled
            and not self.manual_disconnect_requested
            and not closing
            and not busy
            and not self.failover_in_progress
        )

    def register_self_healing_attempt(self, settings: AppSettings, reason: str) -> SelfHealingDecision:
        now = int(time.time())
        cooldown = self.self_healing_cooldown_seconds(settings)
        # Cooldown защищает систему от бесконечного цикла "sing-box упал -> restart".
        if self.self_healing_cooldown_until and now < self.self_healing_cooldown_until:
            remaining = self.self_healing_cooldown_until - now
            self.logger.error("Self-healing paused for %s seconds: %s", remaining, reason)
            return SelfHealingDecision(False, f"Self-healing на паузе ещё {remaining} сек.: {reason}")
        if self.self_healing_cooldown_until and now >= self.self_healing_cooldown_until:
            self.reset_self_healing_state()
        if self.self_healing_last_attempt_at and now - self.self_healing_last_attempt_at > cooldown:
            self.self_healing_attempts = 0

        self.self_healing_attempts += 1
        self.self_healing_last_attempt_at = now
        max_attempts = self.self_healing_max_attempts(settings)
        if self.self_healing_attempts > max_attempts:
            self.self_healing_cooldown_until = now + cooldown
            self.logger.error(
                "Self-healing stopped after %s attempts; cooldown=%ss. Last reason: %s",
                max_attempts,
                cooldown,
                reason,
            )
            return SelfHealingDecision(
                False,
                f"Self-healing: лимит {max_attempts} попыток исчерпан, пауза {cooldown} сек.",
            )

        self.logger.warning(
            "Self-healing attempt %s/%s after sing-box stop: %s",
            self.self_healing_attempts,
            max_attempts,
            reason,
        )
        return SelfHealingDecision(True)

    def reset_self_healing_state(self) -> None:
        self.self_healing_attempts = 0
        self.self_healing_last_attempt_at = 0
        self.self_healing_cooldown_until = 0

    def mark_unrecoverable_failure(self) -> None:
        self.clear_failover_session()
        self.last_connection_running = False
        self.health_check_running = False

    @staticmethod
    def self_healing_max_attempts(settings: AppSettings) -> int:
        try:
            value = int(settings.self_healing_max_attempts)
        except (TypeError, ValueError):
            value = SELF_HEALING_DEFAULT_MAX_ATTEMPTS
        return max(SELF_HEALING_MIN_MAX_ATTEMPTS, min(SELF_HEALING_MAX_MAX_ATTEMPTS, value))

    @staticmethod
    def self_healing_cooldown_seconds(settings: AppSettings) -> int:
        try:
            value = int(settings.self_healing_cooldown_seconds)
        except (TypeError, ValueError):
            value = SELF_HEALING_DEFAULT_COOLDOWN_SECONDS
        return max(SELF_HEALING_MIN_COOLDOWN_SECONDS, min(SELF_HEALING_MAX_COOLDOWN_SECONDS, value))

    @staticmethod
    def background_health_interval_seconds(settings: AppSettings) -> int:
        try:
            value = int(settings.background_health_check_interval_seconds)
        except (TypeError, ValueError):
            value = BACKGROUND_HEALTH_CHECK_DEFAULT_INTERVAL_SECONDS
        return max(
            BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
            min(BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS, value),
        )

    @staticmethod
    def background_health_failure_threshold(settings: AppSettings) -> int:
        try:
            value = int(settings.background_health_check_failure_threshold)
        except (TypeError, ValueError):
            value = BACKGROUND_HEALTH_CHECK_DEFAULT_FAILURE_THRESHOLD
        return max(
            BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
            min(BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD, value),
        )
