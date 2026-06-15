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

"""Smart Connect: выбор кандидатов, scoring и статистика качества серверов."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from models.connection import (
    QUALITY_EVENT_FAILURE,
    QUALITY_EVENT_LATENCY,
    QUALITY_EVENT_SUCCESS,
    SMART_STRATEGY_FAILOVER_ORDER,
    SMART_STRATEGY_LATENCY,
    SMART_STRATEGY_SMART,
    ServerQualityStats,
    SmartGroup,
    normalize_smart_strategy,
)
from models.profile import ServerProfile, utc_now_iso


SMART_CONNECT_DEFAULT_LIMIT = 12
SMART_CONNECT_EWMA_ALPHA = 0.35
SMART_CONNECT_UNKNOWN_LATENCY_MS = 2500.0
SMART_CONNECT_UNREACHABLE_LATENCY_MS = 30000.0
SMART_CONNECT_FAILURE_PENALTY_MS = 900.0
SMART_CONNECT_CONSECUTIVE_FAILURE_PENALTY_MS = 1200.0
SMART_CONNECT_COOLDOWN_PENALTY_MS = 100000.0
SMART_CONNECT_STABILITY_BONUS_MS = 180.0
SMART_CONNECT_FAILURE_COOLDOWN_MINUTES = 10


@dataclass(frozen=True, slots=True)
class SmartConnectCandidate:
    profile: ServerProfile
    score: float
    latency_ms: int | None
    source: str


@dataclass(frozen=True, slots=True)
class SmartConnectDecision:
    selected: ServerProfile | None
    candidates: list[SmartConnectCandidate]
    reason: str = ""


class SmartConnectManager:
    """Синхронная бизнес-логика Smart Connect без GUI и subprocess-зависимостей."""

    def __init__(
        self,
        quality_stats: dict[str, ServerQualityStats] | None = None,
        smart_groups: list[SmartGroup] | None = None,
    ) -> None:
        self.quality_stats: dict[str, ServerQualityStats] = dict(quality_stats or {})
        self.smart_groups: list[SmartGroup] = list(smart_groups or [])

    def group_key(self, profile: ServerProfile) -> str:
        subscription_id = str(profile.subscription_id or "").strip() or "__manual__"
        source_group = str(profile.group or "").strip()
        return f"{subscription_id}::{source_group}" if source_group else subscription_id

    def candidate_profiles(
        self,
        active_profile: ServerProfile | None,
        profiles: Iterable[ServerProfile],
        *,
        limit: int = SMART_CONNECT_DEFAULT_LIMIT,
    ) -> list[ServerProfile]:
        profile_list = [profile for profile in profiles if self._is_usable_profile(profile)]
        if not profile_list:
            return []
        if active_profile is None:
            return self._limit_by_score(profile_list, limit)

        # Кандидаты намеренно сужаются вокруг выбранного сервера: explicit
        # группа, группа провайдера, подписка, и только затем общий список.
        explicit_group = self._explicit_group_for_profile(active_profile)
        if explicit_group:
            by_id = {profile.id: profile for profile in profile_list}
            explicit_profiles = [by_id[profile_id] for profile_id in explicit_group.profile_ids if profile_id in by_id]
            if explicit_profiles:
                return self._limit_by_strategy(explicit_profiles, explicit_group.strategy, limit)

        active_key = self.group_key(active_profile)
        same_group = [profile for profile in profile_list if self.group_key(profile) == active_key]
        if same_group:
            return self._limit_by_score(same_group, limit)

        subscription_id = str(active_profile.subscription_id or "").strip()
        if subscription_id:
            same_subscription = [profile for profile in profile_list if profile.subscription_id == subscription_id]
            if same_subscription:
                return self._limit_by_score(same_subscription, limit)

        return self._limit_by_score(profile_list, limit)

    def group_profiles(self, active_profile: ServerProfile, profiles: Iterable[ServerProfile]) -> list[ServerProfile]:
        """Возвращает профили той же logical-группы, что и active_profile."""
        profile_list = [profile for profile in profiles if self._is_usable_profile(profile)]
        if not profile_list:
            return []
        active_key = self.group_key(active_profile)
        same_group = [profile for profile in profile_list if self.group_key(profile) == active_key]
        if same_group:
            return same_group
        subscription_id = str(active_profile.subscription_id or "").strip()
        if subscription_id:
            same_subscription = [profile for profile in profile_list if profile.subscription_id == subscription_id]
            if same_subscription:
                return same_subscription
        return [profile for profile in profile_list if profile.id == active_profile.id] or [active_profile]

    def create_or_update_failover_group(
        self,
        active_profile: ServerProfile,
        profiles: Iterable[ServerProfile],
        *,
        name: str | None = None,
        strategy: str = SMART_STRATEGY_FAILOVER_ORDER,
    ) -> tuple[SmartGroup, list[ServerProfile]]:
        """Создаёт или обновляет explicit failover-группу вокруг active_profile."""
        members = self.group_profiles(active_profile, profiles)
        member_ids = [profile.id for profile in members]
        source_group = str(active_profile.group or "").strip() or None
        subscription_id = str(active_profile.subscription_id or "").strip() or None
        group = self._matching_group(subscription_id, source_group) or self._explicit_group_for_profile(active_profile)
        if group is None:
            group = SmartGroup()
            self.smart_groups.append(group)

        clean_name = str(name or "").strip()
        group.name = clean_name or self._default_group_name(active_profile)
        group.enabled = True
        group.profile_ids = member_ids
        group.subscription_id = subscription_id
        group.source_group = source_group
        group.strategy = normalize_smart_strategy(strategy)
        group.touch()
        return group, members

    def choose_best(
        self,
        active_profile: ServerProfile | None,
        profiles: Iterable[ServerProfile],
        *,
        latency_overrides: dict[str, int | None] | None = None,
        limit: int = SMART_CONNECT_DEFAULT_LIMIT,
    ) -> SmartConnectDecision:
        candidates = self.rank_candidates(
            self.candidate_profiles(active_profile, profiles, limit=limit),
            latency_overrides=latency_overrides,
        )
        if not candidates:
            return SmartConnectDecision(selected=None, candidates=[], reason="no candidates")
        return SmartConnectDecision(selected=candidates[0].profile, candidates=candidates, reason="best score")

    def failover_profiles(
        self,
        active_profile: ServerProfile | None,
        profiles: Iterable[ServerProfile],
        *,
        current_profile: ServerProfile | None = None,
        failed_ids: Iterable[str] = (),
        latency_overrides: dict[str, int | None] | None = None,
        limit: int = SMART_CONNECT_DEFAULT_LIMIT,
    ) -> list[ServerProfile]:
        """Возвращает ordered список кандидатов для переключения после падения текущего сервера."""
        profile_list = [profile for profile in profiles if self._is_usable_profile(profile)]
        if not profile_list:
            return []

        # Для explicit failover-группы порядок пользователя важнее глобального
        # score; smart/latency стратегии включаются только после фильтрации.
        strategy = SMART_STRATEGY_SMART
        if active_profile is None:
            ordered = self._limit_by_score(profile_list, limit)
        else:
            explicit_group = self._explicit_group_for_profile(active_profile)
            if explicit_group:
                by_id = {profile.id: profile for profile in profile_list}
                ordered = [by_id[profile_id] for profile_id in explicit_group.profile_ids if profile_id in by_id]
                strategy = normalize_smart_strategy(explicit_group.strategy)
            else:
                ordered = self.group_profiles(active_profile, profile_list)

        if current_profile and strategy == SMART_STRATEGY_FAILOVER_ORDER:
            ordered = self._rotate_after_profile(ordered, current_profile.id)

        failed = {str(profile_id) for profile_id in failed_ids if str(profile_id)}
        if current_profile:
            failed.add(current_profile.id)
        ordered = [profile for profile in ordered if profile.id not in failed]

        overrides = latency_overrides or {}
        if overrides:
            ordered = [profile for profile in ordered if profile.id not in overrides or overrides[profile.id] is not None]
        if not ordered:
            return []

        if strategy == SMART_STRATEGY_FAILOVER_ORDER:
            return ordered[: max(1, int(limit))]
        if strategy == SMART_STRATEGY_LATENCY:
            return self._limit_by_latency(ordered, limit, latency_overrides=latency_overrides)
        return [candidate.profile for candidate in self.rank_candidates(ordered, latency_overrides=latency_overrides)][
            : max(1, int(limit))
        ]

    def choose_failover_next(
        self,
        active_profile: ServerProfile | None,
        profiles: Iterable[ServerProfile],
        *,
        current_profile: ServerProfile | None = None,
        failed_ids: Iterable[str] = (),
        latency_overrides: dict[str, int | None] | None = None,
        limit: int = SMART_CONNECT_DEFAULT_LIMIT,
    ) -> SmartConnectDecision:
        candidates = self.failover_profiles(
            active_profile,
            profiles,
            current_profile=current_profile,
            failed_ids=failed_ids,
            latency_overrides=latency_overrides,
            limit=limit,
        )
        if not candidates:
            return SmartConnectDecision(selected=None, candidates=[], reason="no failover candidates")
        ranked = self.rank_candidates(candidates, latency_overrides=latency_overrides)
        if self._active_strategy(active_profile) == SMART_STRATEGY_FAILOVER_ORDER:
            ranked = [
                SmartConnectCandidate(
                    profile=profile,
                    score=float(index),
                    latency_ms=(latency_overrides or {}).get(profile.id, profile.latency_ms),
                    source=self.group_key(profile),
                )
                for index, profile in enumerate(candidates)
            ]
        return SmartConnectDecision(selected=ranked[0].profile, candidates=ranked, reason="failover next")

    def rank_candidates(
        self,
        profiles: Iterable[ServerProfile],
        *,
        latency_overrides: dict[str, int | None] | None = None,
    ) -> list[SmartConnectCandidate]:
        overrides = latency_overrides or {}
        result: list[SmartConnectCandidate] = []
        for profile in profiles:
            override_present = profile.id in overrides
            override_latency = overrides.get(profile.id) if override_present else None
            latency = override_latency if override_present else profile.latency_ms
            score = self.score_profile(
                profile,
                latency_override_ms=override_latency,
                latency_override_present=override_present,
            )
            result.append(
                SmartConnectCandidate(
                    profile=profile,
                    score=score,
                    latency_ms=latency,
                    source=self.group_key(profile),
                )
            )
        return sorted(result, key=lambda item: (item.score, item.profile.name.lower(), item.profile.id))

    def score_profile(
        self,
        profile: ServerProfile,
        *,
        latency_override_ms: int | None = None,
        latency_override_present: bool = False,
    ) -> float:
        stats = self.quality_stats.get(profile.id)
        latency = self._effective_latency(profile, stats, latency_override_ms, latency_override_present)
        score = float(latency)
        if stats:
            # Score держит баланс между свежей latency и долговременной
            # стабильностью, чтобы быстрый, но падающий сервер не побеждал.
            score += stats.consecutive_failures * SMART_CONNECT_CONSECUTIVE_FAILURE_PENALTY_MS
            score += stats.failure_count * SMART_CONNECT_FAILURE_PENALTY_MS
            score -= min(SMART_CONNECT_STABILITY_BONUS_MS, stats.success_count * 12.0)
            score += (1.0 - stats.success_rate) * 500.0
            if stats.history:
                score += (1.0 - stats.recent_success_rate) * 250.0
            if self._is_on_cooldown(stats):
                score += SMART_CONNECT_COOLDOWN_PENALTY_MS
        return max(0.0, score)

    def record_latency(
        self,
        profile_id: str,
        latency_ms: int | None,
        *,
        checked_at: str | None = None,
    ) -> ServerQualityStats:
        stats = self._stats_for(profile_id)
        timestamp = checked_at or utc_now_iso()
        stats.last_checked_at = timestamp
        if latency_ms is None:
            self.record_failure(profile_id, checked_at=timestamp, message="latency timeout")
            return stats

        stats.samples += 1
        latency = max(1, int(latency_ms))
        stats.last_latency_ms = latency
        stats.latency_ewma_ms = (
            float(latency)
            if stats.latency_ewma_ms is None
            else (SMART_CONNECT_EWMA_ALPHA * latency) + ((1.0 - SMART_CONNECT_EWMA_ALPHA) * stats.latency_ewma_ms)
        )
        stats.success_count += 1
        stats.consecutive_failures = 0
        stats.last_success_at = timestamp
        stats.cooldown_until = None
        stats.add_event(QUALITY_EVENT_LATENCY, timestamp=timestamp, success=True, latency_ms=latency)
        return stats

    def record_failure(
        self,
        profile_id: str,
        *,
        checked_at: str | None = None,
        message: str | None = None,
    ) -> ServerQualityStats:
        stats = self._stats_for(profile_id)
        timestamp = checked_at or utc_now_iso()
        stats.samples += 1
        stats.failure_count += 1
        stats.consecutive_failures += 1
        stats.last_failure_at = timestamp
        stats.last_checked_at = timestamp
        if stats.consecutive_failures >= 2:
            stats.cooldown_until = self._iso_after_minutes(SMART_CONNECT_FAILURE_COOLDOWN_MINUTES)
        stats.add_event(QUALITY_EVENT_FAILURE, timestamp=timestamp, success=False, message=message)
        return stats

    def record_success(self, profile_id: str, *, checked_at: str | None = None) -> ServerQualityStats:
        stats = self._stats_for(profile_id)
        timestamp = checked_at or utc_now_iso()
        stats.samples += 1
        stats.success_count += 1
        stats.consecutive_failures = 0
        stats.last_success_at = timestamp
        stats.last_checked_at = timestamp
        stats.cooldown_until = None
        stats.add_event(QUALITY_EVENT_SUCCESS, timestamp=timestamp, success=True)
        return stats

    def record_usage(
        self,
        profile_id: str,
        *,
        connected_seconds: int,
        download_bytes: int,
        upload_bytes: int,
        connected_at: str | None = None,
        disconnected_at: str | None = None,
    ) -> ServerQualityStats:
        stats = self._stats_for(profile_id)
        stats.record_usage(
            connected_seconds=connected_seconds,
            download_bytes=download_bytes,
            upload_bytes=upload_bytes,
            connected_at=connected_at,
            disconnected_at=disconnected_at,
        )
        return stats

    def prune_missing_profiles(self, profile_ids: Iterable[str]) -> None:
        valid_ids = {str(profile_id) for profile_id in profile_ids if str(profile_id)}
        self.quality_stats = {
            profile_id: stats
            for profile_id, stats in self.quality_stats.items()
            if profile_id in valid_ids
        }
        for group in self.smart_groups:
            group.profile_ids = [profile_id for profile_id in group.profile_ids if profile_id in valid_ids]

    def _limit_by_strategy(self, profiles: list[ServerProfile], strategy: str, limit: int) -> list[ServerProfile]:
        normalized_strategy = normalize_smart_strategy(strategy)
        if normalized_strategy == SMART_STRATEGY_FAILOVER_ORDER:
            return profiles[: max(1, int(limit))]
        if normalized_strategy == SMART_STRATEGY_LATENCY:
            return sorted(
                profiles,
                key=lambda item: (
                    item.latency_ms is None,
                    item.latency_ms if item.latency_ms is not None else SMART_CONNECT_UNKNOWN_LATENCY_MS,
                    item.name.lower(),
                    item.id,
                ),
            )[: max(1, int(limit))]
        return self._limit_by_score(profiles, limit)

    def _limit_by_score(self, profiles: list[ServerProfile], limit: int) -> list[ServerProfile]:
        return [candidate.profile for candidate in self.rank_candidates(profiles)[: max(1, int(limit))]]

    def _limit_by_latency(
        self,
        profiles: list[ServerProfile],
        limit: int,
        *,
        latency_overrides: dict[str, int | None] | None = None,
    ) -> list[ServerProfile]:
        overrides = latency_overrides or {}
        return sorted(
            profiles,
            key=lambda item: (
                self._effective_latency(
                    item,
                    self.quality_stats.get(item.id),
                    overrides.get(item.id) if item.id in overrides else None,
                    item.id in overrides,
                ),
                item.name.lower(),
                item.id,
            ),
        )[: max(1, int(limit))]

    def _explicit_group_for_profile(self, profile: ServerProfile) -> SmartGroup | None:
        for group in self.smart_groups:
            if group.enabled and profile.id in group.profile_ids:
                return group
        return None

    def _matching_group(self, subscription_id: str | None, source_group: str | None) -> SmartGroup | None:
        for group in self.smart_groups:
            if group.subscription_id == subscription_id and group.source_group == source_group:
                return group
        return None

    def _active_strategy(self, profile: ServerProfile | None) -> str:
        if profile is None:
            return SMART_STRATEGY_SMART
        group = self._explicit_group_for_profile(profile)
        if group:
            return normalize_smart_strategy(group.strategy)
        return SMART_STRATEGY_SMART

    @staticmethod
    def _rotate_after_profile(profiles: list[ServerProfile], profile_id: str) -> list[ServerProfile]:
        for index, profile in enumerate(profiles):
            if profile.id == profile_id:
                return profiles[index + 1 :] + profiles[:index]
        return profiles

    @staticmethod
    def _default_group_name(profile: ServerProfile) -> str:
        source_group = str(profile.group or "").strip()
        if source_group:
            return f"Failover: {source_group}"
        source_name = str(profile.source_name or "").strip()
        if source_name:
            return f"Failover: {source_name}"
        return "Failover Group"

    def _stats_for(self, profile_id: str) -> ServerQualityStats:
        clean_id = str(profile_id or "").strip()
        if not clean_id:
            raise ValueError("profile_id is required")
        stats = self.quality_stats.get(clean_id)
        if stats is None:
            stats = ServerQualityStats(profile_id=clean_id)
            self.quality_stats[clean_id] = stats
        return stats

    @staticmethod
    def _effective_latency(
        profile: ServerProfile,
        stats: ServerQualityStats | None,
        latency_override_ms: int | None,
        latency_override_present: bool = False,
    ) -> float:
        if latency_override_present and latency_override_ms is None:
            return SMART_CONNECT_UNREACHABLE_LATENCY_MS
        if latency_override_ms is not None:
            return float(max(1, int(latency_override_ms)))
        if stats and stats.latency_ewma_ms is not None:
            return float(stats.latency_ewma_ms)
        if profile.latency_ms is not None:
            return float(max(1, int(profile.latency_ms)))
        if stats and stats.last_latency_ms is not None:
            return float(max(1, int(stats.last_latency_ms)))
        return SMART_CONNECT_UNKNOWN_LATENCY_MS

    @staticmethod
    def _is_usable_profile(profile: ServerProfile) -> bool:
        try:
            port = int(profile.port or 0)
        except (TypeError, ValueError):
            port = 0
        return bool(str(profile.id or "").strip() and str(profile.address or "").strip() and port > 0)

    @staticmethod
    def _is_on_cooldown(stats: ServerQualityStats) -> bool:
        if not stats.cooldown_until:
            return False
        try:
            cooldown = datetime.fromisoformat(stats.cooldown_until)
        except ValueError:
            return False
        if cooldown.tzinfo is None:
            cooldown = cooldown.replace(tzinfo=timezone.utc)
        return cooldown > datetime.now(timezone.utc)

    @staticmethod
    def _iso_after_minutes(minutes: int) -> str:
        value = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=max(1, int(minutes)))
        return value.isoformat()
