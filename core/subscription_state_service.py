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

"""Local state mutations for subscriptions and their profiles."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from core.subscription_importer import SubscriptionImporter
from core.subscription_types import SubscriptionFetchResult
from models.profile import Subscription, VlessProfile


ProfileKeyFunc = Callable[[VlessProfile], str]
ErrorFormatter = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class SubscriptionProfileCountResult:
    counts: dict[str, int]
    changed: bool = False


@dataclass(frozen=True, slots=True)
class SubscriptionStateChange:
    subscriptions: list[Subscription]
    profiles: list[VlessProfile]
    active_profile_id: str | None
    profile_counts: dict[str, int]
    updated: int = 0
    failed: tuple[str, ...] = field(default_factory=tuple)


class SubscriptionStateService:
    """Applies fetched subscription data to local models without file or GUI dependencies."""

    def __init__(self, profile_key: ProfileKeyFunc | None = None) -> None:
        self.profile_key = profile_key or SubscriptionImporter.profile_key

    @staticmethod
    def subscription_by_id(subscriptions: Sequence[Subscription], subscription_id: str) -> Subscription | None:
        return next((item for item in subscriptions if item.id == subscription_id), None)

    @staticmethod
    def profile_counts(profiles: Sequence[VlessProfile]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for profile in profiles:
            if not profile.subscription_id:
                continue
            counts[profile.subscription_id] = counts.get(profile.subscription_id, 0) + 1
        return counts

    def sync_profile_counts(
        self,
        subscriptions: Sequence[Subscription],
        profiles: Sequence[VlessProfile],
    ) -> SubscriptionProfileCountResult:
        counts = self.profile_counts(profiles)
        changed = False
        for subscription in subscriptions:
            actual_count = counts.get(subscription.id, 0)
            if subscription.profile_count != actual_count:
                subscription.profile_count = actual_count
                changed = True
        return SubscriptionProfileCountResult(counts=counts, changed=changed)

    def apply_update(
        self,
        *,
        subscriptions: Sequence[Subscription],
        profiles: Sequence[VlessProfile],
        active_profile_id: str | None,
        subscription: Subscription,
        incoming_profiles: Sequence[VlessProfile],
    ) -> SubscriptionStateChange:
        active_before = self._profile_by_id(profiles, active_profile_id)
        active_key = self.profile_key(active_before) if active_before else None
        old_subscription_profiles = [profile for profile in profiles if profile.subscription_id == subscription.id]
        other_profiles = [profile for profile in profiles if profile.subscription_id != subscription.id]
        merged_profiles = self._merge_subscription_profiles(old_subscription_profiles, incoming_profiles)
        subscription.profile_count = len(merged_profiles)
        next_profiles = [*other_profiles, *merged_profiles]
        next_subscriptions = self._replace_subscription(subscriptions, subscription)
        sync = self.sync_profile_counts(next_subscriptions, next_profiles)
        next_active_id = self._restore_active_profile_id(
            active_profile_id,
            active_key,
            next_profiles,
            merged_profiles,
        )
        return SubscriptionStateChange(
            subscriptions=next_subscriptions,
            profiles=next_profiles,
            active_profile_id=next_active_id,
            profile_counts=sync.counts,
            updated=1,
        )

    def record_error(
        self,
        *,
        subscriptions: Sequence[Subscription],
        profiles: Sequence[VlessProfile],
        active_profile_id: str | None,
        subscription: Subscription,
        error: str,
    ) -> SubscriptionStateChange:
        subscription.last_error = error
        next_subscriptions = self._replace_subscription(subscriptions, subscription)
        sync = self.sync_profile_counts(next_subscriptions, profiles)
        return SubscriptionStateChange(
            subscriptions=next_subscriptions,
            profiles=list(profiles),
            active_profile_id=active_profile_id,
            profile_counts=sync.counts,
            failed=(subscription.name,),
        )

    def apply_batch_results(
        self,
        *,
        subscriptions: Sequence[Subscription],
        profiles: Sequence[VlessProfile],
        active_profile_id: str | None,
        results: Sequence[SubscriptionFetchResult],
        error_formatter: ErrorFormatter | None = None,
    ) -> SubscriptionStateChange:
        next_subscriptions = list(subscriptions)
        next_profiles = list(profiles)
        next_active_profile_id = active_profile_id
        updated = 0
        failed: list[str] = []
        for result in results:
            if result.success:
                change = self.apply_update(
                    subscriptions=next_subscriptions,
                    profiles=next_profiles,
                    active_profile_id=next_active_profile_id,
                    subscription=result.subscription,
                    incoming_profiles=result.profiles,
                )
                next_subscriptions = change.subscriptions
                next_profiles = change.profiles
                next_active_profile_id = change.active_profile_id
                updated += 1
                continue

            message = self._format_error(result.error, error_formatter)
            error_change = self.record_error(
                subscriptions=next_subscriptions,
                profiles=next_profiles,
                active_profile_id=next_active_profile_id,
                subscription=result.subscription,
                error=message,
            )
            next_subscriptions = error_change.subscriptions
            next_profiles = error_change.profiles
            failed.append(result.subscription.name)

        sync = self.sync_profile_counts(next_subscriptions, next_profiles)
        return SubscriptionStateChange(
            subscriptions=next_subscriptions,
            profiles=next_profiles,
            active_profile_id=next_active_profile_id,
            profile_counts=sync.counts,
            updated=updated,
            failed=tuple(failed),
        )

    def delete_subscription(
        self,
        *,
        subscriptions: Sequence[Subscription],
        profiles: Sequence[VlessProfile],
        active_profile_id: str | None,
        subscription_id: str,
    ) -> SubscriptionStateChange:
        next_subscriptions = [item for item in subscriptions if item.id != subscription_id]
        next_profiles = [profile for profile in profiles if profile.subscription_id != subscription_id]
        next_active_id = active_profile_id if self._profile_by_id(next_profiles, active_profile_id) else ""
        if not next_active_id and next_profiles:
            next_active_id = next_profiles[0].id
        sync = self.sync_profile_counts(next_subscriptions, next_profiles)
        return SubscriptionStateChange(
            subscriptions=next_subscriptions,
            profiles=next_profiles,
            active_profile_id=next_active_id,
            profile_counts=sync.counts,
        )

    def _merge_subscription_profiles(
        self,
        existing_profiles: Sequence[VlessProfile],
        incoming_profiles: Sequence[VlessProfile],
    ) -> list[VlessProfile]:
        existing_by_key: dict[str, deque[VlessProfile]] = {}
        for profile in existing_profiles:
            key = self.profile_key(profile)
            existing_by_key.setdefault(key, deque()).append(profile)

        merged: list[VlessProfile] = []
        for incoming in incoming_profiles:
            key = self.profile_key(incoming)
            existing_profiles_for_key = existing_by_key.get(key)
            existing = existing_profiles_for_key.popleft() if existing_profiles_for_key else None
            if existing is not None:
                incoming.id = existing.id
                incoming.created_at = existing.created_at
                incoming.latency_ms = existing.latency_ms
                incoming.latency_checked_at = existing.latency_checked_at
            merged.append(incoming)
        return merged

    def _restore_active_profile_id(
        self,
        active_profile_id: str | None,
        active_key: str | None,
        profiles: Sequence[VlessProfile],
        merged_profiles: Sequence[VlessProfile],
    ) -> str | None:
        next_active_id = active_profile_id
        if active_key and not self._profile_by_id(profiles, active_profile_id):
            restored = next((profile for profile in merged_profiles if self.profile_key(profile) == active_key), None)
            next_active_id = restored.id if restored else ""
        if not next_active_id and profiles:
            next_active_id = profiles[0].id
        return next_active_id

    @staticmethod
    def _profile_by_id(profiles: Sequence[VlessProfile], profile_id: str | None) -> VlessProfile | None:
        if not profile_id:
            return None
        return next((profile for profile in profiles if profile.id == profile_id), None)

    @staticmethod
    def _replace_subscription(
        subscriptions: Sequence[Subscription],
        subscription: Subscription,
    ) -> list[Subscription]:
        replaced = False
        next_subscriptions: list[Subscription] = []
        for item in subscriptions:
            if item.id == subscription.id:
                next_subscriptions.append(subscription)
                replaced = True
            else:
                next_subscriptions.append(item)
        if not replaced:
            next_subscriptions.append(subscription)
        return next_subscriptions

    @staticmethod
    def _format_error(error: str | None, formatter: ErrorFormatter | None) -> str:
        text = str(error or "ошибка обновления")
        return formatter(text) if formatter else text
