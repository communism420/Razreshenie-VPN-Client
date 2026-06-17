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

"""Local state mutations for server profiles."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from core.smart_connect import SmartConnectManager
from models.profile import VlessProfile, utc_now_iso


TimestampFactory = Callable[[], str]


@dataclass(frozen=True, slots=True)
class ProfileStateChange:
    profiles: list[VlessProfile]
    active_profile_id: str | None
    changed_profile_ids: tuple[str, ...] = field(default_factory=tuple)
    imported_count: int = 0


@dataclass(frozen=True, slots=True)
class ProfileLatencyBatchResult:
    changed_profile_ids: tuple[str, ...]
    checked_at: str


class ProfileStateService:
    """Applies profile list changes without GUI or persistence dependencies."""

    def __init__(
        self,
        smart_connect: SmartConnectManager,
        *,
        timestamp_factory: TimestampFactory = utc_now_iso,
    ) -> None:
        self.smart_connect = smart_connect
        self.timestamp_factory = timestamp_factory

    @staticmethod
    def profile_index(profiles: Sequence[VlessProfile]) -> dict[str, VlessProfile]:
        return {profile.id: profile for profile in profiles}

    @staticmethod
    def profile_by_id(profiles: Sequence[VlessProfile], profile_id: str | None) -> VlessProfile | None:
        target = str(profile_id or "").strip()
        if not target:
            return None
        return next((profile for profile in profiles if profile.id == target), None)

    def apply_import(
        self,
        *,
        profiles: Sequence[VlessProfile],
        imported_profiles: Sequence[VlessProfile],
        active_profile_id: str | None,
    ) -> ProfileStateChange:
        imported = list(imported_profiles)
        if not imported:
            return ProfileStateChange(profiles=list(profiles), active_profile_id=active_profile_id)
        next_profiles = [*profiles, *imported]
        return ProfileStateChange(
            profiles=next_profiles,
            active_profile_id=imported[0].id,
            changed_profile_ids=tuple(profile.id for profile in imported),
            imported_count=len(imported),
        )

    def replace_profile(
        self,
        *,
        profiles: Sequence[VlessProfile],
        profile_id: str,
        updated_profile: VlessProfile,
        active_profile_id: str | None,
    ) -> ProfileStateChange:
        target = str(profile_id or "").strip()
        if not target:
            return ProfileStateChange(profiles=list(profiles), active_profile_id=active_profile_id)

        replaced = False
        next_profiles: list[VlessProfile] = []
        for profile in profiles:
            if profile.id == target:
                updated_profile.touch()
                next_profiles.append(updated_profile)
                replaced = True
            else:
                next_profiles.append(profile)

        if not replaced:
            return ProfileStateChange(profiles=next_profiles, active_profile_id=active_profile_id)

        next_active_id = updated_profile.id if active_profile_id == target else active_profile_id
        return ProfileStateChange(
            profiles=next_profiles,
            active_profile_id=next_active_id,
            changed_profile_ids=(updated_profile.id,),
        )

    def delete_profile(
        self,
        *,
        profiles: Sequence[VlessProfile],
        profile_id: str,
        active_profile_id: str | None,
    ) -> ProfileStateChange:
        target = str(profile_id or "").strip()
        next_profiles = [profile for profile in profiles if profile.id != target]
        next_active_id = active_profile_id
        if active_profile_id == target:
            next_active_id = next_profiles[0].id if next_profiles else None
        return ProfileStateChange(
            profiles=next_profiles,
            active_profile_id=next_active_id,
            changed_profile_ids=(target,) if len(next_profiles) != len(profiles) else (),
        )

    @staticmethod
    def sort_by_latency(profiles: Sequence[VlessProfile], active_profile_id: str | None) -> ProfileStateChange:
        next_profiles = sorted(
            profiles,
            key=lambda profile: (
                profile.latency_ms is None,
                profile.latency_ms or 10**9,
                profile.name.lower(),
            ),
        )
        return ProfileStateChange(profiles=next_profiles, active_profile_id=active_profile_id)

    def apply_latency_batch(
        self,
        profiles: Sequence[VlessProfile],
        results: Sequence[tuple[str, int | None]],
        *,
        checked_at: str | None = None,
    ) -> ProfileLatencyBatchResult:
        timestamp = checked_at or self.timestamp_factory()
        changed_ids: list[str] = []
        by_id = self.profile_index(profiles)
        for profile_id, latency in results:
            profile = by_id.get(str(profile_id or "").strip())
            if not profile:
                continue
            profile.latency_ms = latency
            profile.latency_checked_at = timestamp
            profile.updated_at = timestamp
            self.smart_connect.record_latency(profile.id, latency, checked_at=timestamp)
            changed_ids.append(profile.id)
        return ProfileLatencyBatchResult(changed_profile_ids=tuple(changed_ids), checked_at=timestamp)

    def set_profile_latency(
        self,
        profiles: Sequence[VlessProfile],
        profile_id: str,
        latency: int | None,
        *,
        checked_at: str | None = None,
    ) -> VlessProfile | None:
        result = self.apply_latency_batch(profiles, [(profile_id, latency)], checked_at=checked_at)
        if not result.changed_profile_ids:
            return None
        return self.profile_by_id(profiles, result.changed_profile_ids[0])
