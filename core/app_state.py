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

"""Загрузка и сохранение состояния приложения."""

from __future__ import annotations

from models.connection import ServerQualityStats, SmartGroup
from models.profile import Subscription, VlessProfile
from models.rules import SplitRules
from models.settings import AppSettings
from utils import paths
from utils.storage import read_json, write_json
from core.vless_parser import get_karing_server_name


def load_settings() -> AppSettings:
    return AppSettings.from_dict(read_json(paths.settings_path(), {}))


def save_settings(settings: AppSettings) -> None:
    write_json(paths.settings_path(), settings.to_dict())


def load_profiles() -> list[VlessProfile]:
    profiles = [VlessProfile.from_dict(item) for item in read_json(paths.profiles_path(), [])]
    changed = False
    for profile in profiles:
        if not profile.raw_url:
            continue
        provider_name = get_karing_server_name(profile.raw_url)
        if not provider_name or provider_name == profile.address:
            continue
        fallback_names = {"", "Новый профиль", profile.address, f"{profile.address}:{profile.port}"}
        if profile.subscription_id or profile.name in fallback_names:
            if profile.name != provider_name:
                profile.name = provider_name
                profile.touch()
                changed = True
    if changed:
        save_profiles(profiles)
    return profiles


def save_profiles(profiles: list[VlessProfile]) -> None:
    write_json(paths.profiles_path(), [profile.to_dict() for profile in profiles])


def load_subscriptions() -> list[Subscription]:
    return [Subscription.from_dict(item) for item in read_json(paths.subscriptions_path(), [])]


def save_subscriptions(subscriptions: list[Subscription]) -> None:
    write_json(paths.subscriptions_path(), [subscription.to_dict() for subscription in subscriptions])


def load_split_rules() -> SplitRules:
    return SplitRules.from_dict(read_json(paths.rules_path(), {}))


def save_split_rules(rules: SplitRules) -> None:
    write_json(paths.rules_path(), rules.to_dict())


def load_quality_stats() -> dict[str, ServerQualityStats]:
    raw = read_json(paths.quality_stats_path(), {})
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.values()
    else:
        items = []
    result: dict[str, ServerQualityStats] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        stats = ServerQualityStats.from_dict(item)
        if stats.profile_id:
            result[stats.profile_id] = stats
    return result


def save_quality_stats(stats: dict[str, ServerQualityStats]) -> None:
    write_json(
        paths.quality_stats_path(),
        {
            profile_id: item.to_dict()
            for profile_id, item in sorted(stats.items())
            if profile_id and item.profile_id
        },
    )


def load_smart_groups() -> list[SmartGroup]:
    raw = read_json(paths.smart_groups_path(), [])
    if not isinstance(raw, list):
        return []
    return [SmartGroup.from_dict(item) for item in raw if isinstance(item, dict)]


def save_smart_groups(groups: list[SmartGroup]) -> None:
    write_json(paths.smart_groups_path(), [group.to_dict() for group in groups])
