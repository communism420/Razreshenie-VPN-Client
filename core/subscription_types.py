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

"""Shared subscription import and fetch types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from models.profile import Subscription, VlessProfile


class SubscriptionError(ValueError):
    """Ошибка загрузки или разбора подписки."""


@dataclass(frozen=True, slots=True)
class ImportProgress:
    current: int
    total: int
    source: str
    imported: int
    errors: int = 0


ProgressCallback = Callable[[ImportProgress], None]


@dataclass(frozen=True, slots=True)
class SubscriptionFetchProgress:
    current: int
    total: int
    subscription: Subscription
    updated: int
    errors: int = 0


@dataclass(slots=True)
class SubscriptionFetchResult:
    subscription: Subscription
    profiles: list[VlessProfile] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


SubscriptionProgressCallback = Callable[[SubscriptionFetchProgress], None]
