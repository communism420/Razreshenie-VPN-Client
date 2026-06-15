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

"""Local last-good payload cache for subscriptions."""

from __future__ import annotations

import hashlib
from pathlib import Path

from models.profile import Subscription, utc_now_iso
from utils import paths


class SubscriptionCache:
    """Stores raw subscription payload snapshots for offline fallback."""

    def read_payload(self, subscription: Subscription) -> str | None:
        try:
            payload = self.cache_path(subscription).read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return None
        return payload if payload.strip() else None

    def write_payload(self, subscription: Subscription, payload: str) -> None:
        if not payload.strip():
            return
        try:
            cache_path = self.cache_path(subscription)
            tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(cache_path)
        except OSError:
            return
        subscription.last_cached_at = utc_now_iso()

    def cache_path(self, subscription: Subscription) -> Path:
        source = subscription.id or subscription.url or subscription.name
        digest = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:32]
        return self.cache_dir() / f"{digest}.txt"

    @staticmethod
    def cache_dir() -> Path:
        cache_dir = paths.ensure_app_dirs()["downloads"] / "subscription-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir
