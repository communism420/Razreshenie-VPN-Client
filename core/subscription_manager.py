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

"""Facade for subscription import, batch parsing and HTTP updates."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Iterable
from pathlib import Path

from core.subscription_cache import SubscriptionCache
from core.subscription_fetcher import FETCH_ATTEMPTS, FETCH_TIMEOUT_SECONDS, REQUEST_HEADERS, SubscriptionFetcher
from core.subscription_importer import SubscriptionImporter
from core.subscription_types import (
    ImportProgress,
    ProgressCallback,
    SubscriptionError,
    SubscriptionFetchProgress,
    SubscriptionFetchResult,
    SubscriptionProgressCallback,
)
from models.profile import Subscription, VlessProfile


class SubscriptionManager:
    """Backward-compatible subscription service used by GUI and self-checks."""

    def __init__(
        self,
        importer: SubscriptionImporter | None = None,
        fetcher: SubscriptionFetcher | None = None,
        cache: SubscriptionCache | None = None,
    ) -> None:
        self.importer = importer or SubscriptionImporter()
        self.cache = cache or SubscriptionCache()
        self.fetcher = fetcher or SubscriptionFetcher(self.importer, self.cache)

    def fetch_many(
        self,
        subscriptions: Iterable[Subscription],
        *,
        max_workers: int = 3,
        progress_callback: SubscriptionProgressCallback | None = None,
    ) -> list[SubscriptionFetchResult]:
        items = list(subscriptions)
        if not items:
            return []

        results: list[SubscriptionFetchResult] = []
        total = len(items)
        completed = 0
        errors = 0
        worker_count = max(1, min(max_workers, total))
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="SubscriptionBatch") as executor:
            future_map = {executor.submit(self.fetch, subscription): subscription for subscription in items}
            for future in as_completed(future_map):
                subscription = future_map[future]
                try:
                    profiles, updated_subscription = future.result()
                except Exception as exc:
                    message = str(exc)
                    subscription.last_error = message
                    result = SubscriptionFetchResult(subscription=subscription, error=message)
                    errors += 1
                else:
                    result = SubscriptionFetchResult(subscription=updated_subscription, profiles=profiles)
                results.append(result)
                completed += 1
                if progress_callback:
                    progress_callback(
                        SubscriptionFetchProgress(
                            current=completed,
                            total=total,
                            subscription=result.subscription,
                            updated=sum(1 for item in results if item.success),
                            errors=errors,
                        )
                    )
        return results

    def fetch(self, subscription: Subscription) -> tuple[list[VlessProfile], Subscription]:
        return self.fetcher.fetch(subscription)

    def parse_text(self, text: str, subscription_id: str | None = None) -> list[VlessProfile]:
        return self.importer.parse_text(text, subscription_id)

    def parse_many(
        self,
        sources: Iterable[tuple[str, str]],
        subscription_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[VlessProfile]:
        return self.importer.parse_many(sources, subscription_id, progress_callback)

    def parse_files(
        self,
        file_paths: Iterable[str | Path],
        subscription_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[VlessProfile]:
        return self.importer.parse_files(file_paths, subscription_id, progress_callback)

    @staticmethod
    def profile_key(profile: VlessProfile) -> str:
        return SubscriptionImporter.profile_key(profile)


__all__ = [
    "FETCH_ATTEMPTS",
    "FETCH_TIMEOUT_SECONDS",
    "REQUEST_HEADERS",
    "ImportProgress",
    "ProgressCallback",
    "SubscriptionError",
    "SubscriptionFetchProgress",
    "SubscriptionFetchResult",
    "SubscriptionManager",
    "SubscriptionProgressCallback",
]
