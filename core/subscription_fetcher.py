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

"""HTTP fetch and cache fallback strategy for subscriptions."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

from core.subscription_cache import SubscriptionCache
from core.subscription_importer import SubscriptionImporter
from core.subscription_types import SubscriptionError
from models.profile import Subscription, VlessProfile, utc_now_iso


FETCH_ATTEMPTS = 3
FETCH_TIMEOUT_SECONDS = 15
REQUEST_HEADERS = {
    "User-Agent": "RazreshenieVPN/1.1",
    "Accept": "text/plain, application/json, */*",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass(slots=True)
class FetchResult:
    profiles: list[VlessProfile]
    payload: str
    etag: str | None = None
    last_modified: str | None = None
    from_cache: bool = False
    label: str = "primary"


class SubscriptionFetcher:
    """Downloads subscriptions and chooses the best available snapshot."""

    def __init__(
        self,
        importer: SubscriptionImporter | None = None,
        cache: SubscriptionCache | None = None,
    ) -> None:
        self.importer = importer or SubscriptionImporter()
        self.cache = cache or SubscriptionCache()

    def fetch(self, subscription: Subscription) -> tuple[list[VlessProfile], Subscription]:
        best_result: FetchResult | None = None
        errors: list[str] = []
        expected_count = max(0, int(subscription.profile_count or 0))

        try:
            best_result = self._fetch_once(subscription, label="primary", conditional=True)
        except (requests.RequestException, SubscriptionError) as exc:
            errors.append(str(exc))

        if best_result and (not expected_count or len(best_result.profiles) >= expected_count):
            return self._finish_fetch(subscription, best_result)

        # Extra requests are only useful against temporarily incomplete
        # responses. Run them in parallel and pick one best snapshot.
        retry_count = FETCH_ATTEMPTS - 1
        if retry_count > 0:
            retry_results = self._fetch_retries(subscription, retry_count, errors)
            for retry_result in retry_results:
                best_result = self._choose_better_result(best_result, retry_result)

        cached = self._fetch_from_cache(subscription, label="last-good")
        if cached:
            best_result = self._choose_better_result(best_result, cached)

        if not best_result:
            message = errors[-1] if errors else "пустой ответ"
            subscription.last_error = message
            raise SubscriptionError(f"Не удалось загрузить подписку: {message}")

        return self._finish_fetch(subscription, best_result)

    def _fetch_once(
        self,
        subscription: Subscription,
        *,
        label: str,
        conditional: bool = False,
        no_cache: bool = False,
    ) -> FetchResult:
        headers = dict(REQUEST_HEADERS)
        if conditional:
            if subscription.etag:
                headers["If-None-Match"] = subscription.etag
            if subscription.last_modified:
                headers["If-Modified-Since"] = subscription.last_modified
        if no_cache:
            headers["Cache-Control"] = "no-cache, no-store"
            headers["Pragma"] = "no-cache"
        response = requests.get(
            subscription.url,
            timeout=FETCH_TIMEOUT_SECONDS,
            headers=headers,
        )
        if response.status_code == 304:
            cached = self._fetch_from_cache(subscription, label=f"{label}-304")
            if cached:
                cached.etag = subscription.etag
                cached.last_modified = subscription.last_modified
                return cached
            raise SubscriptionError("сервер вернул 304, но локальный кэш пуст")
        response.raise_for_status()
        payload = response.text
        return FetchResult(
            profiles=self.importer.parse_text(payload, subscription.id),
            payload=payload,
            etag=response.headers.get("ETag") or subscription.etag,
            last_modified=response.headers.get("Last-Modified") or subscription.last_modified,
            from_cache=False,
            label=label,
        )

    def _fetch_retries(
        self,
        subscription: Subscription,
        retry_count: int,
        errors: list[str],
    ) -> list[FetchResult]:
        results: list[FetchResult] = []
        variants = [
            {"label": "retry-direct", "conditional": False, "no_cache": False},
            {"label": "retry-no-cache", "conditional": False, "no_cache": True},
        ][:retry_count]
        with ThreadPoolExecutor(max_workers=max(1, retry_count), thread_name_prefix="SubscriptionFetch") as executor:
            futures = [
                executor.submit(self._fetch_once, subscription, **variant)
                for variant in variants
            ]
            for future in as_completed(futures):
                try:
                    fetched_result = future.result()
                except (requests.RequestException, SubscriptionError) as exc:
                    errors.append(str(exc))
                    continue
                results.append(fetched_result)
        return results

    def _choose_better_result(
        self,
        current: FetchResult | None,
        candidate: FetchResult,
    ) -> FetchResult:
        if current is None:
            return candidate
        if len(candidate.profiles) != len(current.profiles):
            return candidate if len(candidate.profiles) > len(current.profiles) else current
        if candidate.from_cache != current.from_cache:
            return current if current.from_cache is False else candidate
        if len(candidate.payload) > len(current.payload):
            return candidate
        return current

    def _fetch_from_cache(self, subscription: Subscription, *, label: str) -> FetchResult | None:
        payload = self.cache.read_payload(subscription)
        if payload is None:
            return None
        try:
            profiles = self.importer.parse_text(payload, subscription.id)
        except SubscriptionError:
            return None
        return FetchResult(
            profiles=profiles,
            payload=payload,
            etag=subscription.etag,
            last_modified=subscription.last_modified,
            from_cache=True,
            label=label,
        )

    def _finish_fetch(
        self,
        subscription: Subscription,
        result: FetchResult,
    ) -> tuple[list[VlessProfile], Subscription]:
        subscription.last_update_at = utc_now_iso()
        subscription.last_error = None
        subscription.profile_count = len(result.profiles)
        if result.etag:
            subscription.etag = result.etag
        if result.last_modified:
            subscription.last_modified = result.last_modified
        if result.payload:
            subscription.last_content_hash = hashlib.sha256(result.payload.encode("utf-8", errors="replace")).hexdigest()
            if not result.from_cache:
                self.cache.write_payload(subscription, result.payload)
        return result.profiles, subscription
