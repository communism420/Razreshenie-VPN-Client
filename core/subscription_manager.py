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

"""Импорт подписок с поддерживаемыми ссылками серверов."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from core.server_parser import (
    SUPPORTED_OUTBOUND_TYPES,
    SUPPORTED_URI_SCHEMES,
    ServerParseError,
    is_supported_outbound_type,
    parse_outbound,
    parse_server_uri,
)
from core.subscription_formats import parse_subscription_payload
from models.profile import Subscription, VlessProfile
from utils import paths


class SubscriptionError(ValueError):
    """Ошибка загрузки подписки."""


FETCH_ATTEMPTS = 3
FETCH_TIMEOUT_SECONDS = 15
REQUEST_HEADERS = {
    "User-Agent": "RazreshenieVPN/1.1",
    "Accept": "text/plain, application/json, */*",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass(slots=True)
class _FetchResult:
    profiles: list[VlessProfile]
    payload: str
    etag: str | None = None
    last_modified: str | None = None
    from_cache: bool = False
    label: str = "primary"


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class SubscriptionManager:
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
        best_result: _FetchResult | None = None
        errors: list[str] = []
        expected_count = max(0, int(subscription.profile_count or 0))

        try:
            best_result = self._fetch_once(subscription, label="primary", conditional=True)
        except (requests.RequestException, SubscriptionError) as exc:
            errors.append(str(exc))

        if best_result and (not expected_count or len(best_result.profiles) >= expected_count):
            return self._finish_fetch(subscription, best_result)

        # Повторные запросы нужны только против временно неполного ответа.
        # Они идут параллельно, а не последовательно, и не суммируются между
        # собой: берем один самый полный снимок подписки.
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
    ) -> _FetchResult:
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
        return _FetchResult(
            profiles=self.parse_text(payload, subscription.id),
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
    ) -> list[_FetchResult]:
        results: list[_FetchResult] = []
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
        current: _FetchResult | None,
        candidate: _FetchResult,
    ) -> _FetchResult:
        if current is None:
            return candidate
        if len(candidate.profiles) != len(current.profiles):
            return candidate if len(candidate.profiles) > len(current.profiles) else current
        if candidate.from_cache != current.from_cache:
            return current if current.from_cache is False else candidate
        if len(candidate.payload) > len(current.payload):
            return candidate
        return current

    def _fetch_from_cache(self, subscription: Subscription, *, label: str) -> _FetchResult | None:
        try:
            payload = self._cache_path(subscription).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if not payload.strip():
            return None
        try:
            profiles = self.parse_text(payload, subscription.id)
        except SubscriptionError:
            return None
        return _FetchResult(
            profiles=profiles,
            payload=payload,
            etag=subscription.etag,
            last_modified=subscription.last_modified,
            from_cache=True,
            label=label,
        )

    def _write_cache(self, subscription: Subscription, payload: str) -> None:
        if not payload.strip():
            return
        try:
            cache_path = self._cache_path(subscription)
            tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(cache_path)
        except OSError:
            return
        subscription.last_cached_at = _utc_now()

    def _cache_path(self, subscription: Subscription) -> Path:
        source = subscription.id or subscription.url or subscription.name
        digest = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:32]
        return self._cache_dir() / f"{digest}.txt"

    @staticmethod
    def _cache_dir() -> Path:
        cache_dir = paths.ensure_app_dirs()["downloads"] / "subscription-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _finish_fetch(
        self,
        subscription: Subscription,
        result: _FetchResult,
    ) -> tuple[list[VlessProfile], Subscription]:
        subscription.last_update_at = _utc_now()
        subscription.last_error = None
        subscription.profile_count = len(result.profiles)
        if result.etag:
            subscription.etag = result.etag
        if result.last_modified:
            subscription.last_modified = result.last_modified
        if result.payload:
            subscription.last_content_hash = hashlib.sha256(result.payload.encode("utf-8", errors="replace")).hexdigest()
            if not result.from_cache:
                self._write_cache(subscription, result.payload)
        return result.profiles, subscription

    def parse_text(self, text: str, subscription_id: str | None = None) -> list[VlessProfile]:
        payload = self._decode_if_base64(text)
        parsed = parse_subscription_payload(payload, subscription_id)
        profiles: list[VlessProfile] = list(parsed.profiles)
        errors: list[str] = list(parsed.errors)

        if profiles and parsed.format_name != "text":
            return self._append_duplicate_name_suffixes(profiles)

        json_outbounds = self._extract_json_outbounds(payload)
        json_links = self._extract_json_links(payload)

        for outbound in json_outbounds:
            try:
                profile = parse_outbound(outbound, subscription_id=subscription_id)
                profiles.append(profile)
            except ServerParseError as exc:
                errors.append(str(exc))

        # Karing считает каждую запись подписки отдельным сервером, даже если
        # провайдер повторил один и тот же ключ несколько раз. Поэтому здесь
        # намеренно нет дедупликации по endpoint/name/params.
        links = json_links if json_outbounds or json_links else self._extract_links(payload)
        for link in links:
            try:
                profile = parse_server_uri(link, subscription_id=subscription_id)
            except ServerParseError as exc:
                errors.append(str(exc))
                continue
            profiles.append(profile)

        if not profiles:
            details = f": {'; '.join(errors[:3])}" if errors else ""
            raise SubscriptionError(f"В подписке не найдено корректных серверов{details}")
        return self._append_duplicate_name_suffixes(profiles)

    def parse_many(
        self,
        sources: Iterable[tuple[str, str]],
        subscription_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[VlessProfile]:
        source_items = list(sources)
        all_profiles: list[VlessProfile] = []
        errors: list[str] = []
        total = len(source_items)

        for index, (source, text) in enumerate(source_items, start=1):
            source_name = str(source or f"source-{index}")
            try:
                profiles = self.parse_text(str(text or ""), subscription_id)
            except SubscriptionError as exc:
                errors.append(f"{source_name}: {exc}")
            else:
                all_profiles.extend(profiles)
            if progress_callback:
                progress_callback(
                    ImportProgress(
                        current=index,
                        total=total,
                        source=source_name,
                        imported=len(all_profiles),
                        errors=len(errors),
                    )
                )

        if not all_profiles:
            details = f": {'; '.join(errors[:3])}" if errors else ""
            raise SubscriptionError(f"Не удалось импортировать серверы{details}")
        return self._append_duplicate_name_suffixes(all_profiles)

    def parse_files(
        self,
        file_paths: Iterable[str | Path],
        subscription_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[VlessProfile]:
        path_items = [Path(path) for path in file_paths]
        all_profiles: list[VlessProfile] = []
        errors: list[str] = []
        total = len(path_items)

        for index, file_path in enumerate(path_items, start=1):
            source_name = str(file_path)
            try:
                text = file_path.read_text(encoding="utf-8-sig")
                profiles = self.parse_text(text, subscription_id)
            except (OSError, UnicodeError, SubscriptionError) as exc:
                errors.append(f"{source_name}: {exc}")
            else:
                all_profiles.extend(profiles)
            if progress_callback:
                progress_callback(
                    ImportProgress(
                        current=index,
                        total=total,
                        source=source_name,
                        imported=len(all_profiles),
                        errors=len(errors),
                    )
                )

        if not all_profiles:
            details = f": {'; '.join(errors[:3])}" if errors else ""
            raise SubscriptionError(f"Не удалось импортировать файлы{details}")
        return self._append_duplicate_name_suffixes(all_profiles)

    @staticmethod
    def _append_duplicate_name_suffixes(profiles: list[VlessProfile]) -> list[VlessProfile]:
        """Добавляет `-1`, `-2` к повторяющимся именам серверов."""
        totals: dict[str, int] = {}
        for profile in profiles:
            key = SubscriptionManager._name_key(profile.name)
            totals[key] = totals.get(key, 0) + 1

        seen: dict[str, int] = {}
        used_names = {profile.name for profile in profiles}
        for profile in profiles:
            key = SubscriptionManager._name_key(profile.name)
            if totals.get(key, 0) <= 1:
                continue

            occurrence = seen.get(key, 0)
            seen[key] = occurrence + 1
            if occurrence == 0:
                continue

            base_name = profile.name
            suffix_index = occurrence
            candidate = f"{base_name}-{suffix_index}"
            while candidate in used_names:
                suffix_index += 1
                candidate = f"{base_name}-{suffix_index}"
            profile.name = candidate
            used_names.add(candidate)

        return profiles

    @staticmethod
    def _name_key(name: str) -> str:
        return " ".join(str(name or "").casefold().split())

    def _decode_if_base64(self, text: str) -> str:
        raw = text.strip()
        compact = "".join(raw.split())
        if self._looks_like_subscription(raw):
            return text

        for candidate in (raw, compact):
            if not candidate:
                continue
            padding = "=" * (-len(candidate) % 4)
            data = (candidate + padding).encode("ascii", errors="ignore")
            for altchars in (None, b"-_"):
                try:
                    decoded_bytes = base64.b64decode(data, altchars=altchars, validate=True)
                    decoded = decoded_bytes.decode("utf-8", errors="replace")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                if self._looks_like_subscription(decoded):
                    return decoded
        return text

    def _extract_links(self, text: str) -> list[str]:
        links: list[str] = []
        schemes = "|".join(sorted(re.escape(item) for item in SUPPORTED_URI_SCHEMES))
        pattern = re.compile(rf"(?i)({schemes}|ssr)://")
        matches = list(pattern.finditer(text))
        for index, match in enumerate(matches):
            if match.group(1).lower() not in SUPPORTED_URI_SCHEMES:
                continue
            start = match.start()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            chunk = text[start:end]
            newline_positions = [pos for pos in (chunk.find("\n"), chunk.find("\r")) if pos >= 0]
            if newline_positions:
                chunk = chunk[: min(newline_positions)]
            link = self._clean_link(chunk)
            if link:
                links.append(link)
        return links

    def _extract_json_outbounds(self, text: str) -> list[dict[str, Any]]:
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return []

        outbounds: list[dict[str, Any]] = []
        for item in self._walk_json(payload):
            if isinstance(item, dict) and is_supported_outbound_type(item.get("type")):
                outbounds.append(item)
        return outbounds

    def _extract_json_links(self, text: str) -> list[str]:
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return []

        links: list[str] = []
        for item in self._walk_json(payload):
            if isinstance(item, str) and self._contains_supported_uri(item):
                links.extend(self._extract_links(item))
        return links

    def _walk_json(self, value: Any) -> list[Any]:
        result: list[Any] = []
        stack = [value]
        while stack:
            item = stack.pop()
            result.append(item)
            if isinstance(item, dict):
                stack.extend(reversed(list(item.values())))
            elif isinstance(item, list):
                stack.extend(reversed(item))
        return result

    @staticmethod
    def _looks_like_subscription(text: str) -> bool:
        stripped = text.strip()
        if SubscriptionManager._contains_supported_uri(stripped):
            return True
        if not stripped:
            return False
        if stripped[0] in "[{":
            lowered = stripped.lower()
            has_supported_type = any(f'"{protocol}"' in lowered for protocol in SUPPORTED_OUTBOUND_TYPES)
            return '"outbounds"' in lowered or '"proxies"' in lowered or '"type"' in lowered and has_supported_type
        return False

    @staticmethod
    def _clean_link(value: str) -> str:
        link = value.strip()
        while link and link[-1] in ",;]})\"'":
            link = link[:-1].rstrip()
        while link and link[0] in {'"', "'", "[", "(", "{"}:
            link = link[1:].lstrip()
        return link

    @staticmethod
    def profile_key(profile: VlessProfile) -> str:
        params = "&".join(f"{key.lower()}={value}" for key, value in sorted(profile.params.items()))
        name = " ".join(profile.name.lower().split())
        return f"{profile.protocol}|{name}|{profile.address.lower()}|{profile.port}|{profile.uuid.lower()}|{params}"

    @staticmethod
    def _contains_supported_uri(text: str) -> bool:
        lowered = str(text or "").lower()
        return any(f"{scheme}://" in lowered for scheme in SUPPORTED_URI_SCHEMES)
