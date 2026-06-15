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

"""Subscription payload import and server profile extraction."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core.server_parser import (
    SUPPORTED_OUTBOUND_TYPES,
    SUPPORTED_URI_SCHEMES,
    ServerParseError,
    is_supported_outbound_type,
    parse_outbound,
    parse_server_uri,
)
from core.subscription_formats import parse_subscription_payload
from core.subscription_types import ImportProgress, ProgressCallback, SubscriptionError
from models.profile import VlessProfile


class SubscriptionImporter:
    """Parses subscription text, files and mixed source batches."""

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

        # Karing treats every subscription entry as a separate server, even
        # when a provider repeats identical keys. Keep that behavior here.
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
    def profile_key(profile: VlessProfile) -> str:
        params = "&".join(f"{key.lower()}={value}" for key, value in sorted(profile.params.items()))
        name = " ".join(profile.name.lower().split())
        return f"{profile.protocol}|{name}|{profile.address.lower()}|{profile.port}|{profile.uuid.lower()}|{params}"

    @staticmethod
    def _append_duplicate_name_suffixes(profiles: list[VlessProfile]) -> list[VlessProfile]:
        """Добавляет `-1`, `-2` к повторяющимся именам серверов."""
        totals: dict[str, int] = {}
        for profile in profiles:
            key = SubscriptionImporter._name_key(profile.name)
            totals[key] = totals.get(key, 0) + 1

        seen: dict[str, int] = {}
        used_names = {profile.name for profile in profiles}
        for profile in profiles:
            key = SubscriptionImporter._name_key(profile.name)
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
        if SubscriptionImporter._contains_supported_uri(stripped):
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
    def _contains_supported_uri(text: str) -> bool:
        lowered = str(text or "").lower()
        return any(f"{scheme}://" in lowered for scheme in SUPPORTED_URI_SCHEMES)
