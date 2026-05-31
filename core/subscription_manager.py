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

"""Импорт VLESS-подписок."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from time import sleep
from typing import Any

import requests

from core.vless_parser import VlessParseError, parse_vless_outbound, parse_vless_uri
from models.profile import Subscription, VlessProfile


class SubscriptionError(ValueError):
    """Ошибка загрузки подписки."""


FETCH_ATTEMPTS = 3


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class SubscriptionManager:
    def fetch(self, subscription: Subscription) -> tuple[list[VlessProfile], Subscription]:
        profiles_by_key: dict[str, VlessProfile] = {}
        errors: list[str] = []

        for attempt in range(1, FETCH_ATTEMPTS + 1):
            try:
                response = requests.get(
                    subscription.url,
                    timeout=30,
                    headers={
                        "User-Agent": "RazreshenieVPN/1.0",
                        "Accept": "text/plain, application/json, */*",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                    },
                )
                response.raise_for_status()
                fetched_profiles = self.parse_text(response.text, subscription.id)
            except (requests.RequestException, SubscriptionError) as exc:
                errors.append(str(exc))
                if attempt < FETCH_ATTEMPTS:
                    sleep(0.35 * attempt)
                continue

            for profile in fetched_profiles:
                profiles_by_key.setdefault(self.profile_key(profile), profile)

            # Если вторая попытка не дала новых серверов, третья обычно не нужна.
            if attempt > 1 and len(profiles_by_key) == len(fetched_profiles):
                break

        if not profiles_by_key:
            message = errors[-1] if errors else "пустой ответ"
            subscription.last_error = message
            raise SubscriptionError(f"Не удалось загрузить подписку: {message}")

        profiles = list(profiles_by_key.values())
        subscription.last_update_at = _utc_now()
        subscription.last_error = None
        subscription.profile_count = len(profiles)
        return profiles, subscription

    def parse_text(self, text: str, subscription_id: str | None = None) -> list[VlessProfile]:
        payload = self._decode_if_base64(text)
        profiles: list[VlessProfile] = []
        seen: set[str] = set()
        errors: list[str] = []

        for outbound in self._extract_json_vless_outbounds(payload):
            try:
                profile = parse_vless_outbound(outbound, subscription_id=subscription_id)
                key = self.profile_key(profile)
                if key not in seen:
                    seen.add(key)
                    profiles.append(profile)
            except VlessParseError as exc:
                errors.append(str(exc))

        links = [*self._extract_json_links(payload), *self._extract_links(payload)]
        for link in links:
            try:
                profile = parse_vless_uri(link, subscription_id=subscription_id)
            except VlessParseError as exc:
                errors.append(str(exc))
                continue
            key = self.profile_key(profile)
            if key in seen:
                continue
            seen.add(key)
            profiles.append(profile)

        if not profiles:
            details = f": {'; '.join(errors[:3])}" if errors else ""
            raise SubscriptionError(f"В подписке не найдено корректных VLESS-ключей{details}")
        return profiles

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
        pattern = re.compile(r"(?i)(vless|vmess|trojan|ss|ssr|hysteria2|hy2)://")
        matches = list(pattern.finditer(text))
        for index, match in enumerate(matches):
            if match.group(1).lower() != "vless":
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

    def _extract_json_vless_outbounds(self, text: str) -> list[dict[str, Any]]:
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return []

        outbounds: list[dict[str, Any]] = []
        for item in self._walk_json(payload):
            if isinstance(item, dict) and str(item.get("type") or "").lower() == "vless":
                outbounds.append(item)
        return outbounds

    def _extract_json_links(self, text: str) -> list[str]:
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return []

        links: list[str] = []
        for item in self._walk_json(payload):
            if isinstance(item, str) and "vless://" in item.lower():
                links.extend(self._extract_links(item))
        return links

    def _walk_json(self, value: Any) -> list[Any]:
        result: list[Any] = []
        stack = [value]
        while stack:
            item = stack.pop()
            result.append(item)
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        return result

    @staticmethod
    def _looks_like_subscription(text: str) -> bool:
        stripped = text.strip()
        if "vless://" in stripped.lower():
            return True
        if not stripped:
            return False
        if stripped[0] in "[{":
            lowered = stripped.lower()
            return '"outbounds"' in lowered or '"proxies"' in lowered or '"type"' in lowered and '"vless"' in lowered
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
