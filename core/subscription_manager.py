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
from datetime import datetime, timezone

import requests

from core.vless_parser import VlessParseError, parse_vless_uri
from models.profile import Subscription, VlessProfile


class SubscriptionError(ValueError):
    """Ошибка загрузки подписки."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class SubscriptionManager:
    def fetch(self, subscription: Subscription) -> tuple[list[VlessProfile], Subscription]:
        try:
            response = requests.get(
                subscription.url,
                timeout=30,
                headers={"User-Agent": "RazreshenieVPN/1.0"},
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            subscription.last_error = str(exc)
            raise SubscriptionError(f"Не удалось загрузить подписку: {exc}") from exc

        profiles = self.parse_text(response.text, subscription.id)
        subscription.last_update_at = _utc_now()
        subscription.last_error = None
        subscription.profile_count = len(profiles)
        return profiles, subscription

    def parse_text(self, text: str, subscription_id: str | None = None) -> list[VlessProfile]:
        payload = self._decode_if_base64(text)
        links = self._extract_links(payload)
        profiles: list[VlessProfile] = []
        seen: set[str] = set()
        errors: list[str] = []
        for link in links:
            if link in seen:
                continue
            seen.add(link)
            try:
                profiles.append(parse_vless_uri(link, subscription_id=subscription_id))
            except VlessParseError as exc:
                errors.append(str(exc))
        if not profiles:
            details = f": {'; '.join(errors[:3])}" if errors else ""
            raise SubscriptionError(f"В подписке не найдено корректных VLESS-ключей{details}")
        return profiles

    def _decode_if_base64(self, text: str) -> str:
        stripped = "".join(text.strip().split())
        if "vless://" in text:
            return text
        try:
            padding = "=" * (-len(stripped) % 4)
            decoded = base64.urlsafe_b64decode(stripped + padding).decode("utf-8", errors="replace")
            if "vless://" in decoded:
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
        return text

    def _extract_links(self, text: str) -> list[str]:
        links: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or "vless://" not in line:
                continue
            start = line.find("vless://")
            link = line[start:].strip().strip('"').strip("'").strip(",")
            if link:
                links.append(link)
        if links:
            return links

        # Fallback для подписок без переводов строк: собираем до следующего URI.
        compact = text.strip()
        positions = [index for index in range(len(compact)) if compact.startswith("vless://", index)]
        for current, start in enumerate(positions):
            end = positions[current + 1] if current + 1 < len(positions) else len(compact)
            link = compact[start:end].strip().strip('"').strip("'").strip(",")
            if link:
                links.append(link)
        return links
