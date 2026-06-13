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

"""Shared connectivity checks for startup, latency tests and health monitoring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


DEFAULT_CONNECTIVITY_CHECK_URLS = (
    "https://www.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://cp.cloudflare.com/generate_204",
    "https://checkip.amazonaws.com",
    "http://connectivity-check.ubuntu.com",
    "http://detectportal.firefox.com/success.txt",
    "http://connectivitycheck.gstatic.com/generate_204",
)
DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS = 5000
MIN_CONNECTIVITY_CHECK_TIMEOUT_MS = 1000
MAX_CONNECTIVITY_CHECK_TIMEOUT_MS = 30000
MAX_CONNECTIVITY_CHECK_URLS = 16


@dataclass(frozen=True, slots=True)
class ConnectivityProbeResult:
    """Result of one concrete URL probe through direct HTTP or Clash API delay."""

    url: str
    success: bool
    latency_ms: int | None = None
    status_code: int | None = None
    error: str = ""
    via: str = "direct"


@dataclass(frozen=True, slots=True)
class ConnectivityCheckResult:
    """Aggregated result of a multi-URL connectivity check."""

    success: bool
    attempts: list[ConnectivityProbeResult]

    @property
    def successful_attempt(self) -> ConnectivityProbeResult | None:
        return next((attempt for attempt in self.attempts if attempt.success), None)

    @property
    def error(self) -> str:
        if self.success:
            return ""
        if not self.attempts:
            return "нет URL для проверки связности"
        errors = [attempt.error for attempt in self.attempts if attempt.error]
        if errors:
            return "; ".join(errors[-3:])
        return "проверочные URL не ответили успешно"

    @property
    def summary(self) -> str:
        attempt = self.successful_attempt
        if attempt:
            latency = f", {attempt.latency_ms} ms" if attempt.latency_ms is not None else ""
            return f"{attempt.via}: {attempt.url}{latency}"
        return self.error


def normalize_connectivity_urls(value: Any, *, fallback: Iterable[str] | None = None) -> list[str]:
    """Normalizes user-provided health-check URLs and keeps only http(s) endpoints."""
    raw_items: list[Any] = []
    if value is None:
        raw_items = []
    elif isinstance(value, str):
        raw_items = value.replace(",", "\n").splitlines()
    elif isinstance(value, Iterable):
        for item in value:
            if isinstance(item, str):
                raw_items.extend(item.replace(",", "\n").splitlines())
            else:
                raw_items.append(item)
    else:
        raw_items = [value]

    result: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        url = str(item or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        normalized = parsed.geturl()
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
        if len(result) >= MAX_CONNECTIVITY_CHECK_URLS:
            break

    if result:
        return result
    return list(fallback or DEFAULT_CONNECTIVITY_CHECK_URLS)


def normalize_connectivity_timeout_ms(value: Any) -> int:
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        timeout = DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS
    return max(MIN_CONNECTIVITY_CHECK_TIMEOUT_MS, min(MAX_CONNECTIVITY_CHECK_TIMEOUT_MS, timeout))


def is_successful_connectivity_status(status_code: int) -> bool:
    return 200 <= int(status_code) < 400
