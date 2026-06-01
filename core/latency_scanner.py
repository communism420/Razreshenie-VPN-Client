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

"""Фоновая проверка отклика VPN-серверов."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

from models.profile import VlessProfile
from utils.network import measure_server_latency_ms


LatencyBatch = list[tuple[str, int | None]]
LatencyBatchCallback = Callable[[LatencyBatch], None]
LatencyDoneCallback = Callable[["LatencyScanSummary"], None]
LatencyErrorCallback = Callable[[Exception], None]


@dataclass(frozen=True, slots=True)
class LatencyTarget:
    """Минимальные данные профиля, нужные для проверки отклика."""

    profile_id: str
    address: str
    port: int

    @classmethod
    def from_profile(cls, profile: VlessProfile) -> "LatencyTarget":
        try:
            port = int(profile.port or 0)
        except (TypeError, ValueError):
            port = 0
        return cls(
            profile_id=profile.id,
            address=(profile.address or "").strip(),
            port=port,
        )


@dataclass(frozen=True, slots=True)
class LatencyScanSummary:
    """Итог фоновой проверки отклика."""

    total_profiles: int
    successful_profiles: int
    unique_endpoints: int
    cancelled: bool = False

    @property
    def timeout_profiles(self) -> int:
        return max(0, self.total_profiles - self.successful_profiles)


class LatencyScanner:
    """Отдельный worker для проверки ping/latency без нагрузки на GUI-поток."""

    def __init__(
        self,
        *,
        timeout_ms: int = 900,
        max_workers: int = 32,
        batch_size: int = 64,
        batch_interval_seconds: float = 0.25,
        logger: logging.Logger | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self.max_workers = max(1, max_workers)
        self.batch_size = max(1, batch_size)
        self.batch_interval_seconds = max(0.05, batch_interval_seconds)
        self.logger = logger
        self._lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def scan_profiles(
        self,
        profiles: Iterable[VlessProfile],
        *,
        on_batch: LatencyBatchCallback,
        on_done: LatencyDoneCallback,
        on_error: LatencyErrorCallback,
    ) -> bool:
        """Запускает проверку профилей в отдельном потоке.

        Возвращает False, если предыдущая проверка еще не завершилась.
        """
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._cancel_event.clear()

        self._thread = threading.Thread(
            target=self._run_profile_scan,
            args=(profiles, on_batch, on_done, on_error),
            name="RazreshenieLatencyScanner",
            daemon=True,
        )
        self._thread.start()
        return True

    def scan_targets(
        self,
        targets: Iterable[LatencyTarget],
        *,
        on_batch: LatencyBatchCallback,
        on_done: LatencyDoneCallback,
        on_error: LatencyErrorCallback,
    ) -> bool:
        target_snapshot = tuple(targets)
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._cancel_event.clear()

        self._thread = threading.Thread(
            target=self._run_scan,
            args=(target_snapshot, on_batch, on_done, on_error),
            name="RazreshenieLatencyScanner",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._cancel_event.set()

    def _run_scan(
        self,
        targets: tuple[LatencyTarget, ...],
        on_batch: LatencyBatchCallback,
        on_done: LatencyDoneCallback,
        on_error: LatencyErrorCallback,
    ) -> None:
        try:
            summary = self._scan_targets(targets, on_batch)
        except Exception as exc:
            on_error(exc)
        else:
            on_done(summary)
        finally:
            with self._lock:
                self._running = False

    def _run_profile_scan(
        self,
        profiles: Iterable[VlessProfile],
        on_batch: LatencyBatchCallback,
        on_done: LatencyDoneCallback,
        on_error: LatencyErrorCallback,
    ) -> None:
        try:
            targets = tuple(LatencyTarget.from_profile(profile) for profile in profiles)
            summary = self._scan_targets(targets, on_batch)
        except Exception as exc:
            on_error(exc)
        else:
            on_done(summary)
        finally:
            with self._lock:
                self._running = False

    def _scan_targets(
        self,
        targets: tuple[LatencyTarget, ...],
        on_batch: LatencyBatchCallback,
    ) -> LatencyScanSummary:
        endpoint_to_ids: dict[tuple[str, int], list[str]] = {}
        endpoint_values: dict[tuple[str, int], tuple[str, int]] = {}
        invalid_ids: list[str] = []

        for target in targets:
            address = target.address.strip()
            port = target.port
            if not address or port <= 0:
                invalid_ids.append(target.profile_id)
                continue
            key = (address.lower(), port)
            endpoint_to_ids.setdefault(key, []).append(target.profile_id)
            endpoint_values.setdefault(key, (address, port))

        total_profiles = len(targets)
        endpoint_items = list(endpoint_values.items())
        if self.logger:
            self.logger.info(
                "Проверка отклика запущена: профилей %s, уникальных адресов %s",
                total_profiles,
                len(endpoint_items),
            )

        batch: LatencyBatch = []
        last_flush = time.monotonic()

        def flush_batch(force: bool = False) -> None:
            nonlocal batch, last_flush
            if not batch:
                return
            if (
                not force
                and len(batch) < self.batch_size
                and time.monotonic() - last_flush < self.batch_interval_seconds
            ):
                return
            send_batch = batch
            batch = []
            last_flush = time.monotonic()
            on_batch(send_batch)

        if invalid_ids:
            batch.extend((profile_id, None) for profile_id in invalid_ids)
            flush_batch()

        ok = 0
        cancelled = False
        executor: ThreadPoolExecutor | None = None
        try:
            if endpoint_items and not self._cancel_event.is_set():
                executor = ThreadPoolExecutor(max_workers=min(self.max_workers, len(endpoint_items)))
                futures = {}
                for index, (key, (address, port)) in enumerate(endpoint_items, start=1):
                    futures[executor.submit(measure_server_latency_ms, address, port, self.timeout_ms)] = key
                    if index % 64 == 0:
                        time.sleep(0)
                for future in as_completed(futures):
                    if self._cancel_event.is_set():
                        cancelled = True
                        break
                    endpoint_key = futures[future]
                    try:
                        latency = future.result()
                    except Exception:
                        latency = None
                    profile_ids = endpoint_to_ids[endpoint_key]
                    ok += len(profile_ids) if latency is not None else 0
                    batch.extend((profile_id, latency) for profile_id in profile_ids)
                    flush_batch()
        finally:
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)

        if self._cancel_event.is_set():
            cancelled = True
        flush_batch(force=True)
        summary = LatencyScanSummary(total_profiles, ok, len(endpoint_items), cancelled)
        if self.logger:
            self.logger.info(
                "Проверка отклика завершена: профилей %s, уникальных адресов %s, успешно %s, таймаутов %s",
                summary.total_profiles,
                summary.unique_endpoints,
                summary.successful_profiles,
                summary.timeout_profiles,
            )
        return summary
