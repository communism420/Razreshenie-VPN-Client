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

import json
import logging
import os
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote

import requests

from core.config_builder import ConfigBuildError, SingBoxConfigBuilder
from models.profile import VlessProfile
from models.settings import AppSettings
from utils import paths
from utils.network import measure_server_latency_ms
from utils.storage import read_json, write_json


KARING_URL_TEST_LIST = (
    "https://www.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://cp.cloudflare.com/generate_204",
    "https://checkip.amazonaws.com",
    "http://connectivity-check.ubuntu.com",
    "http://detectportal.firefox.com/success.txt",
)
KARING_URL_TEST_TIMEOUT_SECONDS = 15
KARING_LATENCY_MAX_CONCURRENCY = 20
KARING_LATENCY_CONTROL_HOST = "127.0.0.1"
KARING_LATENCY_RETRY_COUNT = 1
KARING_LATENCY_FALLBACK_TIMEOUT_MS = 5000


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
    """Karing-style worker: delay проверяется через sing-box Clash API."""

    def __init__(
        self,
        *,
        timeout_ms: int = KARING_URL_TEST_TIMEOUT_SECONDS * 1000,
        max_workers: int = KARING_LATENCY_MAX_CONCURRENCY,
        batch_size: int = 64,
        batch_interval_seconds: float = 0.25,
        logger: logging.Logger | None = None,
        binary_provider: Callable[[], Path] | None = None,
    ) -> None:
        self.timeout_ms = max(1000, min(KARING_URL_TEST_TIMEOUT_SECONDS * 1000, int(timeout_ms)))
        self.max_workers = max(1, min(KARING_LATENCY_MAX_CONCURRENCY, max_workers))
        self.batch_size = max(1, batch_size)
        self.batch_interval_seconds = max(0.05, batch_interval_seconds)
        self.logger = logger
        self.binary_provider = binary_provider
        self.builder = SingBoxConfigBuilder()
        self._lock = threading.RLock()
        self._process_lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._running = False
        self._thread: threading.Thread | None = None
        self._process: subprocess.Popen[str] | None = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def scan_profiles(
        self,
        profiles: Iterable[VlessProfile],
        *,
        settings: AppSettings | None = None,
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
            args=(profiles, settings or AppSettings(), on_batch, on_done, on_error),
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
        self._stop_latency_core()

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
        settings: AppSettings,
        on_batch: LatencyBatchCallback,
        on_done: LatencyDoneCallback,
        on_error: LatencyErrorCallback,
    ) -> None:
        try:
            profile_snapshot = tuple(VlessProfile.from_dict(profile.to_dict()) for profile in profiles)
            summary = self._scan_profiles(profile_snapshot, settings, on_batch)
        except Exception as exc:
            on_error(exc)
        else:
            on_done(summary)
        finally:
            with self._lock:
                self._running = False

    def _scan_profiles(
        self,
        profiles: tuple[VlessProfile, ...],
        settings: AppSettings,
        on_batch: LatencyBatchCallback,
    ) -> LatencyScanSummary:
        total_profiles = len(profiles)
        prepared: list[tuple[str, VlessProfile, str]] = []
        invalid_ids: list[str] = []
        outbounds: list[dict] = []

        for profile in profiles:
            tag = self._latency_tag(profile.id)
            try:
                self._validate_profile(profile)
                outbounds.append(self.builder.build_latency_test_outbound(profile, tag))
            except (ConfigBuildError, ValueError):
                invalid_ids.append(profile.id)
                continue
            prepared.append((profile.id, profile, tag))

        if self.logger:
            self.logger.info(
                "Karing-style проверка отклика запущена: профилей %s, outbounds %s",
                total_profiles,
                len(prepared),
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

        if not prepared or self._cancel_event.is_set():
            flush_batch(force=True)
            return LatencyScanSummary(total_profiles, 0, len(prepared), self._cancel_event.is_set())

        config_path: Path | None = None
        ok = 0
        cancelled = False
        try:
            exe = self._ensure_binary()
            controller_port = self._reserve_local_port()
            config_path = self._write_latency_config(outbounds, settings, controller_port)
            try:
                self._check_latency_config(exe, config_path)
            except RuntimeError as exc:
                if len(prepared) <= 1:
                    raise
                if self.logger:
                    self.logger.warning(
                        "Общий latency config не прошел проверку, фильтрую проблемные outbounds: %s",
                        exc,
                    )
                prepared, outbounds, broken_ids = self._filter_checkable_outbounds(
                    exe,
                    prepared,
                    outbounds,
                    settings,
                    controller_port,
                )
                if broken_ids:
                    batch.extend((profile_id, None) for profile_id in broken_ids)
                    flush_batch()
                if not prepared:
                    flush_batch(force=True)
                    return LatencyScanSummary(total_profiles, ok, 0, self._cancel_event.is_set())
                config_path.unlink(missing_ok=True)
                config_path = self._write_latency_config(outbounds, settings, controller_port)
                self._check_latency_config(exe, config_path)
            self._start_latency_core(exe, config_path)
            self._wait_clash_api_ready(controller_port)

            executor = ThreadPoolExecutor(max_workers=min(self.max_workers, len(prepared)))
            futures = {
                executor.submit(self._measure_outbound_delay, controller_port, tag): profile_id
                for profile_id, _profile, tag in prepared
            }
            try:
                for future in as_completed(futures):
                    if self._cancel_event.is_set():
                        cancelled = True
                        break
                    profile_id = futures[future]
                    try:
                        latency = future.result()
                    except Exception:
                        latency = None
                    if latency is not None:
                        ok += 1
                    batch.append((profile_id, latency))
                    flush_batch()
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        finally:
            if self._cancel_event.is_set():
                cancelled = True
            self._stop_latency_core()
            if config_path is not None:
                try:
                    config_path.unlink(missing_ok=True)
                except OSError:
                    if self.logger:
                        self.logger.debug("Не удалось удалить latency config: %s", config_path, exc_info=True)

        flush_batch(force=True)
        summary = LatencyScanSummary(total_profiles, ok, len(prepared), cancelled)
        if self.logger:
            self.logger.info(
                "Karing-style проверка отклика завершена: профилей %s, outbounds %s, успешно %s, таймаутов %s",
                summary.total_profiles,
                summary.unique_endpoints,
                summary.successful_profiles,
                summary.timeout_profiles,
            )
        return summary

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

    @staticmethod
    def _latency_tag(profile_id: str) -> str:
        return f"latency-{profile_id}"

    @staticmethod
    def _validate_profile(profile: VlessProfile) -> None:
        if not (profile.address or "").strip():
            raise ValueError("empty address")
        port = int(profile.port)
        if port <= 0 or port > 65535:
            raise ValueError("invalid port")
        if not (profile.uuid or "").strip():
            raise ValueError("empty uuid")
        uuid.UUID(str(profile.uuid).strip())

    def _ensure_binary(self) -> Path:
        if self.binary_provider:
            return self.binary_provider()
        metadata = read_json(paths.ensure_app_dirs()["cores"] / "sing-box.json", {})
        exe = metadata.get("executable")
        if exe and Path(exe).exists():
            return Path(exe)
        matches = list(paths.ensure_app_dirs()["cores"].glob("**/sing-box.exe"))
        if matches:
            return matches[0]
        raise RuntimeError("sing-box не установлен. Сначала скачайте/обновите sing-box.")

    @staticmethod
    def _reserve_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((KARING_LATENCY_CONTROL_HOST, 0))
            return int(sock.getsockname()[1])

    def _write_latency_config(
        self,
        outbounds: list[dict],
        settings: AppSettings,
        controller_port: int,
    ) -> Path:
        dns_server = self._primary_dns_server(settings)
        config = {
            "log": {
                "level": "warning",
                "timestamp": True,
            },
            "dns": {
                "servers": [
                    {
                        "type": "udp",
                        "tag": "bootstrap-dns",
                        "server": dns_server,
                    }
                ],
                "final": "bootstrap-dns",
                "strategy": "prefer_ipv4",
            },
            "outbounds": [
                *outbounds,
                {
                    "type": "direct",
                    "tag": "direct",
                    "domain_resolver": "bootstrap-dns",
                },
            ],
            "route": {
                "auto_detect_interface": True,
                "default_domain_resolver": "bootstrap-dns",
                "final": "direct",
            },
            "experimental": {
                "clash_api": {
                    "external_controller": f"{KARING_LATENCY_CONTROL_HOST}:{controller_port}",
                    "secret": "",
                }
            },
        }
        path = paths.ensure_app_dirs()["configs"] / f"sing-box-latency-{uuid.uuid4().hex}.json"
        write_json(path, config)
        return path

    @staticmethod
    def _primary_dns_server(settings: AppSettings) -> str:
        for value in settings.dns_servers:
            text = str(value or "").strip()
            if not text:
                continue
            if "://" in text:
                return text.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] or "1.1.1.1"
            return text.split(":", 1)[0] or "1.1.1.1"
        return "1.1.1.1"

    def _check_latency_config(self, exe: Path, config_path: Path) -> None:
        try:
            proc = subprocess.run(
                [str(exe), "check", "-c", str(config_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
                **self._no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Не удалось проверить latency config: {exc}") from exc
        if proc.returncode != 0:
            output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
            raise RuntimeError(f"sing-box отклонил latency config:\n{output}")

    def _filter_checkable_outbounds(
        self,
        exe: Path,
        prepared: list[tuple[str, VlessProfile, str]],
        outbounds: list[dict],
        settings: AppSettings,
        controller_port: int,
    ) -> tuple[list[tuple[str, VlessProfile, str]], list[dict], list[str]]:
        valid_prepared: list[tuple[str, VlessProfile, str]] = []
        valid_outbounds: list[dict] = []
        broken_ids: list[str] = []
        for prepared_item, outbound in zip(prepared, outbounds, strict=False):
            profile_id, _profile, _tag = prepared_item
            path = self._write_latency_config([outbound], settings, controller_port)
            try:
                self._check_latency_config(exe, path)
            except RuntimeError:
                broken_ids.append(profile_id)
            else:
                valid_prepared.append(prepared_item)
                valid_outbounds.append(outbound)
            finally:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        return valid_prepared, valid_outbounds, broken_ids

    def _start_latency_core(self, exe: Path, config_path: Path) -> None:
        with self._process_lock:
            self._process = subprocess.Popen(
                [str(exe), "run", "-c", str(config_path), "-D", str(exe.parent)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(exe.parent),
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                **self._no_window_kwargs(),
            )
            threading.Thread(target=self._read_latency_core_logs, daemon=True).start()

    def _read_latency_core_logs(self) -> None:
        with self._process_lock:
            proc = self._process
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            if self.logger:
                message = line.strip()
                if message:
                    self.logger.debug("[latency-sing-box] %s", message)

    def _wait_clash_api_ready(self, controller_port: int) -> None:
        deadline = time.monotonic() + 8.0
        url = f"http://{KARING_LATENCY_CONTROL_HOST}:{controller_port}/version"
        session = requests.Session()
        session.trust_env = False
        while time.monotonic() < deadline:
            if self._cancel_event.is_set():
                raise RuntimeError("Проверка отклика остановлена")
            with self._process_lock:
                proc = self._process
            if not proc or proc.poll() is not None:
                raise RuntimeError("latency core завершился до запуска Clash API")
            try:
                response = session.get(url, timeout=0.35)
                if response.status_code == 200:
                    return
            except requests.RequestException:
                time.sleep(0.1)
        raise RuntimeError("latency core не запустил Clash API вовремя")

    def _measure_outbound_delay(self, controller_port: int, tag: str) -> int | None:
        """Повторяет Karing URL-test и использует тот же список URL как быстрый fallback."""
        for _attempt in range(KARING_LATENCY_RETRY_COUNT):
            if self._cancel_event.is_set():
                return None
            latency = self._measure_outbound_delay_once(controller_port, tag, KARING_URL_TEST_LIST[0], self.timeout_ms)
            if latency is not None:
                return latency

        fallback_timeout_ms = min(self.timeout_ms, KARING_LATENCY_FALLBACK_TIMEOUT_MS)
        best_latency: int | None = None
        for test_url in KARING_URL_TEST_LIST[1:]:
            if self._cancel_event.is_set():
                return best_latency
            latency = self._measure_outbound_delay_once(controller_port, tag, test_url, fallback_timeout_ms)
            if latency is not None:
                best_latency = latency if best_latency is None else min(best_latency, latency)
                if best_latency <= 250:
                    return best_latency
        return best_latency

    def _measure_outbound_delay_once(
        self,
        controller_port: int,
        tag: str,
        test_url: str,
        timeout_ms: int,
    ) -> int | None:
        session = requests.Session()
        session.trust_env = False
        url = f"http://{KARING_LATENCY_CONTROL_HOST}:{controller_port}/proxies/{quote(tag, safe='')}/delay"
        timeout_seconds = max(1.0, int(timeout_ms) / 1000.0)
        try:
            response = session.get(
                url,
                params={
                    "url": test_url,
                    "timeout": int(timeout_ms),
                },
                timeout=timeout_seconds + 2.0,
            )
            if response.status_code != 200:
                return None
            payload = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            return None
        value = payload.get("delay")
        try:
            latency = int(value)
        except (TypeError, ValueError):
            return None
        return latency if latency > 0 else None

    def _stop_latency_core(self) -> None:
        with self._process_lock:
            proc = self._process
            self._process = None
        if not proc:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    @staticmethod
    def _no_window_kwargs() -> dict[str, object]:
        if os.name != "nt":
            return {}
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
