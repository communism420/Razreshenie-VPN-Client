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

"""Управление sing-box core: загрузка, проверка config, запуск и остановка."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import requests

from core.connectivity import (
    ConnectivityCheckResult,
    ConnectivityProbeResult,
    DEFAULT_CONNECTIVITY_CHECK_URLS,
    is_successful_connectivity_status,
    normalize_connectivity_timeout_ms,
    normalize_connectivity_urls,
)
from core.config_builder import ConfigBuildError, SingBoxConfigBuilder
from models.profile import ServerProfile
from models.rules import SplitRules
from models.settings import AppSettings
from utils import paths
from utils.storage import read_json, write_json
from utils.version import APP_VERSION


class SingBoxError(RuntimeError):
    """Ошибка sing-box core."""


@dataclass(frozen=True, slots=True)
class _ConnectionPlan:
    """Подготовленный Karing-style план запуска: config уже собран и проверен."""

    profile: ServerProfile
    settings: AppSettings
    executable: Path
    config_path: Path
    fingerprint: str
    outbound_count: int
    clash_api_port: int


class SingBoxManager:
    RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    CONNECTIVITY_TEST_URLS = DEFAULT_CONNECTIVITY_CHECK_URLS
    SERVER_REACHABILITY_TIMEOUT = 4.0
    CORE_CONNECTIVITY_TIMEOUT = 10.0

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("razreshenie")
        self.builder = SingBoxConfigBuilder()
        self.process: subprocess.Popen[str] | None = None
        self.config_path = paths.runtime_config_path()
        self._lock = threading.RLock()
        self._output_lock = threading.RLock()
        self._reader_thread: threading.Thread | None = None
        self._last_output_lines: deque[str] = deque(maxlen=120)
        self._active_tun_interface: str | None = None
        self._active_fingerprint: str | None = None
        self._active_profile_name: str | None = None
        self._active_clash_api_port: int | None = None
        self._connection_state = "disconnected"
        self._connected_at: float | None = None

    @staticmethod
    def _no_window_kwargs() -> dict[str, object]:
        if os.name != "nt":
            return {}
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}

    @property
    def executable_path(self) -> Path | None:
        metadata = read_json(paths.ensure_app_dirs()["cores"] / "sing-box.json", {})
        exe = metadata.get("executable")
        if exe and Path(exe).exists():
            return Path(exe)
        matches = list(paths.ensure_app_dirs()["cores"].glob("**/sing-box.exe"))
        return matches[0] if matches else None

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @property
    def connection_state(self) -> str:
        return self._connection_state

    def last_runtime_error(self) -> str:
        """Возвращает компактную причину последнего неожиданного завершения core."""
        with self._lock:
            return self._unexpected_exit_message(startup=False)

    def mark_stopped_if_exited(self) -> None:
        """Синхронизирует состояние, если процесс уже завершился сам."""
        with self._lock:
            if self.process and self.process.poll() is not None:
                self.process = None
                self._mark_disconnected()

    def check_current_connectivity(self, settings: AppSettings) -> ConnectivityCheckResult:
        """Checks the currently running sing-box instance using its active Clash API when available."""
        with self._lock:
            if not self.is_running():
                return ConnectivityCheckResult(
                    success=False,
                    attempts=[
                        ConnectivityProbeResult(
                            url="sing-box",
                            success=False,
                            error=self._unexpected_exit_message(startup=False),
                            via="process",
                        )
                    ],
                )
            clash_api_port = self._active_clash_api_port
        return self._check_core_connectivity_once_result(settings, clash_api_port)

    def ensure_binary(self) -> Path:
        exe = self.executable_path
        if exe and exe.exists():
            return exe
        return self.download_latest()

    def download_latest(self) -> Path:
        self.logger.info("Загрузка последней версии sing-box для Windows x64")
        try:
            release = requests.get(self.RELEASE_API, timeout=20).json()
        except requests.RequestException as exc:
            raise SingBoxError(f"Не удалось получить release sing-box: {exc}") from exc

        assets = release.get("assets") or []
        asset = self._select_windows_asset(assets)
        if not asset:
            raise SingBoxError("В последнем release sing-box не найден Windows x64 архив")

        dirs = paths.ensure_app_dirs()
        downloads = dirs["downloads"]
        archive_path = downloads / asset["name"]
        self._download_file(asset["browser_download_url"], archive_path)
        self._verify_checksum_if_possible(assets, archive_path)

        tag = str(release.get("tag_name") or "latest").lstrip("v")
        target_dir = dirs["cores"] / f"sing-box-{tag}"
        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(target_dir)

        candidates = list(target_dir.glob("**/sing-box.exe"))
        if not candidates:
            raise SingBoxError("Архив sing-box не содержит sing-box.exe")

        exe = candidates[0]
        write_json(
            dirs["cores"] / "sing-box.json",
            {
                "version": tag,
                "executable": str(exe),
                "source": asset["browser_download_url"],
            },
        )
        self.logger.info("sing-box установлен: %s", exe)
        return exe

    def version(self) -> str:
        exe = self.executable_path
        if not exe:
            return "не установлен"
        metadata = read_json(paths.ensure_app_dirs()["cores"] / "sing-box.json", {})
        cached_version = str(metadata.get("version") or "").strip()
        if cached_version:
            return f"sing-box {cached_version}"
        try:
            proc = subprocess.run(
                [str(exe), "version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                check=False,
                **self._no_window_kwargs(),
            )
            return (proc.stdout or proc.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            return "неизвестно"

    def build_and_save_config(
        self,
        profile: ServerProfile,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> Path:
        config = self._build_config(profile, settings, split_rules)
        write_json(self.config_path, config)
        return self.config_path

    def _build_config(
        self,
        profile: ServerProfile,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> dict[str, Any]:
        try:
            return self.builder.build(profile, settings, split_rules, paths.log_file_path())
        except ConfigBuildError as exc:
            raise SingBoxError(str(exc)) from exc

    def check_config(self, config_path: Path | None = None) -> tuple[bool, str]:
        exe = self.ensure_binary()
        target = config_path or self.config_path
        try:
            proc = subprocess.run(
                [str(exe), "check", "-c", str(target)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
                **self._no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
        return proc.returncode == 0, output or "config OK"

    def start(self, profile: ServerProfile, settings: AppSettings, split_rules: SplitRules) -> None:
        with self._lock:
            fingerprint = self._connection_fingerprint(profile, settings, split_rules)
            running = self.is_running()
            if running:
                if self._active_fingerprint == fingerprint and self._connection_state == "connected":
                    self.logger.info("Подключение уже активно: %s", self._active_profile_name or profile.name)
                    return
                self.logger.info("Конфигурация подключения изменилась, выполняется Karing-style reload")

            self._connection_state = "reloading" if running else "connecting"
            stopped_for_reload = False
            try:
                plan = self._prepare_connection_plan(profile, settings, split_rules, fingerprint)
                if running:
                    self._stop_process_locked(wait_tun_release=True, mark_disconnected=False)
                    stopped_for_reload = True
                self._start_prepared_plan(plan, reload=running)
            except Exception:
                if stopped_for_reload or not running:
                    self._mark_disconnected()
                elif self.process and self.process.poll() is None:
                    self._connection_state = "connected"
                else:
                    self._mark_disconnected()
                raise

    def _prepare_connection_plan(
        self,
        profile: ServerProfile,
        settings: AppSettings,
        split_rules: SplitRules,
        fingerprint: str,
    ) -> _ConnectionPlan:
        exe = self.ensure_binary()
        self._preflight_profile(profile)
        config = self._build_config(profile, settings, split_rules)
        clash_api_port = self._reserve_local_port()
        config.setdefault("experimental", {})["clash_api"] = {
            "external_controller": f"127.0.0.1:{clash_api_port}",
            "secret": "",
        }
        write_json(self.config_path, config)
        ok, output = self.check_config(self.config_path)
        if not ok:
            raise SingBoxError(f"sing-box отклонил конфигурацию:\n{output}")
        if settings.mode == "tun":
            conflicts = self._active_foreign_tun_adapters(settings.tun_interface_name, timeout=1.2)
            if conflicts:
                names = ", ".join(conflicts[:3])
                raise SingBoxError(
                    "Обнаружен активный TUN другого VPN: "
                    f"{names}. Закройте Karing или другой VPN-клиент и подключитесь заново, "
                    "иначе Windows будет использовать чужой DNS, а раздельное туннелирование не сработает."
                )
        outbound_count = len(config.get("outbounds") or [])
        self.logger.info("Karing-style setServer: config готов, outbounds=%s", outbound_count)
        return _ConnectionPlan(
            profile=profile,
            settings=settings,
            executable=exe,
            config_path=self.config_path,
            fingerprint=fingerprint,
            outbound_count=outbound_count,
            clash_api_port=clash_api_port,
        )

    def _start_prepared_plan(self, plan: _ConnectionPlan, *, reload: bool) -> None:
        exe = plan.executable
        settings = plan.settings
        attempts = 3
        last_error = ""
        if settings.mode == "proxy":
            self._ensure_proxy_port_free(settings.mixed_listen_host, int(settings.mixed_port))
        for attempt in range(1, attempts + 1):
            self._connection_state = "reloading" if reload else "connecting"
            if attempt > 1:
                self._kill_orphaned(exe)
            if settings.mode == "tun":
                self._clear_runtime_cache(exe)
            elif attempt > 1:
                self._ensure_proxy_port_free(settings.mixed_listen_host, int(settings.mixed_port))
            self._clear_last_output()
            action = "reload" if reload else "start"
            self.logger.info(
                "Karing-style %s sing-box: %s (попытка %s/%s)",
                action,
                plan.config_path,
                attempt,
                attempts,
            )
            self._active_tun_interface = settings.tun_interface_name if settings.mode == "tun" else None
            self.process = subprocess.Popen(
                [str(exe), "run", "-c", str(plan.config_path), "-D", str(exe.parent)],
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
            self._reader_thread = threading.Thread(target=self._read_process_logs, daemon=True)
            self._reader_thread.start()

            if settings.mode != "tun":
                if self._wait_until_proxy_ready(settings.mixed_listen_host, int(settings.mixed_port), max_wait=3.0):
                    self._wait_until_clash_api_ready(plan.clash_api_port, max_wait=1.0)
                    self._mark_connected(plan.profile, plan.fingerprint, plan.clash_api_port)
                    self._start_background_health_check(plan)
                    return
                exited = self.process is None or self.process.poll() is not None
                last_error = self._unexpected_exit_message(startup=True) if exited else (
                    "sing-box запустился, но локальный proxy-порт "
                    f"{settings.mixed_listen_host}:{settings.mixed_port} не принимает подключения"
                )
                self._stop_process_locked()
                if attempt < attempts:
                    time.sleep(0.35)
                    continue
                break

            if not self._wait_process_stable(max_wait=0.25):
                exited = self.process is None or self.process.poll() is not None
                last_error = self._unexpected_exit_message(startup=True) if exited else "sing-box не стабилизировался после запуска"
                retryable = exited and self._startup_error_is_retryable()
                self._stop_process_locked(wait_tun_release=True, tun_interface_name=settings.tun_interface_name)
                if retryable and attempt < attempts:
                    self._wait_tun_released(settings.tun_interface_name)
                    continue
                break

            if not self._wait_until_clash_api_ready(plan.clash_api_port, max_wait=1.5):
                self.logger.warning(
                    "sing-box запустился, но Clash API не ответил сразу; продолжаю запуск как Karing-style service start"
                )
            self._mark_connected(plan.profile, plan.fingerprint, plan.clash_api_port)
            self._start_background_health_check(plan)
            self._start_post_connect_tasks(settings)
            return
        raise SingBoxError(last_error or "Не удалось запустить sing-box")

    def stop(self) -> None:
        with self._lock:
            self._stop_process_locked(wait_tun_release=True)

    def _stop_process_locked(
        self,
        wait_tun_release: bool = False,
        tun_interface_name: str | None = None,
        *,
        mark_disconnected: bool = True,
    ) -> None:
        if not self.process:
            if mark_disconnected:
                self._mark_disconnected()
            return
        proc = self.process
        interface_name = tun_interface_name or self._active_tun_interface
        if proc.poll() is None:
            self.logger.info("Остановка sing-box")
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.logger.warning("sing-box не завершился штатно, выполняется kill")
                proc.kill()
                proc.wait(timeout=5)
        self.process = None
        if mark_disconnected:
            self._mark_disconnected()
        if wait_tun_release:
            self._wait_tun_released(interface_name)
            self._flush_windows_dns_cache()

    def _read_process_logs(self) -> None:
        proc = self.process
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            message = line.strip()
            if message:
                with self._output_lock:
                    self._last_output_lines.append(message)
                self.logger.info("[sing-box] %s", message)
        code = proc.poll()
        if code not in (None, 0):
            self.logger.error("sing-box завершился с кодом %s", code)

    def _clear_last_output(self) -> None:
        with self._output_lock:
            self._last_output_lines.clear()

    def _last_output(self) -> list[str]:
        with self._output_lock:
            return list(self._last_output_lines)

    def _mark_connected(self, profile: ServerProfile, fingerprint: str, clash_api_port: int | None) -> None:
        self._active_fingerprint = fingerprint
        self._active_profile_name = profile.name
        self._active_clash_api_port = clash_api_port
        self._connection_state = "connected"
        self._connected_at = time.monotonic()
        self.logger.info("Подключение активно: %s", profile.name)

    def _mark_disconnected(self) -> None:
        self._active_tun_interface = None
        self._active_fingerprint = None
        self._active_profile_name = None
        self._active_clash_api_port = None
        self._connection_state = "disconnected"
        self._connected_at = None

    def _start_background_health_check(self, plan: _ConnectionPlan) -> None:
        def worker() -> None:
            connected, error = self._wait_until_core_connected(
                plan.settings,
                plan.outbound_count,
                plan.clash_api_port,
                max_wait=8.0,
            )
            with self._lock:
                still_current = self._active_fingerprint == plan.fingerprint and self._connection_state == "connected"
            if not still_current:
                return
            if connected:
                self.logger.info("Фоновая проверка выхода через текущий сервер прошла успешно")
            else:
                self.logger.warning("Фоновая проверка выхода через текущий сервер не прошла: %s", error)

        threading.Thread(target=worker, name="RazreshenieCoreHealthCheck", daemon=True).start()

    def _start_post_connect_tasks(self, settings: AppSettings) -> None:
        if settings.mode != "tun":
            return
        tun_interface_name = settings.tun_interface_name

        def worker() -> None:
            self._flush_windows_dns_cache()
            if not self._wait_until_tun_ready(tun_interface_name, max_wait=2.0):
                self.logger.debug(
                    "TUN-интерфейс '%s' не показал IPv4 в короткой фоновой проверке",
                    tun_interface_name,
                )

        threading.Thread(target=worker, name="RazreshenieTunPostConnect", daemon=True).start()

    def _connection_fingerprint(
        self,
        profile: ServerProfile,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> str:
        payload = {
            "profile": {
                "protocol": profile.protocol,
                "address": profile.address,
                "port": int(profile.port),
                "uuid": profile.uuid,
                "raw_url": profile.raw_url,
                "params": dict(sorted(profile.params.items())),
            },
            "settings": {
                "mode": settings.mode,
                "mixed_listen_host": settings.mixed_listen_host,
                "mixed_port": int(settings.mixed_port),
                "tun_interface_name": settings.tun_interface_name,
                "tun_address": settings.tun_address,
                "tun_mtu": int(settings.tun_mtu),
                "dns_servers": list(settings.dns_servers),
                "kill_switch": bool(settings.kill_switch),
                "log_level": settings.log_level,
            },
            "split_rules": split_rules.to_dict(),
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _wait_until_proxy_ready(self, host: str, port: int, max_wait: float = 8.0) -> bool:
        connect_host = self._connect_host(host)
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False
            try:
                with socket.create_connection((connect_host, int(port)), timeout=0.35):
                    return self._wait_process_stable(max_wait=0.35)
            except OSError:
                time.sleep(0.08)
        return False

    def _wait_until_core_connected(
        self,
        settings: AppSettings,
        outbound_count: int = 1,
        clash_api_port: int | None = None,
        max_wait: float | None = None,
    ) -> tuple[bool, str]:
        timeout = max_wait if max_wait is not None else self._startup_timeout(outbound_count, tun=settings.mode == "tun")
        deadline = time.monotonic() + timeout
        last_error = "Проверка выхода через core не выполнена"
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False, self._unexpected_exit_message(startup=True)
            result = self._check_core_connectivity_once_result(settings, clash_api_port)
            if result.success:
                self.logger.info("Проверка подключения через текущий сервер прошла успешно: %s", result.summary)
                return True, ""
            last_error = result.error
            time.sleep(0.35)
        return False, (
            "sing-box запустился, но проверка выхода через текущий сервер не прошла. "
            f"Последняя ошибка: {last_error}"
        )

    def _wait_until_clash_api_ready(self, clash_api_port: int | None, max_wait: float = 1.5) -> bool:
        if not clash_api_port:
            return True
        deadline = time.monotonic() + max_wait
        url = f"http://127.0.0.1:{int(clash_api_port)}/version"
        session = requests.Session()
        session.trust_env = False
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False
            try:
                response = session.get(url, timeout=0.2)
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                time.sleep(0.05)
        return False

    @classmethod
    def _startup_timeout(cls, outbound_count: int, *, tun: bool) -> float:
        """Karing-style timeout: больше outbounds и TUN дают больше времени core."""
        count = max(1, int(outbound_count or 1))
        base = cls.CORE_CONNECTIVITY_TIMEOUT + (10.0 if tun else 0.0)
        extra = min(18.0 if tun else 10.0, count / 150.0)
        return base + extra

    def _check_core_connectivity_once(
        self,
        settings: AppSettings,
        clash_api_port: int | None = None,
    ) -> tuple[bool, str]:
        result = self._check_core_connectivity_once_result(settings, clash_api_port)
        return result.success, result.error

    def _check_core_connectivity_once_result(
        self,
        settings: AppSettings,
        clash_api_port: int | None = None,
    ) -> ConnectivityCheckResult:
        session = requests.Session()
        session.trust_env = False
        urls = normalize_connectivity_urls(settings.connectivity_check_urls)
        timeout_ms = normalize_connectivity_timeout_ms(settings.connectivity_check_timeout_ms)
        timeout_seconds = max(1.0, timeout_ms / 1000.0)
        attempts: list[ConnectivityProbeResult] = []

        if clash_api_port:
            api_url = f"http://127.0.0.1:{int(clash_api_port)}/proxies/proxy/delay"
            for url in urls:
                try:
                    response = session.get(
                        api_url,
                        params={"url": url, "timeout": timeout_ms},
                        timeout=(1.0, timeout_seconds + 1.0),
                        headers={"User-Agent": self._user_agent()},
                    )
                    if response.status_code == 200:
                        delay = response.json().get("delay")
                        latency = int(delay)
                        if latency >= 0:
                            attempt = ConnectivityProbeResult(url=url, success=True, latency_ms=latency, via="clash")
                            return ConnectivityCheckResult(success=True, attempts=[*attempts, attempt])
                        attempts.append(
                            ConnectivityProbeResult(
                                url=url,
                                success=False,
                                status_code=response.status_code,
                                error=f"{url}: Clash API delay вернул некорректное значение: {delay}",
                                via="clash",
                            )
                        )
                        continue
                    attempts.append(
                        ConnectivityProbeResult(
                            url=url,
                            success=False,
                            status_code=response.status_code,
                            error=f"{url}: Clash API delay HTTP {response.status_code}",
                            via="clash",
                        )
                    )
                except (requests.RequestException, ValueError, TypeError) as exc:
                    attempts.append(
                        ConnectivityProbeResult(
                            url=url,
                            success=False,
                            error=f"{url}: Clash API delay: {exc}",
                            via="clash",
                        )
                    )

        proxy_url = f"http://{self._connect_host(settings.mixed_listen_host)}:{int(settings.mixed_port)}"
        proxies = {"http": proxy_url, "https": proxy_url} if settings.mode == "proxy" else None
        for url in urls:
            started = time.perf_counter()
            try:
                response = session.get(
                    url,
                    timeout=(1.5, min(timeout_seconds, 8.0)),
                    allow_redirects=False,
                    proxies=proxies,
                    headers={"User-Agent": self._user_agent()},
                )
            except requests.RequestException as exc:
                attempts.append(ConnectivityProbeResult(url=url, success=False, error=f"{url}: {exc}", via="http"))
                continue
            latency_ms = max(1, int((time.perf_counter() - started) * 1000))
            if is_successful_connectivity_status(response.status_code):
                attempt = ConnectivityProbeResult(
                    url=url,
                    success=True,
                    latency_ms=latency_ms,
                    status_code=response.status_code,
                    via="http",
                )
                return ConnectivityCheckResult(success=True, attempts=[*attempts, attempt])
            attempts.append(
                ConnectivityProbeResult(
                    url=url,
                    success=False,
                    latency_ms=latency_ms,
                    status_code=response.status_code,
                    error=f"{url}: HTTP {response.status_code}",
                    via="http",
                )
            )
        return ConnectivityCheckResult(success=False, attempts=attempts)

    @staticmethod
    def _reserve_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _wait_process_stable(self, max_wait: float = 0.7) -> bool:
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False
            time.sleep(0.05)
        return self.is_running()

    def _wait_until_tun_ready(self, tun_interface_name: str, max_wait: float = 24.0) -> bool:
        if os.name != "nt" or not tun_interface_name:
            return self.is_running()
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False
            command_timeout = max(0.2, min(0.7, deadline - time.monotonic()))
            if self._tun_interface_has_ipv4(tun_interface_name, timeout=command_timeout):
                return True
            time.sleep(0.25)
        return False

    @staticmethod
    def _connect_host(host: str) -> str:
        value = str(host or "").strip()
        if value in {"", "0.0.0.0", "::", "[::]"}:
            return "127.0.0.1"
        return value.strip("[]")

    @staticmethod
    def _user_agent() -> str:
        return f"RazreshenieVPN/{APP_VERSION}"

    def _ensure_proxy_port_free(self, host: str, port: int) -> None:
        connect_host = self._connect_host(host)
        try:
            with socket.create_connection((connect_host, int(port)), timeout=0.25):
                raise SingBoxError(
                    f"Локальный proxy-порт {connect_host}:{port} уже занят. "
                    "Закройте приложение, которое использует этот порт, или измените порт в настройках."
                )
        except SingBoxError:
            raise
        except OSError:
            return

    @staticmethod
    def _preflight_profile(profile: ServerProfile) -> None:
        if not str(profile.address or "").strip():
            raise SingBoxError("У выбранного профиля не указан адрес сервера")
        try:
            port = int(profile.port)
        except (TypeError, ValueError) as exc:
            raise SingBoxError("У выбранного профиля указан некорректный порт") from exc
        if port <= 0 or port > 65535:
            raise SingBoxError("У выбранного профиля порт вне диапазона 1-65535")
        if not str(profile.protocol or "").strip():
            raise SingBoxError("У выбранного профиля не указан протокол")

    def _preflight_server_reachability(self, profile: ServerProfile) -> None:
        if self._profile_uses_udp_transport(profile):
            self.logger.info("Профиль использует UDP/QUIC transport, TCP preflight сервера пропущен")
            return
        try:
            with socket.create_connection(
                (profile.address, int(profile.port)),
                timeout=self.SERVER_REACHABILITY_TIMEOUT,
            ):
                return
        except OSError as exc:
            raise SingBoxError(
                "Текущий сервер недоступен до запуска core: "
                f"{profile.address}:{profile.port}. Проверьте сервер или выберите другой профиль."
            ) from exc

    @staticmethod
    def _profile_uses_udp_transport(profile: ServerProfile) -> bool:
        if str(profile.protocol or "").lower() in {"hysteria2", "tuic", "wireguard"}:
            return True
        params = {key.lower(): str(value).lower() for key, value in profile.params.items()}
        network = params.get("type") or params.get("network") or "tcp"
        return network == "quic"

    @staticmethod
    def _tun_interface_has_ipv4(tun_interface_name: str, timeout: float = 4.0) -> bool:
        escaped_name = tun_interface_name.replace("'", "''")
        script = (
            f"$ipv4 = Get-NetIPAddress -InterfaceAlias '{escaped_name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue "
            "| Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' } "
            "| Select-Object -First 1 IPAddress; "
            "if ($ipv4) { exit 0 } else { exit 1 }"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.2, float(timeout)),
                check=False,
                **SingBoxManager._no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

    def _wait_tun_released(self, tun_interface_name: str | None = None, max_wait: float = 10.0) -> None:
        if os.name != "nt":
            return
        name = str(tun_interface_name or "").strip()
        if not name:
            return
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if not self._tun_interface_has_ipv4(name):
                return
            time.sleep(0.3)

    def _flush_windows_dns_cache(self) -> None:
        if os.name != "nt":
            return
        commands = [
            ["ipconfig", "/flushdns"],
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Clear-DnsClientCache"],
        ]
        for command in commands:
            try:
                subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                    check=False,
                    **self._no_window_kwargs(),
                )
            except (OSError, subprocess.SubprocessError):
                self.logger.debug("Не удалось очистить DNS-кэш Windows командой %s", command[0], exc_info=True)

    def _clear_runtime_cache(self, exe: Path) -> None:
        for name in ("cache.db", "cache.db-shm", "cache.db-wal"):
            try:
                (exe.parent / name).unlink(missing_ok=True)
            except OSError:
                self.logger.debug("Не удалось удалить runtime-cache sing-box: %s", exe.parent / name, exc_info=True)

    def _active_foreign_tun_adapters(self, own_interface_name: str, timeout: float = 6.0) -> list[str]:
        if os.name != "nt":
            return []
        own = str(own_interface_name or "").replace("'", "''")
        active = str(self._active_tun_interface or "").replace("'", "''")
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$own='{own}'; "
            f"$active='{active}'; "
            "Get-NetAdapter | "
            "Where-Object { "
            "$_.Status -eq 'Up' -and $_.Name -ne $own -and $_.Name -ne $active -and "
            "($_.Name -match '(?i)(tun|wintun|wireguard|karing)' -or "
            "$_.InterfaceDescription -match '(?i)(tun|wintun|wireguard|tunnel|karing)') "
            "} | ForEach-Object { $_.Name }"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.5, float(timeout)),
                check=False,
                **self._no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _kill_orphaned(self, exe: Path) -> None:
        if os.name != "nt":
            return
        target = str(exe.resolve()).replace("'", "''")
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$target='{target}'; "
            "Get-CimInstance Win32_Process -Filter \"Name = 'sing-box.exe'\" | "
            "Where-Object { $_.ExecutablePath -eq $target } | "
            "ForEach-Object { $_.ProcessId; Stop-Process -Id $_.ProcessId -Force }"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=6,
                check=False,
                **self._no_window_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            return
        if result.returncode == 0 and result.stdout.strip():
            time.sleep(0.8)

    def _startup_error_is_retryable(self) -> bool:
        needles = (
            "already exists",
            "cannot create a file when that file already exists",
            "adapter already exists",
            "device or resource busy",
            "resource busy",
            "wintun",
            "tun device",
            "failed to configure tun",
            "failed to start tun",
            "route already exists",
            "object already exists",
            "access is denied",
            "permission denied",
        )
        for line in self._last_output():
            text = line.lower()
            if any(needle in text for needle in needles):
                return True
        return False

    def _unexpected_exit_message(self, startup: bool) -> str:
        stage = "при запуске" if startup else "во время работы"
        lines = self._last_output()
        if lines:
            tail = "\n".join(lines[-6:])
            return f"sing-box завершился {stage}:\n{tail}"
        if self.process and self.process.returncode is not None:
            return f"sing-box завершился {stage} с кодом {self.process.returncode}"
        return f"sing-box завершился {stage}"

    def _select_windows_asset(self, assets: list[dict[str, Any]]) -> dict[str, Any] | None:
        for asset in assets:
            name = str(asset.get("name", "")).lower()
            if "windows-amd64" in name and name.endswith(".zip") and "legacy" not in name:
                return asset
        return None

    def _download_file(self, url: str, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with requests.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            with target.open("wb") as file:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        file.write(chunk)

    def _verify_checksum_if_possible(self, assets: list[dict[str, Any]], archive_path: Path) -> None:
        checksum_asset = None
        for asset in assets:
            name = str(asset.get("name", "")).lower()
            if "checksum" in name and asset.get("browser_download_url"):
                checksum_asset = asset
                break
        if not checksum_asset:
            self.logger.warning("Checksum-файл sing-box не найден в release, пропускаю проверку SHA256")
            return
        try:
            text = requests.get(checksum_asset["browser_download_url"], timeout=20).text
        except requests.RequestException:
            self.logger.warning("Не удалось скачать checksum-файл sing-box")
            return
        expected = None
        for line in text.splitlines():
            if archive_path.name in line:
                expected = line.split()[0].lower()
                break
        if not expected:
            self.logger.warning("В checksum-файле нет записи для %s", archive_path.name)
            return
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest().lower()
        if digest != expected:
            raise SingBoxError("SHA256 скачанного sing-box не совпадает с checksum release")
