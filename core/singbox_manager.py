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
import hashlib
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

from core.config_builder import ConfigBuildError, SingBoxConfigBuilder
from models.profile import VlessProfile
from models.rules import SplitRules
from models.settings import AppSettings
from utils import paths
from utils.storage import read_json, write_json


class SingBoxError(RuntimeError):
    """Ошибка sing-box core."""


class SingBoxManager:
    RELEASE_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    CONNECTIVITY_TEST_URLS = (
        "https://cp.cloudflare.com/generate_204",
        "https://www.gstatic.com/generate_204",
        "http://connectivitycheck.gstatic.com/generate_204",
    )
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
        profile: VlessProfile,
        settings: AppSettings,
        split_rules: SplitRules,
    ) -> Path:
        try:
            config = self.builder.build(profile, settings, split_rules, paths.log_file_path())
        except ConfigBuildError as exc:
            raise SingBoxError(str(exc)) from exc
        write_json(self.config_path, config)
        return self.config_path

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

    def start(self, profile: VlessProfile, settings: AppSettings, split_rules: SplitRules) -> None:
        with self._lock:
            if self.is_running():
                return
            exe = self.ensure_binary()
            self._preflight_profile(profile)
            self._preflight_server_reachability(profile)
            self._kill_orphaned(exe)
            if settings.mode == "proxy":
                self._ensure_proxy_port_free(settings.mixed_listen_host, int(settings.mixed_port))
            config_path = self.build_and_save_config(profile, settings, split_rules)
            ok, output = self.check_config(config_path)
            if not ok:
                raise SingBoxError(f"sing-box отклонил конфигурацию:\n{output}")
            if settings.mode == "tun":
                conflicts = self._active_foreign_tun_adapters(settings.tun_interface_name)
                if conflicts:
                    names = ", ".join(conflicts[:3])
                    raise SingBoxError(
                        "Обнаружен активный TUN другого VPN: "
                        f"{names}. Закройте Karing или другой VPN-клиент и подключитесь заново, "
                        "иначе Windows будет использовать чужой DNS, а раздельное туннелирование не сработает."
                    )

            attempts = 3
            last_error = ""
            for attempt in range(1, attempts + 1):
                if settings.mode == "tun":
                    self._clear_runtime_cache(exe)
                    self._flush_windows_dns_cache()
                elif attempt > 1:
                    self._ensure_proxy_port_free(settings.mixed_listen_host, int(settings.mixed_port))
                self._clear_last_output()
                self.logger.info("Запуск sing-box: %s (попытка %s/%s)", config_path, attempt, attempts)
                self._active_tun_interface = settings.tun_interface_name if settings.mode == "tun" else None
                self.process = subprocess.Popen(
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
                self._reader_thread = threading.Thread(target=self._read_process_logs, daemon=True)
                self._reader_thread.start()

                if settings.mode != "tun":
                    if self._wait_until_proxy_ready(settings.mixed_listen_host, int(settings.mixed_port)):
                        connected, error = self._wait_until_core_connected(settings)
                        if connected:
                            return
                        last_error = error
                        self._stop_process_locked()
                        if attempt < attempts:
                            time.sleep(0.45)
                            continue
                        break
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

                if self._wait_until_tun_ready(settings.tun_interface_name) and self._wait_process_stable():
                    connected, error = self._wait_until_core_connected(settings)
                    if connected:
                        return
                    last_error = error
                    self._stop_process_locked(wait_tun_release=True, tun_interface_name=settings.tun_interface_name)
                    if attempt < attempts:
                        self._wait_tun_released(settings.tun_interface_name)
                        time.sleep(0.45)
                        continue
                    break

                exited = self.process is None or self.process.poll() is not None
                last_error = self._unexpected_exit_message(startup=True) if exited else (
                    f"sing-box запустился, но TUN-интерфейс '{settings.tun_interface_name}' не получил IPv4-адрес"
                )
                retryable = exited and self._startup_error_is_retryable()
                self._stop_process_locked(wait_tun_release=True, tun_interface_name=settings.tun_interface_name)
                if retryable and attempt < attempts:
                    self._wait_tun_released(settings.tun_interface_name)
                    continue
                break

            raise SingBoxError(last_error or "Не удалось запустить sing-box")

    def stop(self) -> None:
        with self._lock:
            self._stop_process_locked(wait_tun_release=True)

    def _stop_process_locked(self, wait_tun_release: bool = False, tun_interface_name: str | None = None) -> None:
        if not self.process:
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
        self._active_tun_interface = None
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

    def _wait_until_core_connected(self, settings: AppSettings) -> tuple[bool, str]:
        deadline = time.monotonic() + self.CORE_CONNECTIVITY_TIMEOUT
        last_error = "Проверка выхода через core не выполнена"
        while time.monotonic() < deadline:
            if not self.process or self.process.poll() is not None:
                return False, self._unexpected_exit_message(startup=True)
            ok, error = self._check_core_connectivity_once(settings)
            if ok:
                self.logger.info("Проверка подключения через текущий сервер прошла успешно")
                return True, ""
            last_error = error
            time.sleep(0.35)
        return False, (
            "sing-box запустился, но проверка выхода через текущий сервер не прошла. "
            f"Последняя ошибка: {last_error}"
        )

    def _check_core_connectivity_once(self, settings: AppSettings) -> tuple[bool, str]:
        session = requests.Session()
        session.trust_env = False
        proxy_url = f"http://{self._connect_host(settings.mixed_listen_host)}:{int(settings.mixed_port)}"
        proxies = {"http": proxy_url, "https": proxy_url} if settings.mode == "proxy" else None
        last_error = ""
        for url in self.CONNECTIVITY_TEST_URLS:
            try:
                response = session.get(
                    url,
                    timeout=(1.5, 2.0),
                    allow_redirects=False,
                    proxies=proxies,
                    headers={"User-Agent": "RazreshenieVPN/1.1.5"},
                )
            except requests.RequestException as exc:
                last_error = f"{url}: {exc}"
                continue
            if 200 <= response.status_code < 400:
                return True, ""
            last_error = f"{url}: HTTP {response.status_code}"
        return False, last_error or "нет ответа от проверочных URL"

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
            if self._tun_interface_has_ipv4(tun_interface_name):
                return True
            time.sleep(0.25)
        return False

    @staticmethod
    def _connect_host(host: str) -> str:
        value = str(host or "").strip()
        if value in {"", "0.0.0.0", "::", "[::]"}:
            return "127.0.0.1"
        return value.strip("[]")

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
    def _preflight_profile(profile: VlessProfile) -> None:
        if not str(profile.address or "").strip():
            raise SingBoxError("У выбранного профиля не указан адрес сервера")
        try:
            port = int(profile.port)
        except (TypeError, ValueError) as exc:
            raise SingBoxError("У выбранного профиля указан некорректный порт") from exc
        if port <= 0 or port > 65535:
            raise SingBoxError("У выбранного профиля порт вне диапазона 1-65535")
        if not str(profile.uuid or "").strip():
            raise SingBoxError("У выбранного профиля не указан UUID")

    def _preflight_server_reachability(self, profile: VlessProfile) -> None:
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
    def _profile_uses_udp_transport(profile: VlessProfile) -> bool:
        params = {key.lower(): str(value).lower() for key, value in profile.params.items()}
        network = params.get("type") or params.get("network") or "tcp"
        return network == "quic"

    @staticmethod
    def _tun_interface_has_ipv4(tun_interface_name: str) -> bool:
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
                timeout=4,
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

    def _active_foreign_tun_adapters(self, own_interface_name: str) -> list[str]:
        if os.name != "nt":
            return []
        own = str(own_interface_name or "").replace("'", "''")
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$own='{own}'; "
            "Get-NetAdapter | "
            "Where-Object { "
            "$_.Status -eq 'Up' -and $_.Name -ne $own -and "
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
                timeout=6,
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
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
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
        if result.returncode == 0:
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
