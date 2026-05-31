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

import hashlib
import logging
import shutil
import subprocess
import threading
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

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("razreshenie")
        self.builder = SingBoxConfigBuilder()
        self.process: subprocess.Popen[str] | None = None
        self.config_path = paths.runtime_config_path()
        self._lock = threading.RLock()
        self._reader_thread: threading.Thread | None = None

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
        try:
            proc = subprocess.run(
                [str(exe), "version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                check=False,
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
            config_path = self.build_and_save_config(profile, settings, split_rules)
            ok, output = self.check_config(config_path)
            if not ok:
                raise SingBoxError(f"sing-box отклонил конфигурацию:\n{output}")
            self.logger.info("Запуск sing-box: %s", config_path)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            self.process = subprocess.Popen(
                [str(exe), "run", "-c", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
            self._reader_thread = threading.Thread(target=self._read_process_logs, daemon=True)
            self._reader_thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self.process:
                return
            proc = self.process
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

    def _read_process_logs(self) -> None:
        proc = self.process
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            message = line.strip()
            if message:
                self.logger.info("[sing-box] %s", message)
        code = proc.poll()
        if code not in (None, 0):
            self.logger.error("sing-box завершился с кодом %s", code)

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
