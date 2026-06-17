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

"""Проверка и безопасная загрузка обновлений приложения через GitHub Releases."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

import requests

from utils import paths
from utils.version import APP_REPOSITORY, APP_VERSION


GITHUB_API_ROOT = "https://api.github.com/repos"
WINDOWS_UPDATE_EXTENSIONS = (".msi", ".exe", ".zip")
APP_UPDATES_DIR_NAME = "app-updates"
VERSION_PRERELEASE_MARKERS = {"a", "alpha", "b", "beta", "rc", "pre", "preview", "dev"}
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._() \-]+")


class AppUpdateError(RuntimeError):
    """Ошибка проверки или загрузки обновления приложения."""


@dataclass(frozen=True, slots=True)
class AppReleaseAsset:
    name: str
    download_url: str
    size: int = 0
    browser_url: str = ""


@dataclass(frozen=True, slots=True)
class AppUpdateInfo:
    current_version: str
    latest_version: str
    update_available: bool
    release_url: str
    release_name: str = ""
    published_at: str = ""
    asset: AppReleaseAsset | None = None
    checksum_asset: AppReleaseAsset | None = None

    @property
    def asset_name(self) -> str:
        return self.asset.name if self.asset else ""


@dataclass(frozen=True, slots=True)
class PreparedInPlaceUpdate:
    downloaded_path: Path
    script_path: Path
    current_executable: Path
    install_path: Path
    process_id: int


def app_release_api_url(repository_url: str = APP_REPOSITORY) -> str:
    """Возвращает GitHub API endpoint latest release для URL репозитория."""
    parsed = urlparse(str(repository_url or "").strip())
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise AppUpdateError("Автообновление поддерживает только GitHub Releases")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise AppUpdateError("Некорректный URL GitHub репозитория")
    owner, repo = parts[0], parts[1]
    return f"{GITHUB_API_ROOT}/{owner}/{repo}/releases/latest"


def is_newer_version(latest_version: str, current_version: str) -> bool:
    """Сравнивает semver-like версии без внешних зависимостей."""
    latest_numbers, latest_prerelease, latest_suffix = _version_key(latest_version)
    current_numbers, current_prerelease, current_suffix = _version_key(current_version)
    width = max(len(latest_numbers), len(current_numbers))
    latest_base = latest_numbers + (0,) * (width - len(latest_numbers))
    current_base = current_numbers + (0,) * (width - len(current_numbers))
    if latest_base != current_base:
        return latest_base > current_base
    if latest_prerelease != current_prerelease:
        return current_prerelease and not latest_prerelease
    return _suffix_rank(latest_suffix) > _suffix_rank(current_suffix)


def update_info_from_release(
    release: Mapping[str, Any],
    *,
    current_version: str = APP_VERSION,
) -> AppUpdateInfo:
    if not isinstance(release, Mapping):
        raise AppUpdateError("GitHub вернул некорректные данные release")

    tag = str(release.get("tag_name") or release.get("name") or "").strip()
    latest_version = tag.lstrip("vV") or "latest"
    release_url = str(release.get("html_url") or APP_REPOSITORY).strip()
    release_name = str(release.get("name") or tag or "Latest release").strip()
    published_at = str(release.get("published_at") or "").strip()
    assets_payload = release.get("assets") or []
    assets = assets_payload if isinstance(assets_payload, Sequence) else []
    asset = select_windows_asset(assets)
    checksum_asset = select_checksum_asset(assets, asset.name if asset else "")
    update_available = is_newer_version(latest_version, current_version)
    return AppUpdateInfo(
        current_version=current_version,
        latest_version=latest_version,
        update_available=update_available,
        release_url=release_url,
        release_name=release_name,
        published_at=published_at,
        asset=asset,
        checksum_asset=checksum_asset,
    )


def check_for_app_update(
    *,
    current_version: str = APP_VERSION,
    repository_url: str = APP_REPOSITORY,
    timeout: float = 20.0,
) -> AppUpdateInfo:
    """Получает latest release GitHub и возвращает результат сравнения версий."""
    api_url = app_release_api_url(repository_url)
    try:
        response = requests.get(
            api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"RazreshenieVPN/{APP_VERSION}",
            },
            timeout=max(1.0, float(timeout)),
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise AppUpdateError(f"Не удалось проверить обновления приложения: {exc}") from exc
    except ValueError as exc:
        raise AppUpdateError("GitHub вернул некорректный JSON release") from exc
    return update_info_from_release(payload, current_version=current_version)


def select_windows_asset(assets: Sequence[Any]) -> AppReleaseAsset | None:
    """Выбирает наиболее подходящий Windows x64 asset из release."""
    candidates: list[tuple[int, str, AppReleaseAsset]] = []
    for raw_asset in assets:
        if not isinstance(raw_asset, Mapping):
            continue
        asset = _asset_from_mapping(raw_asset)
        score = _windows_asset_score(asset)
        if score is None:
            continue
        candidates.append((score, asset.name.lower(), asset))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def select_checksum_asset(assets: Sequence[Any], target_name: str = "") -> AppReleaseAsset | None:
    target = str(target_name or "").lower()
    fallback: AppReleaseAsset | None = None
    for raw_asset in assets:
        if not isinstance(raw_asset, Mapping):
            continue
        asset = _asset_from_mapping(raw_asset)
        name = asset.name.lower()
        if not asset.download_url:
            continue
        if "sha256" not in name and "checksum" not in name and not name.endswith(".sha256"):
            continue
        if target and target in name:
            return asset
        if fallback is None:
            fallback = asset
    return fallback


def download_update_asset(
    update: AppUpdateInfo,
    *,
    target_dir: Path | None = None,
    verify_checksum: bool = True,
    timeout: float = 90.0,
) -> Path:
    """Скачивает выбранный update asset в локальную папку downloads/app-updates."""
    if not update.asset:
        raise AppUpdateError("В release нет подходящего Windows-файла обновления")
    root = target_dir or (paths.ensure_app_dirs()["downloads"] / APP_UPDATES_DIR_NAME)
    root.mkdir(parents=True, exist_ok=True)
    target = root / _safe_filename(update.asset.name)
    temp_target = target.with_suffix(target.suffix + ".part")
    try:
        with requests.get(
            update.asset.download_url,
            stream=True,
            headers={"User-Agent": f"RazreshenieVPN/{APP_VERSION}"},
            timeout=max(1.0, float(timeout)),
        ) as response:
            response.raise_for_status()
            with temp_target.open("wb") as file:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        file.write(chunk)
        if _file_size(temp_target) <= 0:
            raise AppUpdateError("Скачанный файл обновления пустой")
        if verify_checksum and update.checksum_asset:
            _verify_sha256_if_available(update.checksum_asset, target.name, temp_target)
        temp_target.replace(target)
    except requests.RequestException as exc:
        _remove_partial(temp_target)
        raise AppUpdateError(f"Не удалось скачать обновление приложения: {exc}") from exc
    except AppUpdateError:
        _remove_partial(temp_target)
        raise
    except OSError as exc:
        _remove_partial(temp_target)
        raise AppUpdateError(f"Не удалось сохранить обновление приложения: {exc}") from exc
    return target


def current_executable_can_be_replaced(current_executable: Path | None = None) -> bool:
    executable = Path(current_executable or sys.executable)
    return os.name == "nt" and executable.suffix.lower() == ".exe" and bool(getattr(sys, "frozen", False))


def prepare_in_place_update(
    downloaded_update: Path,
    *,
    current_executable: Path | None = None,
    updates_dir: Path | None = None,
    require_frozen: bool = True,
) -> PreparedInPlaceUpdate:
    """Готовит Windows batch-файл, который заменит текущий EXE после выхода приложения."""
    if os.name != "nt":
        raise AppUpdateError("Замена текущего EXE поддерживается только на Windows")
    executable = Path(current_executable or sys.executable).resolve()
    if executable.suffix.lower() != ".exe":
        raise AppUpdateError("Замена текущего EXE доступна только для .exe сборки")
    if require_frozen and not getattr(sys, "frozen", False):
        raise AppUpdateError("Замена текущего EXE недоступна при запуске из исходников")
    downloaded = Path(downloaded_update).resolve()
    if not downloaded.exists():
        raise AppUpdateError("Скачанный файл обновления не найден")
    if downloaded.suffix.lower() != ".exe":
        raise AppUpdateError("Автоматическая замена поддерживает только .exe asset")
    if _file_size(downloaded) <= 0:
        raise AppUpdateError("Скачанный файл обновления пустой")
    if downloaded == executable:
        raise AppUpdateError("Файл обновления совпадает с текущим EXE")

    updates_dir = updates_dir or (paths.ensure_app_dirs()["downloads"] / APP_UPDATES_DIR_NAME)
    updates_dir.mkdir(parents=True, exist_ok=True)
    install_path = executable
    script_path = updates_dir / f"apply-update-{int(time.time())}.bat"
    backup_path = executable.with_suffix(executable.suffix + ".old")
    log_path = updates_dir / "apply-update.log"
    script_path.write_text(
        _build_in_place_update_script(
            current_executable=executable,
            downloaded_update=downloaded,
            install_path=install_path,
            backup_path=backup_path,
            log_path=log_path,
            process_id=os.getpid(),
        ),
        encoding="utf-8",
        newline="\r\n",
    )
    return PreparedInPlaceUpdate(
        downloaded_path=downloaded,
        script_path=script_path,
        current_executable=executable,
        install_path=install_path,
        process_id=os.getpid(),
    )


def launch_in_place_update(plan: PreparedInPlaceUpdate) -> None:
    if not plan.script_path.exists():
        raise AppUpdateError("Скрипт замены приложения не найден")
    if _file_size(plan.script_path) <= 0:
        raise AppUpdateError("Скрипт замены приложения пустой")
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        subprocess.Popen(
            ["cmd.exe", "/c", str(plan.script_path)],
            cwd=str(plan.script_path.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            close_fds=True,
        )
    except OSError as exc:
        raise AppUpdateError(f"Не удалось запустить замену приложения: {exc}") from exc


def _version_key(version: str) -> tuple[tuple[int, ...], bool, tuple[str, ...]]:
    text = str(version or "").strip().lower()
    text = text.lstrip("v")
    match = re.search(r"\d", text)
    if match:
        text = text[match.start() :]
    if "+" in text:
        text = text.split("+", 1)[0]
    tokens = re.findall(r"\d+|[a-z]+", text)
    numbers: list[int] = []
    suffix: list[str] = []
    in_suffix = False
    for token in tokens:
        if token.isdigit() and not in_suffix:
            numbers.append(int(token))
            continue
        in_suffix = True
        suffix.append(token)
    if not numbers:
        numbers.append(0)
    prerelease = any(token in VERSION_PRERELEASE_MARKERS for token in suffix)
    return tuple(numbers), prerelease, tuple(suffix)


def _suffix_rank(suffix: tuple[str, ...]) -> tuple[tuple[int, object], ...]:
    result: list[tuple[int, object]] = []
    for token in suffix:
        if token.isdigit():
            result.append((1, int(token)))
        else:
            result.append((0, token))
    return tuple(result)


def _asset_from_mapping(asset: Mapping[str, Any]) -> AppReleaseAsset:
    return AppReleaseAsset(
        name=str(asset.get("name") or "").strip(),
        download_url=str(asset.get("browser_download_url") or "").strip(),
        size=_safe_int(asset.get("size")),
        browser_url=str(asset.get("html_url") or "").strip(),
    )


def _windows_asset_score(asset: AppReleaseAsset) -> int | None:
    name = asset.name.lower()
    if not name or not asset.download_url:
        return None
    if any(marker in name for marker in ("source", "src", "checksum", "sha256", ".sig", ".asc")):
        return None
    if any(marker in name for marker in ("linux", "darwin", "macos", "appimage", "deb", "rpm")):
        return None
    if any(marker in name for marker in ("arm64", "aarch64")):
        return None
    if "x86" in name and not any(marker in name for marker in ("x86_64", "x64", "amd64")):
        return None

    suffix = Path(name).suffix
    if suffix not in WINDOWS_UPDATE_EXTENSIONS:
        return None

    score = 100
    if any(marker in name for marker in ("windows", "win", "x64", "amd64")):
        score -= 20
    if any(marker in name for marker in ("setup", "installer", "install")):
        score -= 15
    if suffix == ".msi":
        score -= 10
    elif suffix == ".exe":
        score -= 8
    elif suffix == ".zip":
        score += 5
    if "portable" in name:
        score += 4
    if any(marker in name for marker in ("debug", "symbols", "pdb")):
        score += 40
    return score


def _verify_sha256_if_available(checksum_asset: AppReleaseAsset, target_name: str, target_path: Path) -> None:
    try:
        response = requests.get(
            checksum_asset.download_url,
            headers={"User-Agent": f"RazreshenieVPN/{APP_VERSION}"},
            timeout=20,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise AppUpdateError(f"Не удалось скачать checksum обновления: {exc}") from exc

    expected = _extract_sha256(response.text, target_name)
    if not expected:
        raise AppUpdateError("Checksum release не содержит SHA256 для файла обновления")
    digest = hashlib.sha256(target_path.read_bytes()).hexdigest().lower()
    if digest != expected.lower():
        raise AppUpdateError("SHA256 скачанного обновления не совпадает с checksum release")


def _extract_sha256(text: str, target_name: str) -> str | None:
    target = str(target_name or "").lower()
    for line in str(text or "").splitlines():
        if target and target not in line.lower():
            continue
        match = SHA256_RE.search(line)
        if match:
            return match.group(0).lower()
    matches = SHA256_RE.findall(str(text or ""))
    if len(matches) == 1:
        return matches[0].lower()
    return None


def _safe_filename(name: str) -> str:
    cleaned = FILENAME_SAFE_RE.sub("_", str(name or "").strip()).strip(" .")
    return cleaned or "razreshenie-update.bin"


def _batch_value(value: Path) -> str:
    return str(value).replace("%", "%%")


def _build_in_place_update_script(
    *,
    current_executable: Path,
    downloaded_update: Path,
    install_path: Path,
    backup_path: Path,
    log_path: Path,
    process_id: int,
) -> str:
    old_value = _batch_value(current_executable)
    new_value = _batch_value(downloaded_update)
    install_value = _batch_value(install_path)
    backup_value = _batch_value(backup_path)
    log_value = _batch_value(log_path)
    pid_value = str(max(0, int(process_id)))
    return f"""@echo off
setlocal EnableExtensions
set "OLD={old_value}"
set "NEW={new_value}"
set "INSTALL={install_value}"
set "BACKUP={backup_value}"
set "LOG={log_value}"
set "PID={pid_value}"
echo [%date% %time%] Applying Razreshenie VPN Client update>"%LOG%"
call :log Current EXE: "%OLD%"
call :log Downloaded EXE: "%NEW%"
call :log Target EXE: "%INSTALL%"
if not exist "%NEW%" goto fail_missing_new
if /I not "%INSTALL%"=="%OLD%" goto fail_bad_target
call :wait_for_app_exit
call :replace_current_exe
if errorlevel 1 goto restore_old
call :log Update installed successfully.
start "" "%OLD%"
goto cleanup

:wait_for_app_exit
if "%PID%"=="0" exit /b 0
call :log Waiting for process PID %PID% to exit.
for /l %%i in (1,1,45) do (
    tasklist /FI "PID eq %PID%" /NH 2>nul | findstr /R /C:"[ ][ ]*%PID%[ ][ ]*" >nul
    if errorlevel 1 exit /b 0
    ping -n 2 127.0.0.1 >nul
)
call :log Process is still running; forcing termination.
taskkill /PID %PID% /T /F >>"%LOG%" 2>&1
for /l %%i in (1,1,20) do (
    tasklist /FI "PID eq %PID%" /NH 2>nul | findstr /R /C:"[ ][ ]*%PID%[ ][ ]*" >nul
    if errorlevel 1 exit /b 0
    ping -n 2 127.0.0.1 >nul
)
exit /b 0

:replace_current_exe
if exist "%BACKUP%" del /f /q "%BACKUP%" >>"%LOG%" 2>&1
for /l %%i in (1,1,90) do (
    if not exist "%OLD%" goto install_new
    attrib -r -s -h "%OLD%" >>"%LOG%" 2>&1
    move /y "%OLD%" "%BACKUP%" >>"%LOG%" 2>&1
    if not exist "%OLD%" goto install_new
    del /f /q "%OLD%" >>"%LOG%" 2>&1
    if not exist "%OLD%" goto install_new
    ping -n 2 127.0.0.1 >nul
)
call :log Failed to remove or move the old EXE.
exit /b 1

:install_new
copy /y "%NEW%" "%OLD%" >>"%LOG%" 2>&1
if errorlevel 1 exit /b 1
if not exist "%OLD%" exit /b 1
for %%A in ("%OLD%") do if %%~zA LEQ 0 exit /b 1
del /f /q "%NEW%" >>"%LOG%" 2>&1
if exist "%BACKUP%" del /f /q "%BACKUP%" >>"%LOG%" 2>&1
exit /b 0

:restore_old
call :log Update failed; trying to restore the old EXE.
if exist "%OLD%" del /f /q "%OLD%" >>"%LOG%" 2>&1
if exist "%BACKUP%" move /y "%BACKUP%" "%OLD%" >>"%LOG%" 2>&1
goto launch_old

:fail_missing_new
call :log Downloaded EXE does not exist.
goto launch_old

:fail_bad_target
call :log Internal error: install path is not the current EXE path.
goto launch_old

:launch_old
if exist "%OLD%" start "" "%OLD%"
goto cleanup

:log
echo [%date% %time%] %*>>"%LOG%"
exit /b 0

:cleanup
del /f /q "%~f0" >nul 2>&1
exit /b 0
"""


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _remove_partial(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
