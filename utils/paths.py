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

"""Пути приложения и пользовательская папка данных."""

from __future__ import annotations

import sys
from pathlib import Path


APP_DIR_NAME = "Razreshenie VPN"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PORTABLE_FLAG = PROJECT_ROOT / "portable.flag"


def resource_path(*parts: str) -> Path:
    """Возвращает путь к bundled-ресурсу в исходниках или PyInstaller onefile."""
    root = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
    return root.joinpath(*parts)


def logo_path() -> Path:
    for candidate in (
        resource_path("logo.webp"),
        resource_path("assets", "logo.webp"),
        PROJECT_ROOT / "logo.webp",
        PROJECT_ROOT / "assets" / "logo.webp",
    ):
        if candidate.exists():
            return candidate
    return PROJECT_ROOT / "logo.webp"


def is_portable_mode() -> bool:
    return False


def set_portable_mode(enabled: bool) -> None:
    _ = enabled
    _remove_legacy_portable_flag()


def _remove_legacy_portable_flag() -> None:
    try:
        PORTABLE_FLAG.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def data_dir() -> Path:
    return Path.home() / APP_DIR_NAME


def ensure_app_dirs() -> dict[str, Path]:
    _remove_legacy_portable_flag()
    root = data_dir()
    dirs = {
        "data": root,
        "logs": root / "logs",
        "configs": root / "configs",
        "cores": root / "cores",
        "rules": root / "rules",
        "downloads": root / "downloads",
        "backups": root / "backups",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def runtime_config_path() -> Path:
    return ensure_app_dirs()["configs"] / "sing-box-runtime.json"


def log_file_path() -> Path:
    return ensure_app_dirs()["logs"] / "razreshenie.log"


def settings_path() -> Path:
    return ensure_app_dirs()["data"] / "settings.json"


def profiles_path() -> Path:
    return ensure_app_dirs()["data"] / "profiles.json"


def subscriptions_path() -> Path:
    return ensure_app_dirs()["data"] / "subscriptions.json"


def rules_path() -> Path:
    return ensure_app_dirs()["rules"] / "split-rules.json"
