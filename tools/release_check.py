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

"""Local release gate for Razreshenie VPN Client."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "4.0.0"
EXPECTED_VERSION_TUPLE = "4, 0, 0, 0"


def main() -> int:
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    required_files = (
        "README.md",
        "CHANGELOG.md",
        "NOTICE.md",
        "licenses/OPEN_SOURCE_POLICY.md",
        "docs/README.md",
        "docs/BUILD_RELEASE.md",
        "docs/PRIVACY_SECURITY.md",
        "docs/TROUBLESHOOTING.md",
        "docs/ADVANCED_GROUPS.md",
        "docs/PROTOCOLS.md",
        "tools/windows_version_info.txt",
        "utils/version.py",
        "Razreshenie VPN Client.spec",
    )
    for relative in required_files:
        check((ROOT / relative).exists(), f"Missing required release file: {relative}")

    if errors:
        return _finish(errors)

    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    notice = _read("NOTICE.md")
    policy = _read("licenses/OPEN_SOURCE_POLICY.md")
    docs_readme = _read("docs/README.md")
    build_release = _read("docs/BUILD_RELEASE.md")
    privacy = _read("docs/PRIVACY_SECURITY.md")
    troubleshooting = _read("docs/TROUBLESHOOTING.md")
    advanced_groups = _read("docs/ADVANCED_GROUPS.md")
    protocols = _read("docs/PROTOCOLS.md")
    version_py = _read("utils/version.py")
    win_version = _read("tools/windows_version_info.txt")
    spec = _read("Razreshenie VPN Client.spec")

    check(f'APP_VERSION = "{EXPECTED_VERSION}"' in version_py, "utils/version.py APP_VERSION is not 4.0.0")
    check(f"filevers=({EXPECTED_VERSION_TUPLE})" in win_version, "windows_version_info filevers is not 4.0.0.0")
    check(f"prodvers=({EXPECTED_VERSION_TUPLE})" in win_version, "windows_version_info prodvers is not 4.0.0.0")
    check(f"FileVersion', '{EXPECTED_VERSION}'" in win_version, "windows_version_info FileVersion is not 4.0.0")
    check(f"ProductVersion', '{EXPECTED_VERSION}'" in win_version, "windows_version_info ProductVersion is not 4.0.0")

    check(f"**Версия:** `{EXPECTED_VERSION}`" in readme, "README.md does not show version 4.0.0")
    check(f"Razreshenie VPN Client version {EXPECTED_VERSION}" in notice, "NOTICE.md does not show version 4.0.0")
    check(f"Текущая версия приложения: {EXPECTED_VERSION}" in policy, "OPEN_SOURCE_POLICY does not show version 4.0.0")

    check(re.search(rf"^## {re.escape(EXPECTED_VERSION)}\b", changelog, re.MULTILINE) is not None, "CHANGELOG.md lacks 4.0.0 section")
    for marker in ("Архитектура", "Тестирование", "Стабильность", "Диагностика", "Приватность"):
        check(marker in changelog, f"CHANGELOG.md lacks marker: {marker}")

    check("CHANGELOG.md" in readme, "README.md does not link CHANGELOG.md")
    check("../CHANGELOG.md" in docs_readme, "docs/README.md does not link ../CHANGELOG.md")
    check("python main.py --self-check" in build_release, "BUILD_RELEASE.md lacks self-check gate")
    check("python tools\\release_check.py" in build_release, "BUILD_RELEASE.md lacks release_check gate")
    check("Get-FileHash" in build_release and "SHA256" in build_release, "BUILD_RELEASE.md lacks SHA256 instructions")
    check("Privacy/security gate" in build_release, "BUILD_RELEASE.md lacks privacy/security gate")
    check("Smoke test" in build_release, "BUILD_RELEASE.md lacks EXE smoke test")

    check("state/stability-summary.redacted.json" in privacy, "PRIVACY_SECURITY.md lacks stability summary note")
    check("Заменить текущий EXE" in privacy, "PRIVACY_SECURITY.md lacks in-place updater mode")
    check("batch" in privacy.lower(), "PRIVACY_SECURITY.md lacks temporary batch updater note")
    check(
        "не заменяет запущенный EXE автоматически" not in privacy,
        "PRIVACY_SECURITY.md still contains stale updater statement",
    )

    check("Reality профиль не запускается" in troubleshooting, "TROUBLESHOOTING.md lacks Reality section")
    check("Advanced-группа не запускается" in troubleshooting, "TROUBLESHOOTING.md lacks advanced group section")
    check("Обновление приложения" in troubleshooting, "TROUBLESHOOTING.md lacks updater troubleshooting")
    check("cooldown" in advanced_groups.lower(), "ADVANCED_GROUPS.md lacks recovery cooldown note")
    check("pbk/publicKey" in protocols and "sid/short_id" in protocols, "PROTOCOLS.md lacks Reality validation details")

    check("name='Razreshenie VPN Client 4.0.0'" in spec, "PyInstaller spec name is not versioned for 4.0.0")
    check("version='tools\\\\windows_version_info.txt'" in spec, "PyInstaller spec lacks Windows version metadata")
    check("collect_data_files('qfluentwidgets')" in spec, "PyInstaller spec lacks qfluentwidgets data collection")
    check("excludes=[" in spec and "PyQt5" in spec and "tkinter" in spec, "PyInstaller spec lacks release excludes")

    attribution_targets = {
        "zapret-kvn": "https://github.com/youtubediscord/zapret-kvn",
        "Karing": "https://github.com/KaringX/karing",
        "russia-mobile-internet-whitelist": "https://github.com/hxehex/russia-mobile-internet-whitelist",
        "flag-icons": "https://github.com/lipis/flag-icons",
    }
    attribution_text = "\n".join((readme, notice, policy))
    for label, url in attribution_targets.items():
        check(url in attribution_text, f"Missing attribution URL for {label}")

    check("Телеметрии нет" in readme or "телеметрии" in privacy.lower(), "Privacy docs do not clearly state no telemetry")
    check((ROOT / "assets/flags/LICENSE.flag-icons.txt").exists(), "flag-icons license file is missing")

    return _finish(errors)


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8", errors="replace")


def _finish(errors: list[str]) -> int:
    if errors:
        print("Release check FAILED:")
        for item in errors:
            print(f"- {item}")
        return 1
    print(f"Release check OK: {EXPECTED_VERSION} docs, metadata, privacy and release checklist are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
