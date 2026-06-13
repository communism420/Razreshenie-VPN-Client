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

"""Windows-интеграции: автозапуск, права администратора, proxy guard, уведомления."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


APP_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "Razreshenie VPN Client"
FIREWALL_KILL_SWITCH_GROUP = "Razreshenie VPN Kill Switch"
FIREWALL_KILL_SWITCH_RULE_ALLOW_CORE = f"{FIREWALL_KILL_SWITCH_GROUP} - Allow sing-box"
FIREWALL_KILL_SWITCH_RULE_ALLOW_APP_LOOPBACK = f"{FIREWALL_KILL_SWITCH_GROUP} - Allow app loopback"
FIREWALL_PROFILES = ("Domain", "Private", "Public")


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if not is_windows():
        return False
    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = sys.argv[1:]
    else:
        executable = sys.executable
        script = str(Path(sys.argv[0]).resolve())
        args = [script, *sys.argv[1:]]
    params = " ".join(f'"{arg}"' for arg in args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    return result > 32


def set_autostart(enabled: bool, executable: str | None = None) -> None:
    if not is_windows():
        return
    import winreg

    exe = executable or sys.executable
    command = f'"{exe}"'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, APP_REG_NAME)
            except FileNotFoundError:
                pass


def set_system_proxy(enabled: bool, host: str, port: int) -> None:
    """Включает системный HTTP/SOCKS proxy для proxy guard. Это не firewall-kill-switch."""
    if not is_windows():
        return
    import winreg

    proxy_server = f"http={host}:{port};https={host}:{port};socks={host}:{port}"
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
        if enabled:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)

    internet_option_settings_changed = 39
    internet_option_refresh = 37
    ctypes.windll.Wininet.InternetSetOptionW(0, internet_option_settings_changed, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, internet_option_refresh, 0, 0)


def set_firewall_kill_switch(
    enabled: bool,
    allowed_executable: str | Path,
    *,
    app_executable: str | Path | None = None,
) -> None:
    """Включает fail-closed Windows Firewall режим.

    Реализация меняет DefaultOutboundAction профилей Windows Firewall на Block и
    добавляет allow-правило для sing-box. Это намеренно отдельный opt-in режим:
    без прав администратора он не применяется.
    """
    if not is_windows():
        return
    if not enabled:
        clear_firewall_kill_switch()
        return
    if not is_admin():
        raise RuntimeError("Firewall Kill Switch требует права администратора")

    core_path = Path(allowed_executable).resolve()
    app_path = Path(app_executable or sys.executable).resolve()
    if not core_path.exists():
        raise RuntimeError(f"sing-box не найден для Firewall Kill Switch: {core_path}")
    profile_defaults = _firewall_profile_defaults()
    _write_firewall_backup(profile_defaults)
    _run_powershell(build_firewall_kill_switch_enable_script(core_path, app_path), timeout=20)


def clear_firewall_kill_switch() -> None:
    if not is_windows():
        return
    if not is_admin():
        raise RuntimeError("Для отключения Firewall Kill Switch нужны права администратора")
    profile_defaults = _read_firewall_backup()
    _run_powershell(build_firewall_kill_switch_clear_script(profile_defaults), timeout=20)
    _delete_firewall_backup()


def build_firewall_kill_switch_enable_script(
    allowed_executable: str | Path,
    app_executable: str | Path | None = None,
) -> str:
    core_path = _ps_quote(str(Path(allowed_executable)))
    app_path = _ps_quote(str(Path(app_executable or sys.executable)))
    group = _ps_quote(FIREWALL_KILL_SWITCH_GROUP)
    allow_core = _ps_quote(FIREWALL_KILL_SWITCH_RULE_ALLOW_CORE)
    allow_app_loopback = _ps_quote(FIREWALL_KILL_SWITCH_RULE_ALLOW_APP_LOOPBACK)
    profiles = ",".join(FIREWALL_PROFILES)
    return (
        "$ErrorActionPreference='Stop'; "
        f"$group={group}; "
        "Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule; "
        f"New-NetFirewallRule -DisplayName {allow_core} -DisplayGroup $group "
        "-Direction Outbound -Action Allow "
        f"-Program {core_path} -Profile Any | Out-Null; "
        f"New-NetFirewallRule -DisplayName {allow_app_loopback} -DisplayGroup $group "
        "-Direction Outbound -Action Allow "
        f"-Program {app_path} -RemoteAddress 127.0.0.1,::1 -Profile Any | Out-Null; "
        f"Set-NetFirewallProfile -Profile {profiles} -DefaultOutboundAction Block"
    )


def build_firewall_kill_switch_clear_script(profile_defaults: dict[str, str] | None = None) -> str:
    group = _ps_quote(FIREWALL_KILL_SWITCH_GROUP)
    commands = [
        "$ErrorActionPreference='Stop'",
        f"$group={group}",
        "Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
    ]
    if profile_defaults:
        for profile in FIREWALL_PROFILES:
            action = str(profile_defaults.get(profile) or "").strip()
            if action not in {"Allow", "Block"}:
                continue
            commands.append(f"Set-NetFirewallProfile -Profile {profile} -DefaultOutboundAction {action}")
    return "; ".join(commands)


def _firewall_profile_defaults() -> dict[str, str]:
    script = (
        "$ErrorActionPreference='Stop'; "
        "Get-NetFirewallProfile -Profile Domain,Private,Public | "
        "Select-Object Name,@{Name='DefaultOutboundAction';Expression={$_.DefaultOutboundAction.ToString()}} | "
        "ConvertTo-Json -Compress"
    )
    output = _run_powershell(script, timeout=10)
    try:
        payload: Any = json.loads(output or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Не удалось прочитать состояние Windows Firewall") from exc
    items = payload if isinstance(payload, list) else [payload]
    result: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "").strip()
        action = str(item.get("DefaultOutboundAction") or "").strip()
        if name in FIREWALL_PROFILES and action in {"Allow", "Block"}:
            result[name] = action
    for profile in FIREWALL_PROFILES:
        result.setdefault(profile, "Allow")
    return result


def _firewall_backup_path() -> Path:
    from utils import paths

    return paths.ensure_app_dirs()["data"] / "firewall-kill-switch-backup.json"


def _write_firewall_backup(profile_defaults: dict[str, str]) -> None:
    backup_path = _firewall_backup_path()
    if backup_path.exists():
        return
    backup_path.write_text(json.dumps(profile_defaults, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_firewall_backup() -> dict[str, str] | None:
    try:
        payload = json.loads(_firewall_backup_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return {str(key): str(value) for key, value in payload.items() if str(key) in FIREWALL_PROFILES}


def _delete_firewall_backup() -> None:
    try:
        _firewall_backup_path().unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def _run_powershell(script: str, *, timeout: float) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1.0, float(timeout)),
            check=False,
            **_no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"PowerShell не выполнил команду Firewall Kill Switch: {exc}") from exc
    if result.returncode != 0:
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        raise RuntimeError(output or f"PowerShell вернул код {result.returncode}")
    return result.stdout.strip()


def _no_window_kwargs() -> dict[str, object]:
    if not is_windows():
        return {}
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def show_toast(title: str, message: str) -> None:
    if not is_windows():
        return
    try:
        from winotify import Notification

        toast = Notification(app_id="Razreshenie VPN Client", title=title, msg=message)
        toast.show()
    except Exception:
        # Уведомления не критичны: приложение должно работать и без winotify.
        return


def executable_for_pyinstaller() -> Path:
    return Path(sys.executable).resolve()


def open_path(path: str | Path) -> None:
    """Открывает файл или папку системным способом."""
    target = Path(path).resolve()
    if is_windows():
        os.startfile(str(target))  # type: ignore[attr-defined]
        return
    command = ["open", str(target)] if sys.platform == "darwin" else ["xdg-open", str(target)]
    subprocess.Popen(command, **_no_window_kwargs())


def reveal_in_file_manager(path: str | Path) -> None:
    """Показывает файл в проводнике, если платформа это поддерживает."""
    target = Path(path).resolve()
    if is_windows():
        subprocess.Popen(["explorer", f"/select,{target}"], **_no_window_kwargs())
        return
    open_path(target.parent)
