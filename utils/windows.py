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
import os
import sys
from pathlib import Path


APP_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "Razreshenie VPN Client"


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
