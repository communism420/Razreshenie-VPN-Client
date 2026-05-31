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

"""Точка входа Razreshenie VPN Client."""

from __future__ import annotations

import argparse
import sys

from utils.version import APP_NAME, APP_VERSION


def run_gui() -> int:
    """Запускает графический интерфейс."""
    try:
        from gui.app import RazreshenieApp
    except ImportError as exc:
        print(
            "Не удалось импортировать зависимости GUI. "
            "Установите зависимости командой: pip install -r requirements.txt",
            file=sys.stderr,
        )
        print(str(exc), file=sys.stderr)
        return 2

    app = RazreshenieApp()
    app.mainloop()
    return 0


def run_self_check() -> int:
    """Минимальная проверка основных модулей без запуска GUI."""
    from core.vless_parser import parse_vless_uri
    from models.rules import SplitRules
    from models.settings import AppSettings
    from core.config_builder import SingBoxConfigBuilder

    sample = (
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision"
        "&sni=example.com&fp=chrome&pbk=public-key&sid=abcd#Demo"
    )
    profile = parse_vless_uri(sample)
    settings = AppSettings(mode="proxy")
    rules = SplitRules(enabled=False)
    config = SingBoxConfigBuilder().build(profile, settings, rules, log_path=None)
    assert config["outbounds"][0]["type"] == "vless"
    assert config["route"]["final"] == "proxy"
    print("Self-check OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME)
    parser.add_argument("--self-check", action="store_true", help="проверить основные модули")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args()
    if args.self_check:
        return run_self_check()
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
