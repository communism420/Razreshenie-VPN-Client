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

"""Логирование в файл и в интерфейс."""

from __future__ import annotations

import logging
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock
from typing import Callable


LogCallback = Callable[[str, str], None]


class GuiLogHandler(logging.Handler):
    def __init__(self, callback: LogCallback) -> None:
        super().__init__()
        self.callback = callback

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.callback(record.levelname.lower(), self.format(record))
        except Exception:
            self.handleError(record)


class LogBuffer:
    """Короткая история логов для вкладки приложения."""

    def __init__(self, max_lines: int = 2000) -> None:
        self._lines: deque[tuple[str, str]] = deque(maxlen=max_lines)
        self._lock = RLock()

    def append(self, level: str, message: str) -> None:
        with self._lock:
            self._lines.append((level, message))

    def snapshot(self, level_filter: str = "all") -> list[str]:
        with self._lock:
            if level_filter == "all":
                return [message for _, message in self._lines]
            return [message for level, message in self._lines if level == level_filter]


def setup_logger(log_path: Path, callback: LogCallback | None = None) -> logging.Logger:
    logger = logging.getLogger("razreshenie")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    if callback:
        gui_handler = GuiLogHandler(callback)
        gui_handler.setFormatter(formatter)
        gui_handler.setLevel(logging.DEBUG)
        logger.addHandler(gui_handler)

    return logger
