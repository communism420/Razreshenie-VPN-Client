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

"""Сетевые проверки для панели состояния."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass

import psutil
import requests


def _subprocess_no_window_kwargs() -> dict[str, object]:
    """Параметры subprocess для скрытого запуска консольных утилит Windows."""
    if platform.system().lower() != "windows":
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
        "startupinfo": startupinfo,
    }


def get_public_ip(timeout: float = 5.0) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            value = response.text.strip()
            if value:
                return value
        except requests.RequestException:
            continue
    return "неизвестно"


def ping_host(host: str, timeout_ms: int = 1500) -> str:
    latency = measure_icmp_latency_ms(host, timeout_ms)
    return f"{latency} мс" if latency is not None else "таймаут"


def measure_tcp_latency_ms(host: str, port: int, timeout_ms: int = 1500) -> int | None:
    if not host or not port:
        return None
    started = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_ms / 1000):
            return max(1, int((time.perf_counter() - started) * 1000))
    except OSError:
        return None


def measure_icmp_latency_ms(host: str, timeout_ms: int = 1500) -> int | None:
    if not host:
        return None
    is_windows = platform.system().lower() == "windows"
    command = "ping.exe" if is_windows else "ping"
    count_arg = "-n" if is_windows else "-c"
    timeout_arg = "-w" if is_windows else "-W"
    timeout_value = str(timeout_ms if is_windows else max(1, timeout_ms // 1000))
    try:
        proc = subprocess.run(
            [command, count_arg, "1", timeout_arg, timeout_value, host],
            capture_output=True,
            timeout=max(2.0, timeout_ms / 1000 + 1),
            check=False,
            **_subprocess_no_window_kwargs(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    encoding = "oem" if is_windows else "utf-8"
    output = (proc.stdout or b"").decode(encoding, errors="ignore")
    output += (proc.stderr or b"").decode(encoding, errors="ignore")
    match = re.search(r"(?:time|время)[=<]\s*(\d+)\s*(?:ms|мс)", output, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def measure_server_latency_ms(host: str, port: int, timeout_ms: int = 1500) -> int | None:
    """Меряет отклик сервера: TCP handshake к proxy port, затем ICMP fallback."""
    latency = measure_tcp_latency_ms(host, port, timeout_ms)
    if latency is not None:
        return latency
    return measure_icmp_latency_ms(host, timeout_ms)


def check_dns_resolver(timeout: float = 5.0) -> str:
    """Быстрая эвристика DNS: показывает ответ DoH-резолвера, не заменяет полный leak-test."""
    try:
        response = requests.get(
            "https://dns.google/resolve",
            params={"name": "o-o.myaddr.l.google.com", "type": "TXT"},
            timeout=timeout,
        )
        response.raise_for_status()
        answers = response.json().get("Answer") or []
        values = [str(item.get("data", "")).strip('"') for item in answers if item.get("data")]
        return ", ".join(values) if values else "DNS-ответ получен, утечек не обнаружено эвристикой"
    except requests.RequestException as exc:
        return f"Проверка DNS не удалась: {exc}"


def format_speed(bytes_per_second: float) -> str:
    units = ("Б/с", "КБ/с", "МБ/с", "ГБ/с")
    value = float(max(0.0, bytes_per_second))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    return f"{value:.1f} {units[unit_index]}"


@dataclass
class TrafficSample:
    download: float = 0.0
    upload: float = 0.0


class TrafficMonitor:
    """Считает общую скорость по системным сетевым счетчикам."""

    def __init__(self) -> None:
        counters = psutil.net_io_counters()
        self._last_recv = counters.bytes_recv
        self._last_sent = counters.bytes_sent
        self._last_time = time.monotonic()

    def sample(self) -> TrafficSample:
        counters = psutil.net_io_counters()
        now = time.monotonic()
        elapsed = max(0.001, now - self._last_time)
        download = (counters.bytes_recv - self._last_recv) / elapsed
        upload = (counters.bytes_sent - self._last_sent) / elapsed
        self._last_recv = counters.bytes_recv
        self._last_sent = counters.bytes_sent
        self._last_time = now
        return TrafficSample(download=download, upload=upload)
