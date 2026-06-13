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

"""Экспорт безопасного диагностического архива для баг-репортов."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import os
import platform
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

from utils import paths
from utils.storage import read_json
from utils.version import APP_NAME, APP_REPOSITORY, APP_VERSION

try:
    import psutil
except ImportError:  # pragma: no cover - зависимость есть в requirements, но экспорт не должен падать без нее.
    psutil = None  # type: ignore[assignment]


DIAGNOSTICS_ARCHIVE_VERSION = 1
URI_RE = re.compile(
    r"(?i)\b(?:vless|trojan|hysteria2|hy2|tuic|vmess|ss|shadowsocks|wireguard)://[^\s\"'<>]+"
)
HTTP_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
HEX_ID_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.%]*(?![\w:])")
DOMAIN_RE = re.compile(
    r"(?i)(?<![\w@/.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    r"(?::\d{1,5})?(?![\w.-])"
)
WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![\w])(?:[a-z]:[\\/]|\\\\|%[a-z0-9_() -]+%[\\/])"
    r"[^\r\n\"<>|?*]+?\.[a-z0-9]{1,8}(?=$|[\s,;)'\"\]])"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|uuid|pbk|sid|private[_-]?key|"
    r"public[_-]?key|key|server|address|host|hostname|sni|domain|domain[_-]?suffix|"
    r"domain[_-]?keyword|domain[_-]?regex|process[_-]?path|process[_-]?path[_-]?regex|"
    r"process[_-]?name)\s*[:=]\s*([^\s,;\"']+)"
)

SENSITIVE_EXACT_KEYS = {
    "address",
    "client_secret",
    "dns_servers",
    "domain",
    "domain_keyword",
    "domain_keywords",
    "domain_regex",
    "domain_regexes",
    "domain_suffix",
    "domain_suffixes",
    "domains",
    "group",
    "host",
    "hosts",
    "hostname",
    "ip_cidr",
    "name",
    "password",
    "path",
    "pbk",
    "private_key",
    "process_name",
    "process_names",
    "process_path",
    "process_paths",
    "process_path_regex",
    "process_path_regexes",
    "public_key",
    "raw_url",
    "secret",
    "server",
    "server_address",
    "server_name",
    "sid",
    "sni",
    "source_name",
    "source",
    "tags",
    "token",
    "url",
    "uuid",
}
SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "private_key",
    "public_key",
    "secret",
    "token",
)
SENSITIVE_KEY_SUFFIXES = ("_url", "-url")


def build_diagnostics_archive(
    target_path: str | Path,
    *,
    settings: Any | None = None,
    profiles: Any | None = None,
    subscriptions: Any | None = None,
    split_rules: Any | None = None,
    quality_stats: Any | None = None,
    smart_groups: Any | None = None,
    singbox: Any | None = None,
    log_lines: list[str] | None = None,
) -> Path:
    """Создает zip-архив диагностики без секретов и возвращает путь к нему."""
    target = Path(target_path)
    if target.suffix.lower() != ".zip":
        target = target.with_suffix(".zip")
    target.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    written: list[str] = []

    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        def write_text(name: str, text: str) -> None:
            archive.writestr(name, text)
            written.append(name)

        def write_json(name: str, payload: Any) -> None:
            write_text(
                name,
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n",
            )

        write_text(
            "README.txt",
            (
                "Razreshenie VPN Client diagnostics archive.\n"
                "All known server URLs, credentials, UUIDs, hostnames, IP addresses and local user paths are redacted.\n"
                "Review the archive before attaching it to a public bug report.\n"
            ),
        )
        write_json("system.json", collect_system_info(settings=settings, singbox=singbox))
        write_json(
            "state/settings.redacted.json",
            redact_diagnostics_data(_to_serializable(settings) if settings is not None else read_json(paths.settings_path(), {})),
        )
        write_json(
            "state/profiles.redacted.json",
            redact_diagnostics_data(_to_serializable(profiles) if profiles is not None else read_json(paths.profiles_path(), [])),
        )
        write_json(
            "state/subscriptions.redacted.json",
            redact_diagnostics_data(
                _to_serializable(subscriptions) if subscriptions is not None else read_json(paths.subscriptions_path(), [])
            ),
        )
        write_json(
            "state/rules.redacted.json",
            redact_diagnostics_data(_to_serializable(split_rules) if split_rules is not None else read_json(paths.rules_path(), {})),
        )
        write_json(
            "state/quality-stats.redacted.json",
            redact_diagnostics_data(
                _to_serializable(quality_stats) if quality_stats is not None else read_json(paths.quality_stats_path(), {})
            ),
        )
        write_json(
            "state/smart-groups.redacted.json",
            redact_diagnostics_data(_to_serializable(smart_groups) if smart_groups is not None else read_json(paths.smart_groups_path(), [])),
        )

        runtime_config = read_json(paths.runtime_config_path(), {}) if paths.runtime_config_path().exists() else {}
        write_json("configs/sing-box-runtime.redacted.json", redact_diagnostics_data(runtime_config))

        disk_log = _read_text(paths.log_file_path())
        write_text("logs/razreshenie.redacted.log", redact_diagnostics_text(disk_log))
        if log_lines is not None:
            write_text("logs/session-buffer.redacted.log", redact_diagnostics_text("\n".join(log_lines)))

        manifest = {
            "archive_version": DIAGNOSTICS_ARCHIVE_VERSION,
            "app": APP_NAME,
            "app_version": APP_VERSION,
            "generated_at": generated_at,
            "redaction": {
                "credentials": True,
                "server_addresses": True,
                "subscription_urls": True,
                "user_paths": True,
            },
            "files": sorted(written),
        }
        write_json("manifest.json", manifest)

    return target


def collect_system_info(*, settings: Any | None = None, singbox: Any | None = None) -> dict[str, Any]:
    """Собирает системную сводку без сетевых адресов и MAC."""
    data: dict[str, Any] = {
        "app": {
            "name": APP_NAME,
            "version": APP_VERSION,
            "repository": APP_REPOSITORY,
        },
        "python": {
            "version": sys.version.split()[0],
            "executable": _safe_path(sys.executable),
        },
        "os": {
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "platform": platform.platform(),
        },
        "paths": {
            "data_dir": _safe_path(paths.data_dir()),
            "log_file": _safe_path(paths.log_file_path()),
            "runtime_config": _safe_path(paths.runtime_config_path()),
        },
        "runtime": {
            "pid": os.getpid(),
            "cwd": _safe_path(Path.cwd()),
        },
    }
    if settings is not None:
        data["settings_summary"] = _settings_summary(settings)
    if singbox is not None:
        data["sing_box"] = _singbox_summary(singbox)
    else:
        data["sing_box"] = {"available": paths.runtime_config_path().exists()}
    if psutil is not None:
        try:
            data["hardware"] = {
                "cpu_count": psutil.cpu_count(),
                "memory_total_mb": int(psutil.virtual_memory().total / (1024 * 1024)),
            }
        except (OSError, RuntimeError):
            data["hardware"] = {"error": "unavailable"}
    return data


def redact_diagnostics_data(value: Any) -> Any:
    """Редактирует JSON-подобные данные перед упаковкой в диагностику."""
    return _redact_json_value(_to_serializable(value), key="")


def redact_diagnostics_text(text: str) -> str:
    """Редактирует логи и текстовые диагностические данные."""
    value = _redact_home_path(str(text or ""))
    value = WINDOWS_PATH_RE.sub(lambda match: _redacted("path", match.group(0)), value)
    value = URI_RE.sub(lambda match: _redacted("uri", match.group(0)), value)
    value = HTTP_URL_RE.sub(lambda match: _redacted("url", match.group(0)), value)
    value = SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}={_redacted(match.group(1), match.group(2))}",
        value,
    )
    value = UUID_RE.sub(lambda match: _redacted("uuid", match.group(0)), value)
    value = HEX_ID_RE.sub(lambda match: _redacted("id", match.group(0)), value)
    value = IPV4_RE.sub(lambda match: _redacted("ip", match.group(0)), value)
    value = IPV6_CANDIDATE_RE.sub(_redact_ipv6_match, value)
    value = DOMAIN_RE.sub(lambda match: _redacted("domain", match.group(0)), value)
    return value


def _redact_json_value(value: Any, *, key: str) -> Any:
    normalized_key = _normalize_key(key)
    if _is_sensitive_key(normalized_key):
        return _redact_sensitive_value(normalized_key or "value", value)
    if isinstance(value, dict):
        return {
            str(item_key): _redact_json_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [_redact_json_value(item, key=key) for item in value]
    if isinstance(value, str):
        return redact_diagnostics_text(value)
    return value


def _redact_sensitive_value(label: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {
            "_redacted": True,
            "type": "object",
            "keys": sorted(str(key) for key in value.keys()),
            "hash": _hash_value(value),
        }
    if isinstance(value, (list, tuple)):
        return [_redacted(label, item) for item in value]
    if value in (None, ""):
        return value
    return _redacted(label, value)


def _is_sensitive_key(key: str) -> bool:
    if key in SENSITIVE_EXACT_KEYS:
        return True
    if key.endswith(SENSITIVE_KEY_SUFFIXES):
        return True
    return any(fragment in key for fragment in SENSITIVE_KEY_FRAGMENTS)


def _normalize_key(key: str) -> str:
    return str(key or "").strip().lower().replace("-", "_")


def _redacted(label: str, value: Any) -> str:
    return f"[redacted:{_normalize_key(label) or 'value'}:{_hash_value(value)}]"


def _redact_ipv6_match(match: re.Match[str]) -> str:
    candidate = match.group(0)
    token = candidate.strip("[]")
    try:
        parsed = ip_address(token)
    except ValueError:
        return candidate
    if parsed.version != 6:
        return candidate
    return _redacted("ip", candidate)


def _hash_value(value: Any) -> str:
    payload = json.dumps(_to_serializable(value), ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:10]


def _to_serializable(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(item) for item in value]
    if hasattr(value, "to_dict"):
        return _to_serializable(value.to_dict())
    if is_dataclass(value):
        return _to_serializable(asdict(value))
    return str(value)


def _settings_summary(settings: Any) -> dict[str, Any]:
    raw = _to_serializable(settings)
    if not isinstance(raw, dict):
        return {}
    keys = (
        "mode",
        "mixed_port",
        "tun_interface_name",
        "tun_mtu",
        "enable_ipv6",
        "dns_strategy",
        "kill_switch",
        "firewall_kill_switch",
        "enable_system_proxy_guard",
        "background_health_check_enabled",
        "self_healing_enabled",
        "auto_connect",
        "auto_update_subscriptions",
        "log_level",
    )
    return {key: raw.get(key) for key in keys if key in raw}


def _singbox_summary(singbox: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, getter in (
        ("version", lambda: singbox.version()),
        ("running", lambda: bool(singbox.is_running())),
        ("connection_state", lambda: str(getattr(singbox, "connection_state", "unknown"))),
    ):
        try:
            summary[key] = getter()
        except Exception as exc:
            summary[key] = f"unavailable: {exc}"
    try:
        executable = getattr(singbox, "executable_path", None)
        summary["executable"] = _safe_path(executable) if executable else None
    except Exception:
        summary["executable"] = None
    return summary


def _safe_path(path: str | Path | None) -> str | None:
    if path is None:
        return None
    return _redact_home_path(str(path))


def _redact_home_path(text: str) -> str:
    home = str(Path.home())
    if not home:
        return text
    return text.replace(home, "~").replace(home.replace("\\", "/"), "~")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return ""
