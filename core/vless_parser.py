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

"""Импорт и разбор VLESS URI."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlparse
from uuid import UUID

from models.profile import VlessProfile


class VlessParseError(ValueError):
    """Ошибка пользовательского VLESS-ключа."""


def _validate_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise VlessParseError("Некорректный UUID в VLESS-ключе") from exc


def _decode_karing_component(value: str) -> str:
    """Повторяет Karing-style decode: URI component decode, без замены '+' на пробел."""
    name = unquote(value).strip()
    return " ".join(name.split())


def _parse_query_karing(query: str) -> dict[str, str]:
    """Разбирает query без unquote_plus, чтобы '+' оставался настоящим плюсом."""
    params: dict[str, str] = {}
    for part in query.replace(";", "&").split("&"):
        if not part:
            continue
        key, separator, value = part.partition("=")
        decoded_key = _decode_karing_component(key)
        if not decoded_key:
            continue
        params[decoded_key] = _decode_karing_component(value if separator else "")
    return params


def _case_get(params: dict[str, str], *names: str) -> str | None:
    lower_map = {key.lower(): value for key, value in params.items()}
    for name in names:
        value = lower_map.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def get_karing_server_name(uri: str) -> str:
    """Возвращает имя сервера Karing-style: fragment -> remarks/name/ps/tag -> host."""
    parsed = urlparse(uri.strip())
    params = _parse_query_karing(parsed.query)

    remarks = ""
    if parsed.fragment:
        remarks = parsed.fragment
    else:
        remarks = _case_get(params, "remarks", "name", "ps", "tag") or ""

    if remarks:
        decoded = _decode_karing_component(remarks)
        if decoded:
            return decoded
    return parsed.hostname or ""


def parse_vless_uri(uri: str, subscription_id: str | None = None) -> VlessProfile:
    raw = uri.strip()
    if not raw.startswith("vless://"):
        raise VlessParseError("Ключ должен начинаться с vless://")

    parsed = urlparse(raw)
    if parsed.scheme != "vless":
        raise VlessParseError("Поддерживается только схема vless://")
    if not parsed.username:
        raise VlessParseError("В VLESS-ключе отсутствует UUID")
    if not parsed.hostname:
        raise VlessParseError("В VLESS-ключе отсутствует адрес сервера")

    params = _parse_query_karing(parsed.query)

    try:
        port = int(parsed.port or 443)
    except ValueError as exc:
        raise VlessParseError("Некорректный порт в VLESS-ключе") from exc

    name = get_karing_server_name(raw) or parsed.hostname
    return VlessProfile(
        name=name or parsed.hostname,
        address=parsed.hostname,
        port=port,
        uuid=_validate_uuid(unquote(parsed.username)),
        raw_url=raw,
        params=params,
        subscription_id=subscription_id,
    )


def parse_vless_outbound(outbound: dict[str, Any], subscription_id: str | None = None) -> VlessProfile:
    """Создает профиль из sing-box/Clash JSON outbound с типом vless."""
    if str(outbound.get("type") or "").lower() != "vless":
        raise VlessParseError("JSON-объект не является VLESS outbound")

    address = _string_value(outbound, "server", "address")
    if not address:
        raise VlessParseError("В JSON VLESS отсутствует адрес сервера")

    uuid = _string_value(outbound, "uuid", "id", "password")
    if not uuid:
        raise VlessParseError("В JSON VLESS отсутствует UUID")

    try:
        port = int(outbound.get("server_port") or outbound.get("port") or 443)
    except (TypeError, ValueError) as exc:
        raise VlessParseError("Некорректный порт в JSON VLESS") from exc

    params: dict[str, str] = {}
    _copy_string_params(outbound, params, ("flow",), "flow")
    _copy_string_params(outbound, params, ("packet_encoding", "packetEncoding"), "packet_encoding")

    _merge_tls_params(outbound, params)
    _merge_transport_params(outbound, params)
    _merge_multiplex_params(outbound, params)

    name = _string_value(outbound, "tag", "name", "remarks", "ps") or f"{address}:{port}"
    return VlessProfile(
        name=_decode_karing_component(name),
        address=address,
        port=port,
        uuid=_validate_uuid(uuid),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _string_value(data: dict[str, Any], *names: str) -> str:
    lower_map = {str(key).lower(): value for key, value in data.items()}
    for name in names:
        value = lower_map.get(name.lower())
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(str(item).strip() for item in value if str(item).strip())
        text = str(value).strip()
        if text:
            return text
    return ""


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _set_param(params: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, (list, tuple)):
        text = ",".join(str(item).strip() for item in value if str(item).strip())
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value).strip()
    if text:
        params[key] = text


def _copy_string_params(source: dict[str, Any], params: dict[str, str], names: tuple[str, ...], target: str) -> None:
    value = _string_value(source, *names)
    if value:
        params[target] = value


def _merge_tls_params(outbound: dict[str, Any], params: dict[str, str]) -> None:
    tls = outbound.get("tls")
    security = _string_value(outbound, "security")
    if isinstance(tls, dict):
        if tls.get("enabled", True):
            reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
            params["security"] = "reality" if reality and reality.get("enabled", True) else "tls"
            _copy_string_params(tls, params, ("server_name", "servername", "sni"), "sni")
            _set_param(params, "alpn", tls.get("alpn"))
            if _bool_value(tls.get("insecure")):
                params["allowInsecure"] = "true"
            utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
            _copy_string_params(utls, params, ("fingerprint", "fp"), "fp")
            _copy_string_params(reality, params, ("public_key", "publicKey", "pbk"), "pbk")
            _copy_string_params(reality, params, ("short_id", "shortId", "sid"), "sid")
            _copy_string_params(reality, params, ("spider_x", "spiderX", "spx"), "spx")
        return

    if _bool_value(tls) or security.lower() in {"tls", "reality"}:
        params["security"] = security.lower() if security.lower() in {"tls", "reality"} else "tls"
        _copy_string_params(outbound, params, ("server_name", "servername", "sni"), "sni")
        _set_param(params, "alpn", outbound.get("alpn"))
        _copy_string_params(outbound, params, ("client-fingerprint", "client_fingerprint", "fingerprint", "fp"), "fp")
        if _bool_value(outbound.get("skip-cert-verify")) or _bool_value(outbound.get("allowInsecure")):
            params["allowInsecure"] = "true"

    reality_opts = outbound.get("reality-opts") if isinstance(outbound.get("reality-opts"), dict) else {}
    if reality_opts:
        params["security"] = "reality"
        _copy_string_params(reality_opts, params, ("public-key", "public_key", "pbk"), "pbk")
        _copy_string_params(reality_opts, params, ("short-id", "short_id", "sid"), "sid")


def _merge_transport_params(outbound: dict[str, Any], params: dict[str, str]) -> None:
    transport = outbound.get("transport")
    if isinstance(transport, dict):
        _copy_string_params(transport, params, ("type", "network"), "type")
        _copy_string_params(transport, params, ("path",), "path")
        _copy_string_params(transport, params, ("host", "authority"), "host")
        _copy_string_params(transport, params, ("service_name", "serviceName"), "serviceName")
        headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
        _copy_string_params(headers, params, ("Host", "host"), "host")
        return

    network = _string_value(outbound, "network")
    if network:
        params["type"] = network
    ws_opts = outbound.get("ws-opts") if isinstance(outbound.get("ws-opts"), dict) else {}
    if ws_opts:
        params.setdefault("type", "ws")
        _copy_string_params(ws_opts, params, ("path",), "path")
        headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
        _copy_string_params(headers, params, ("Host", "host"), "host")
    grpc_opts = outbound.get("grpc-opts") if isinstance(outbound.get("grpc-opts"), dict) else {}
    if grpc_opts:
        params.setdefault("type", "grpc")
        _copy_string_params(grpc_opts, params, ("grpc-service-name", "service_name", "serviceName"), "serviceName")


def _merge_multiplex_params(outbound: dict[str, Any], params: dict[str, str]) -> None:
    multiplex = outbound.get("multiplex") if isinstance(outbound.get("multiplex"), dict) else {}
    if not multiplex or not _bool_value(multiplex.get("enabled")):
        return
    params["mux"] = "true"
    _copy_string_params(multiplex, params, ("protocol",), "muxProtocol")
    _copy_string_params(multiplex, params, ("max_connections", "maxConnections"), "muxMaxConnections")
