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

"""Импорт URI и JSON outbounds для поддерживаемых sing-box протоколов."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any
from urllib.parse import unquote, urlparse
from uuid import UUID

from models.profile import ServerProfile


class ServerParseError(ValueError):
    """Ошибка пользовательского ключа или JSON outbound."""


SUPPORTED_OUTBOUND_TYPES = {
    "vless",
    "trojan",
    "vmess",
    "hysteria2",
    "tuic",
    "shadowsocks",
    "wireguard",
}
SUPPORTED_URI_SCHEMES = {
    "vless",
    "trojan",
    "vmess",
    "hysteria2",
    "hy2",
    "tuic",
    "ss",
    "wireguard",
    "wg",
}
URI_PROTOCOL_ALIASES = {
    "hy2": "hysteria2",
    "ss": "shadowsocks",
    "wg": "wireguard",
}


def normalize_protocol(value: str | None) -> str:
    protocol = str(value or "").strip().lower()
    return URI_PROTOCOL_ALIASES.get(protocol, protocol)


def is_supported_scheme(value: str | None) -> bool:
    return str(value or "").strip().lower() in SUPPORTED_URI_SCHEMES


def is_supported_outbound_type(value: str | None) -> bool:
    return normalize_protocol(value) in SUPPORTED_OUTBOUND_TYPES


def _validate_uuid(value: str, protocol: str = "профиле") -> str:
    try:
        return str(UUID(str(value).strip()))
    except (ValueError, AttributeError) as exc:
        raise ServerParseError(f"Некорректный UUID в {protocol}") from exc


def _decode_karing_component(value: str) -> str:
    """Повторяет Karing-style decode: URI component decode, без замены '+' на пробел."""
    name = unquote(value or "").strip()
    return " ".join(name.split())


def _parse_query_karing(query: str) -> dict[str, str]:
    """Разбирает query без unquote_plus, чтобы '+' оставался настоящим плюсом."""
    params: dict[str, str] = {}
    for part in str(query or "").replace(";", "&").split("&"):
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


def _parsed_port(parsed, default: int) -> int:
    try:
        port = parsed.port
    except ValueError as exc:
        raise ServerParseError("Некорректный порт в ключе") from exc
    return int(port or default)


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


def _int_value(data: dict[str, Any], default: int, *names: str) -> int:
    value = _string_value(data, *names)
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ServerParseError("Некорректный порт в JSON outbound") from exc


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _copy_string_params(source: dict[str, Any], params: dict[str, str], names: tuple[str, ...], target: str) -> None:
    value = _string_value(source, *names)
    if value:
        params[target] = value


def _decode_base64_loose(value: str) -> str:
    text = "".join(str(value or "").strip().split())
    text = text.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.b64decode((text + padding).encode("ascii"), validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ServerParseError("Не удалось декодировать base64 в ключе") from exc


def _decode_base64_optional(value: str) -> str:
    try:
        return _decode_base64_loose(value)
    except ServerParseError:
        return _decode_karing_component(value)


def parse_server_uri(uri: str, subscription_id: str | None = None) -> ServerProfile:
    raw = uri.strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    protocol = normalize_protocol(scheme)
    if scheme not in SUPPORTED_URI_SCHEMES:
        raise ServerParseError("Неподдерживаемый тип ссылки сервера")

    if protocol == "vless":
        return parse_vless_uri(raw, subscription_id)
    if protocol == "trojan":
        return _parse_password_uri(raw, "trojan", subscription_id, default_port=443)
    if protocol == "hysteria2":
        return _parse_password_uri(raw, "hysteria2", subscription_id, default_port=443)
    if protocol == "tuic":
        return _parse_tuic_uri(raw, subscription_id)
    if protocol == "vmess":
        return _parse_vmess_uri(raw, subscription_id)
    if protocol == "shadowsocks":
        return _parse_shadowsocks_uri(raw, subscription_id)
    if protocol == "wireguard":
        return _parse_wireguard_uri(raw, subscription_id)
    raise ServerParseError("Неподдерживаемый тип ссылки сервера")


def parse_vless_uri(uri: str, subscription_id: str | None = None) -> ServerProfile:
    raw = uri.strip()
    if not raw.startswith("vless://"):
        raise ServerParseError("Ключ должен начинаться с vless://")

    parsed = urlparse(raw)
    if parsed.scheme != "vless":
        raise ServerParseError("Поддерживается только схема vless://")
    if not parsed.username:
        raise ServerParseError("В VLESS-ключе отсутствует UUID")
    if not parsed.hostname:
        raise ServerParseError("В VLESS-ключе отсутствует адрес сервера")

    params = _parse_query_karing(parsed.query)
    port = _parsed_port(parsed, 443)
    name = get_karing_server_name(raw) or parsed.hostname
    return ServerProfile(
        name=name or parsed.hostname,
        protocol="vless",
        address=parsed.hostname,
        port=port,
        uuid=_validate_uuid(unquote(parsed.username), "VLESS-ключе"),
        raw_url=raw,
        params=params,
        subscription_id=subscription_id,
    )


def _parse_password_uri(
    uri: str,
    protocol: str,
    subscription_id: str | None,
    *,
    default_port: int,
) -> ServerProfile:
    parsed = urlparse(uri.strip())
    if not parsed.username:
        raise ServerParseError(f"В {protocol.upper()}-ключе отсутствует пароль")
    if not parsed.hostname:
        raise ServerParseError(f"В {protocol.upper()}-ключе отсутствует адрес сервера")
    params = _parse_query_karing(parsed.query)
    params["password"] = unquote(parsed.username)
    name = get_karing_server_name(uri) or parsed.hostname
    return ServerProfile(
        name=name or parsed.hostname,
        protocol=protocol,
        address=parsed.hostname,
        port=_parsed_port(parsed, default_port),
        raw_url=uri.strip(),
        params=params,
        subscription_id=subscription_id,
    )


def _parse_tuic_uri(uri: str, subscription_id: str | None) -> ServerProfile:
    parsed = urlparse(uri.strip())
    if not parsed.username or not parsed.password:
        raise ServerParseError("В TUIC-ключе должны быть UUID и пароль")
    if not parsed.hostname:
        raise ServerParseError("В TUIC-ключе отсутствует адрес сервера")
    params = _parse_query_karing(parsed.query)
    params["password"] = unquote(parsed.password)
    name = get_karing_server_name(uri) or parsed.hostname
    return ServerProfile(
        name=name or parsed.hostname,
        protocol="tuic",
        address=parsed.hostname,
        port=_parsed_port(parsed, 443),
        uuid=_validate_uuid(unquote(parsed.username), "TUIC-ключе"),
        raw_url=uri.strip(),
        params=params,
        subscription_id=subscription_id,
    )


def _parse_vmess_uri(uri: str, subscription_id: str | None) -> ServerProfile:
    raw = uri.strip()
    payload = raw.removeprefix("vmess://")
    payload = payload.split("#", 1)[0].split("?", 1)[0]
    try:
        data = json.loads(_decode_base64_loose(payload))
    except (ServerParseError, json.JSONDecodeError):
        parsed = urlparse(raw)
        if not parsed.username or not parsed.hostname:
            raise ServerParseError("VMess-ключ должен быть base64 JSON или URI с UUID")
        params = _parse_query_karing(parsed.query)
        uuid = _validate_uuid(unquote(parsed.username), "VMess-ключе")
        name = get_karing_server_name(raw) or parsed.hostname
        cipher = _case_get(params, "scy", "cipher")
        if not cipher:
            candidate = _case_get(params, "security")
            if candidate and candidate.lower() not in {"tls", "reality", "none"}:
                cipher = candidate
        params.setdefault("vmess_security", cipher or "auto")
        return ServerProfile(
            name=name or parsed.hostname,
            protocol="vmess",
            address=parsed.hostname,
            port=_parsed_port(parsed, 443),
            uuid=uuid,
            raw_url=raw,
            params=params,
            subscription_id=subscription_id,
        )
    if not isinstance(data, dict):
        raise ServerParseError("VMess base64 JSON должен быть объектом")

    address = _string_value(data, "add", "server", "address")
    if not address:
        raise ServerParseError("В VMess-ключе отсутствует адрес сервера")
    uuid = _string_value(data, "id", "uuid")
    if not uuid:
        raise ServerParseError("В VMess-ключе отсутствует UUID")

    params: dict[str, str] = {}
    _copy_string_params(data, params, ("scy", "security"), "vmess_security")
    _copy_string_params(data, params, ("aid", "alter_id", "alterId"), "alter_id")
    _copy_string_params(data, params, ("net", "network"), "type")
    _copy_string_params(data, params, ("type",), "headerType")
    _copy_string_params(data, params, ("host",), "host")
    _copy_string_params(data, params, ("path",), "path")
    _copy_string_params(data, params, ("sni", "server_name", "serverName"), "sni")
    _copy_string_params(data, params, ("alpn",), "alpn")
    _copy_string_params(data, params, ("fp", "fingerprint"), "fp")
    tls_value = _string_value(data, "tls")
    if tls_value and tls_value.lower() not in {"none", "0", "false"}:
        params["security"] = "tls"
    name = _string_value(data, "ps", "name", "remarks", "tag") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="vmess",
        address=address,
        port=_int_value(data, 443, "port", "server_port"),
        uuid=_validate_uuid(uuid, "VMess-ключе"),
        raw_url=raw,
        params=params,
        subscription_id=subscription_id,
    )


def _parse_shadowsocks_uri(uri: str, subscription_id: str | None) -> ServerProfile:
    raw = uri.strip()
    parsed = urlparse(raw)
    params = _parse_query_karing(parsed.query)
    method = ""
    password = ""
    host = parsed.hostname or ""
    port = _parsed_port(parsed, 8388) if host else 8388

    if host:
        if parsed.username and parsed.password is not None:
            method = unquote(parsed.username)
            password = unquote(parsed.password)
        elif parsed.username:
            method, password = _split_ss_userinfo(_decode_base64_optional(parsed.username))
    else:
        encoded = (parsed.netloc + parsed.path).lstrip("/")
        decoded = _decode_base64_loose(encoded)
        userinfo, separator, endpoint = decoded.rpartition("@")
        if not separator:
            raise ServerParseError("Shadowsocks-ключ должен содержать method:password@host:port")
        method, password = _split_ss_userinfo(userinfo)
        endpoint_parsed = urlparse(f"//{endpoint}")
        host = endpoint_parsed.hostname or ""
        port = _parsed_port(endpoint_parsed, 8388)

    if not method or not password:
        raise ServerParseError("В Shadowsocks-ключе отсутствует method или password")
    if not host:
        raise ServerParseError("В Shadowsocks-ключе отсутствует адрес сервера")

    params["method"] = method
    params["password"] = password
    name = get_karing_server_name(raw) or host
    return ServerProfile(
        name=name or host,
        protocol="shadowsocks",
        address=host,
        port=port,
        raw_url=raw,
        params=params,
        subscription_id=subscription_id,
    )


def _split_ss_userinfo(value: str) -> tuple[str, str]:
    method, separator, password = value.partition(":")
    if not separator:
        raise ServerParseError("Shadowsocks userinfo должен быть method:password")
    return _decode_karing_component(method), unquote(password)


def _parse_wireguard_uri(uri: str, subscription_id: str | None) -> ServerProfile:
    parsed = urlparse(uri.strip())
    if not parsed.username:
        raise ServerParseError("В WireGuard URI отсутствует private_key")
    if not parsed.hostname:
        raise ServerParseError("В WireGuard URI отсутствует peer endpoint")
    params = _parse_query_karing(parsed.query)
    params["private_key"] = unquote(parsed.username)
    name = get_karing_server_name(uri) or parsed.hostname
    return ServerProfile(
        name=name or parsed.hostname,
        protocol="wireguard",
        address=parsed.hostname,
        port=_parsed_port(parsed, 51820),
        raw_url=uri.strip(),
        params=params,
        subscription_id=subscription_id,
    )


def parse_outbound(outbound: dict[str, Any], subscription_id: str | None = None) -> ServerProfile:
    protocol = normalize_protocol(_string_value(outbound, "type"))
    if protocol not in SUPPORTED_OUTBOUND_TYPES:
        raise ServerParseError("JSON-объект не является поддерживаемым outbound")
    if protocol == "vless":
        return parse_vless_outbound(outbound, subscription_id)
    if protocol == "trojan":
        return _parse_password_outbound(outbound, "trojan", subscription_id, default_port=443)
    if protocol == "hysteria2":
        return _parse_password_outbound(outbound, "hysteria2", subscription_id, default_port=443)
    if protocol == "tuic":
        return _parse_tuic_outbound(outbound, subscription_id)
    if protocol == "vmess":
        return _parse_vmess_outbound(outbound, subscription_id)
    if protocol == "shadowsocks":
        return _parse_shadowsocks_outbound(outbound, subscription_id)
    if protocol == "wireguard":
        return _parse_wireguard_outbound(outbound, subscription_id)
    raise ServerParseError("JSON-объект не является поддерживаемым outbound")


def parse_vless_outbound(outbound: dict[str, Any], subscription_id: str | None = None) -> ServerProfile:
    """Создает профиль из sing-box/Clash JSON outbound с типом vless."""
    if normalize_protocol(outbound.get("type")) != "vless":
        raise ServerParseError("JSON-объект не является VLESS outbound")

    address = _string_value(outbound, "server", "address")
    if not address:
        raise ServerParseError("В JSON VLESS отсутствует адрес сервера")

    uuid = _string_value(outbound, "uuid", "id", "password")
    if not uuid:
        raise ServerParseError("В JSON VLESS отсутствует UUID")

    params: dict[str, str] = {}
    _copy_string_params(outbound, params, ("flow",), "flow")
    _copy_string_params(outbound, params, ("packet_encoding", "packetEncoding"), "packet_encoding")
    _merge_tls_params(outbound, params)
    _merge_transport_params(outbound, params)
    _merge_multiplex_params(outbound, params)

    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="vless",
        address=address,
        port=_int_value(outbound, 443, "server_port", "port"),
        uuid=_validate_uuid(uuid, "JSON VLESS"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _parse_password_outbound(
    outbound: dict[str, Any],
    protocol: str,
    subscription_id: str | None,
    *,
    default_port: int,
) -> ServerProfile:
    address = _string_value(outbound, "server", "address")
    password = _string_value(outbound, "password")
    if not address:
        raise ServerParseError(f"В JSON {protocol} отсутствует адрес сервера")
    if not password:
        raise ServerParseError(f"В JSON {protocol} отсутствует password")
    params: dict[str, str] = {"password": password}
    _copy_common_protocol_params(outbound, params)
    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol=protocol,
        address=address,
        port=_int_value(outbound, default_port, "server_port", "port"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _parse_tuic_outbound(outbound: dict[str, Any], subscription_id: str | None) -> ServerProfile:
    address = _string_value(outbound, "server", "address")
    uuid = _string_value(outbound, "uuid", "id")
    password = _string_value(outbound, "password")
    if not address:
        raise ServerParseError("В JSON TUIC отсутствует адрес сервера")
    if not uuid or not password:
        raise ServerParseError("В JSON TUIC отсутствует UUID или password")
    params: dict[str, str] = {"password": password}
    _copy_common_protocol_params(outbound, params)
    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="tuic",
        address=address,
        port=_int_value(outbound, 443, "server_port", "port"),
        uuid=_validate_uuid(uuid, "JSON TUIC"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _parse_vmess_outbound(outbound: dict[str, Any], subscription_id: str | None) -> ServerProfile:
    address = _string_value(outbound, "server", "address")
    uuid = _string_value(outbound, "uuid", "id", "password")
    if not address:
        raise ServerParseError("В JSON VMess отсутствует адрес сервера")
    if not uuid:
        raise ServerParseError("В JSON VMess отсутствует UUID")
    params: dict[str, str] = {}
    _copy_string_params(outbound, params, ("security",), "vmess_security")
    _copy_string_params(outbound, params, ("alter_id", "alterId", "aid"), "alter_id")
    _copy_common_protocol_params(outbound, params)
    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="vmess",
        address=address,
        port=_int_value(outbound, 443, "server_port", "port"),
        uuid=_validate_uuid(uuid, "JSON VMess"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _parse_shadowsocks_outbound(outbound: dict[str, Any], subscription_id: str | None) -> ServerProfile:
    address = _string_value(outbound, "server", "address")
    method = _string_value(outbound, "method", "cipher")
    password = _string_value(outbound, "password")
    if not address:
        raise ServerParseError("В JSON Shadowsocks отсутствует адрес сервера")
    if not method or not password:
        raise ServerParseError("В JSON Shadowsocks отсутствует method или password")
    params: dict[str, str] = {"method": method, "password": password}
    _copy_string_params(outbound, params, ("plugin",), "plugin")
    _copy_string_params(outbound, params, ("plugin_opts", "plugin-opts"), "plugin_opts")
    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="shadowsocks",
        address=address,
        port=_int_value(outbound, 8388, "server_port", "port"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _parse_wireguard_outbound(outbound: dict[str, Any], subscription_id: str | None) -> ServerProfile:
    address = _string_value(outbound, "server", "address")
    if not address:
        raise ServerParseError("В JSON WireGuard отсутствует peer endpoint")
    params: dict[str, str] = {}
    for source, target in (
        ("private_key", "private_key"),
        ("peer_public_key", "peer_public_key"),
        ("pre_shared_key", "pre_shared_key"),
        ("local_address", "local_address"),
        ("reserved", "reserved"),
        ("mtu", "mtu"),
        ("workers", "workers"),
    ):
        _copy_string_params(outbound, params, (source,), target)
    if not params.get("private_key") or not params.get("peer_public_key"):
        raise ServerParseError("В JSON WireGuard отсутствует private_key или peer_public_key")
    name = _string_value(outbound, "tag", "name", "remarks", "ps") or address
    return ServerProfile(
        name=_decode_karing_component(name),
        protocol="wireguard",
        address=address,
        port=_int_value(outbound, 51820, "server_port", "port"),
        raw_url="",
        params=params,
        subscription_id=subscription_id,
    )


def _copy_common_protocol_params(outbound: dict[str, Any], params: dict[str, str]) -> None:
    for name in (
        "congestion_control",
        "udp_relay_mode",
        "zero_rtt_handshake",
        "heartbeat",
        "up_mbps",
        "down_mbps",
    ):
        _copy_string_params(outbound, params, (name,), name)
    obfs = outbound.get("obfs") if isinstance(outbound.get("obfs"), dict) else {}
    _copy_string_params(obfs, params, ("type",), "obfs")
    _copy_string_params(obfs, params, ("password",), "obfs-password")
    _merge_tls_params(outbound, params)
    _merge_transport_params(outbound, params)
    _merge_multiplex_params(outbound, params)


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
