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

"""Распознавание популярных форматов подписок поверх URI и JSON outbounds."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

import yaml

from core.server_parser import (
    SUPPORTED_OUTBOUND_TYPES,
    SUPPORTED_URI_SCHEMES,
    ServerParseError,
    is_supported_outbound_type,
    normalize_protocol,
    parse_outbound,
    parse_server_uri,
)
from models.profile import ServerProfile


SERVICE_OUTBOUND_TYPES = {
    "block",
    "direct",
    "dns",
    "selector",
    "urltest",
    "url-test",
    "loadbalance",
    "load-balance",
}
NODE_LIST_KEYS = ("proxies", "profiles", "servers", "nodes", "configs", "items")
GROUP_LIST_KEYS = ("proxy-groups", "proxy_groups", "groups")
GROUP_MEMBER_KEYS = ("proxies", "outbounds", "use", "profiles", "servers", "nodes")


@dataclass(slots=True)
class ParsedSubscription:
    profiles: list[ServerProfile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    format_name: str = "unknown"


def parse_subscription_payload(text: str, subscription_id: str | None = None) -> ParsedSubscription:
    structured = _load_structured_payload(text)
    if isinstance(structured, dict):
        if _looks_like_clash(structured):
            return _parse_clash_payload(structured, subscription_id)
        if _looks_like_sing_box(structured):
            return _parse_sing_box_payload(structured, subscription_id)
        return _parse_generic_structured_payload(structured, subscription_id, "json")
    if isinstance(structured, list):
        return _parse_generic_structured_payload(structured, subscription_id, "json")
    return ParsedSubscription(format_name="text")


def normalize_server_name(value: str, *, fallback: str = "", group: str | None = None, protocol: str | None = None) -> str:
    text = unquote(str(value or "")).replace("\u200b", "")
    text = re.sub(r"\s+", " ", text).strip()
    text = text.strip(" \t\r\n|,;[](){}")
    if group:
        clean_group = re.escape(group.strip())
        text = re.sub(rf"^(?:{clean_group})\s*(?:[-|:>/\\]+)\s*", "", text, flags=re.IGNORECASE).strip()
    if protocol:
        clean_protocol = re.escape(protocol.strip())
        text = re.sub(rf"^(?:{clean_protocol})\s*(?:[-|:>/\\]+)\s*", "", text, flags=re.IGNORECASE).strip()
    return text or fallback or "Сервер"


def _load_structured_payload(text: str) -> Any:
    raw = text.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        pass
    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    return loaded if isinstance(loaded, (dict, list)) else None


def _looks_like_clash(payload: dict[str, Any]) -> bool:
    return isinstance(payload.get("proxies"), list) or isinstance(payload.get("proxy-groups"), list)


def _looks_like_sing_box(payload: dict[str, Any]) -> bool:
    return isinstance(payload.get("outbounds"), list) or isinstance(payload.get("inbounds"), list)


def _parse_clash_payload(payload: dict[str, Any], subscription_id: str | None) -> ParsedSubscription:
    result = ParsedSubscription(format_name="clash")
    group_map = _clash_group_map(payload)
    for proxy in payload.get("proxies") or []:
        if not isinstance(proxy, dict):
            continue
        name = _string_value(proxy, "name", "tag")
        outbound = _adapt_clash_proxy(proxy)
        if outbound is None:
            continue
        groups = group_map.get(name, [])
        profile = _parse_outbound_with_metadata(
            outbound,
            subscription_id,
            group=groups[0] if groups else None,
            tags=groups,
            source_name=name,
            errors=result.errors,
        )
        if profile:
            result.profiles.append(profile)
    _append_generic_embedded_nodes(payload, result, subscription_id, excluded_ids={id(item) for item in payload.get("proxies") or []})
    return result


def _parse_sing_box_payload(payload: dict[str, Any], subscription_id: str | None) -> ParsedSubscription:
    result = ParsedSubscription(format_name="sing-box")
    group_map = _sing_box_group_map(payload)
    for outbound in payload.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        outbound_type = normalize_protocol(outbound.get("type"))
        if outbound_type in SERVICE_OUTBOUND_TYPES:
            continue
        if not is_supported_outbound_type(outbound_type):
            continue
        tag = _string_value(outbound, "tag", "name")
        groups = group_map.get(tag, [])
        profile = _parse_outbound_with_metadata(
            outbound,
            subscription_id,
            group=groups[0] if groups else None,
            tags=groups,
            source_name=tag,
            errors=result.errors,
        )
        if profile:
            result.profiles.append(profile)
    return result


def _parse_generic_structured_payload(value: Any, subscription_id: str | None, format_name: str) -> ParsedSubscription:
    result = ParsedSubscription(format_name=format_name)
    _walk_generic(value, result, subscription_id, group=None, seen=set())
    return result


def _append_generic_embedded_nodes(
    payload: dict[str, Any],
    result: ParsedSubscription,
    subscription_id: str | None,
    excluded_ids: set[int],
) -> None:
    for key in ("profiles", "servers", "nodes", "configs"):
        value = payload.get(key)
        if value is None:
            continue
        _walk_generic(value, result, subscription_id, group=None, seen=set(excluded_ids))


def _walk_generic(
    value: Any,
    result: ParsedSubscription,
    subscription_id: str | None,
    *,
    group: str | None,
    seen: set[int],
) -> None:
    if isinstance(value, str):
        if _contains_supported_uri(value):
            for link in _extract_links(value):
                _append_uri(link, result, subscription_id, group=group, tags=[group] if group else [])
        return

    if isinstance(value, list):
        for item in value:
            _walk_generic(item, result, subscription_id, group=group, seen=seen)
        return

    if not isinstance(value, dict):
        return
    if id(value) in seen:
        return
    seen.add(id(value))

    group_name = _string_value(value, "group", "group_name", "groupName", "subscription", "subscription_name")
    container_name = _string_value(value, "name", "tag", "remarks", "ps")
    next_group = group or group_name

    if is_supported_outbound_type(_node_protocol(value)):
        profile = _parse_outbound_with_metadata(
            _adapt_generic_proxy(value),
            subscription_id,
            group=next_group,
            tags=[item for item in (next_group, container_name if container_name != next_group else "") if item],
            source_name=container_name,
            errors=result.errors,
        )
        if profile:
            result.profiles.append(profile)
        return

    if _contains_supported_uri(_string_value(value, "url", "link", "uri", "share", "config")):
        for key in ("url", "link", "uri", "share", "config"):
            text = _string_value(value, key)
            if _contains_supported_uri(text):
                _append_uri(text, result, subscription_id, group=next_group, tags=[next_group] if next_group else [])

    nested_group = next_group or container_name
    for key in NODE_LIST_KEYS:
        nested = value.get(key)
        if isinstance(nested, list):
            _walk_generic(nested, result, subscription_id, group=nested_group, seen=seen)
    for key in GROUP_LIST_KEYS:
        nested = value.get(key)
        if isinstance(nested, list):
            _walk_generic(nested, result, subscription_id, group=next_group, seen=seen)
    for key, nested in value.items():
        if key in NODE_LIST_KEYS or key in GROUP_LIST_KEYS:
            continue
        if isinstance(nested, (dict, list)):
            _walk_generic(nested, result, subscription_id, group=next_group, seen=seen)


def _parse_outbound_with_metadata(
    outbound: dict[str, Any],
    subscription_id: str | None,
    *,
    group: str | None,
    tags: list[str],
    source_name: str,
    errors: list[str],
) -> ServerProfile | None:
    try:
        profile = parse_outbound(outbound, subscription_id=subscription_id)
    except ServerParseError as exc:
        errors.append(str(exc))
        return None
    return _apply_metadata(profile, group=group, tags=tags, source_name=source_name)


def _append_uri(
    link: str,
    result: ParsedSubscription,
    subscription_id: str | None,
    *,
    group: str | None,
    tags: list[str],
) -> None:
    for item in _extract_links(link):
        try:
            profile = parse_server_uri(item, subscription_id=subscription_id)
        except ServerParseError as exc:
            result.errors.append(str(exc))
            continue
        result.profiles.append(_apply_metadata(profile, group=group, tags=tags, source_name=""))


def _apply_metadata(profile: ServerProfile, *, group: str | None, tags: list[str], source_name: str) -> ServerProfile:
    clean_group = normalize_server_name(group or "", fallback="") if group else None
    clean_source = normalize_server_name(source_name, fallback="") if source_name else None
    profile.group = clean_group
    profile.source_name = clean_source
    merged_tags = []
    for tag in [*tags, clean_group or "", clean_source or ""]:
        clean_tag = normalize_server_name(tag, fallback="")
        if clean_tag and clean_tag not in merged_tags:
            merged_tags.append(clean_tag)
    profile.tags = merged_tags
    profile.name = normalize_server_name(
        profile.name,
        fallback=profile.address,
        group=clean_group,
        protocol=profile.protocol,
    )
    return profile


def _clash_group_map(payload: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for group in payload.get("proxy-groups") or payload.get("proxy_groups") or []:
        if not isinstance(group, dict):
            continue
        group_name = _string_value(group, "name", "tag")
        if not group_name:
            continue
        for member_key in GROUP_MEMBER_KEYS:
            members = group.get(member_key)
            if not isinstance(members, list):
                continue
            for member in members:
                member_name = str(member or "").strip()
                if not member_name:
                    continue
                result.setdefault(member_name, [])
                if group_name not in result[member_name]:
                    result[member_name].append(group_name)
    return result


def _sing_box_group_map(payload: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for outbound in payload.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        outbound_type = normalize_protocol(outbound.get("type"))
        if outbound_type not in {"selector", "urltest", "url-test", "loadbalance", "load-balance"}:
            continue
        group_name = _string_value(outbound, "tag", "name")
        if not group_name:
            continue
        members = outbound.get("outbounds")
        if not isinstance(members, list):
            continue
        for member in members:
            member_name = str(member or "").strip()
            if not member_name:
                continue
            result.setdefault(member_name, [])
            if group_name not in result[member_name]:
                result[member_name].append(group_name)
    return result


def _adapt_clash_proxy(proxy: dict[str, Any]) -> dict[str, Any] | None:
    protocol = _node_protocol(proxy)
    if protocol in SERVICE_OUTBOUND_TYPES or protocol not in SUPPORTED_OUTBOUND_TYPES:
        return None
    outbound = _adapt_generic_proxy(proxy)
    outbound["type"] = protocol
    return outbound


def _adapt_generic_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    protocol = _node_protocol(proxy)
    outbound = dict(proxy)
    outbound["type"] = protocol
    if "tag" not in outbound:
        for key in ("name", "remarks", "ps"):
            if key in proxy:
                outbound["tag"] = proxy[key]
                break
    if "port" in proxy and "server_port" not in outbound:
        outbound["server_port"] = proxy["port"]
    if protocol == "shadowsocks" and "cipher" in proxy and "method" not in outbound:
        outbound["method"] = proxy["cipher"]
    if protocol == "shadowsocks" and "security" in proxy and "method" not in outbound:
        outbound["method"] = proxy["security"]
    if protocol == "vmess":
        if "cipher" in proxy and "security" not in outbound:
            outbound["security"] = proxy["cipher"]
        if "alterId" in proxy and "alter_id" not in outbound:
            outbound["alter_id"] = proxy["alterId"]
    if "servername" in proxy and "server_name" not in outbound:
        outbound["server_name"] = proxy["servername"]
    if "sni" in proxy and "server_name" not in outbound:
        outbound["server_name"] = proxy["sni"]
    if "client-fingerprint" in proxy and "fingerprint" not in outbound:
        outbound["fingerprint"] = proxy["client-fingerprint"]
    if "skip-cert-verify" in proxy and "allowInsecure" not in outbound:
        outbound["allowInsecure"] = proxy["skip-cert-verify"]
    if _bool_like(proxy.get("tls")):
        outbound["tls"] = True
    if isinstance(proxy.get("reality-opts"), dict):
        outbound["security"] = "reality"
    if protocol == "hysteria2":
        obfs = proxy.get("obfs")
        obfs_password = proxy.get("obfs-password") or proxy.get("obfs_password")
        if obfs and not isinstance(obfs, dict):
            outbound["obfs"] = {"type": str(obfs), "password": str(obfs_password or "")}
    if protocol == "tuic":
        if "congestion-controller" in proxy and "congestion_control" not in outbound:
            outbound["congestion_control"] = proxy["congestion-controller"]
        if "udp-relay-mode" in proxy and "udp_relay_mode" not in outbound:
            outbound["udp_relay_mode"] = proxy["udp-relay-mode"]
    return outbound


def _node_protocol(value: dict[str, Any]) -> str:
    for key in ("type", "protocol", "configType", "config_type", "proxyType", "proxy_type"):
        protocol = normalize_protocol(value.get(key))
        if protocol:
            return protocol
    return ""


def _extract_links(text: str) -> list[str]:
    schemes = "|".join(sorted(re.escape(item) for item in SUPPORTED_URI_SCHEMES))
    pattern = re.compile(rf"(?i)({schemes}|ssr)://")
    matches = list(pattern.finditer(text))
    links: list[str] = []
    for index, match in enumerate(matches):
        if match.group(1).lower() not in SUPPORTED_URI_SCHEMES:
            continue
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        chunk = text[start:end]
        newline_positions = [pos for pos in (chunk.find("\n"), chunk.find("\r")) if pos >= 0]
        if newline_positions:
            chunk = chunk[: min(newline_positions)]
        link = _clean_link(chunk)
        if link:
            links.append(link)
    return links


def _contains_supported_uri(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(f"{scheme}://" in lowered for scheme in SUPPORTED_URI_SCHEMES)


def _clean_link(value: str) -> str:
    link = str(value or "").strip()
    while link and link[-1] in ",;]})\"'":
        link = link[:-1].rstrip()
    while link and link[0] in {'"', "'", "[", "(", "{"}:
        link = link[1:].lstrip()
    return link


def _string_value(data: dict[str, Any], *names: str) -> str:
    lower_map = {str(key).lower(): value for key, value in data.items()}
    for name in names:
        value = lower_map.get(name.lower())
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, dict):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _bool_like(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled", "tls"}
