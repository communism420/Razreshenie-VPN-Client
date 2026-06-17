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

"""Сборка sing-box outbound для поддерживаемых протоколов."""

from __future__ import annotations

import re
from typing import Any

from models.profile import ServerProfile


class OutboundBuildError(ValueError):
    """Ошибка генерации outbound для sing-box."""


SUPPORTED_OUTBOUND_PROTOCOLS = {
    "vless",
    "trojan",
    "vmess",
    "hysteria2",
    "tuic",
    "shadowsocks",
    "wireguard",
}
REALITY_PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
REALITY_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]*$")


def _truthy(value: str | None) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _falsy(value: str | None) -> bool:
    return str(value or "").lower() in {"0", "false", "no", "n", "off", "disabled", "none"}


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _int_param(value: str | None, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        parsed = int(str(value).strip())
    except ValueError:
        return None
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


class OutboundBuilder:
    """Собирает protocol-specific outbound, оставляя DNS/route внешнему config builder."""

    def build(self, profile: ServerProfile, tag: str = "proxy") -> dict[str, Any]:
        protocol = str(profile.protocol or "vless").strip().lower()
        if protocol == "vless":
            return self._build_vless(profile, tag)
        if protocol == "trojan":
            return self._build_trojan(profile, tag)
        if protocol == "vmess":
            return self._build_vmess(profile, tag)
        if protocol == "hysteria2":
            return self._build_hysteria2(profile, tag)
        if protocol == "tuic":
            return self._build_tuic(profile, tag)
        if protocol == "shadowsocks":
            return self._build_shadowsocks(profile, tag)
        if protocol == "wireguard":
            return self._build_wireguard(profile, tag)
        raise OutboundBuildError(f"Протокол '{profile.protocol}' пока не поддержан")

    def _base_dial_outbound(self, profile: ServerProfile, tag: str, outbound_type: str) -> dict[str, Any]:
        self._require_endpoint(profile)
        return {
            "type": outbound_type,
            "tag": tag,
            "server": profile.address,
            "server_port": int(profile.port),
            "domain_resolver": "bootstrap-dns",
        }

    def _build_vless(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        if not str(profile.uuid or "").strip():
            raise OutboundBuildError("VLESS требует UUID")
        outbound = self._base_dial_outbound(profile, tag, "vless")
        outbound["uuid"] = profile.uuid

        flow = self._param(profile, "flow")
        if flow:
            outbound["flow"] = flow

        packet_encoding = self._param(profile, "packetEncoding", "packet_encoding")
        if packet_encoding:
            outbound["packet_encoding"] = packet_encoding

        self._attach_tls_transport_mux(outbound, profile, default_tls=False)
        return outbound

    def _build_trojan(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        password = self._param(profile, "password")
        if not password:
            raise OutboundBuildError("Trojan требует password")
        outbound = self._base_dial_outbound(profile, tag, "trojan")
        outbound["password"] = password
        self._attach_tls_transport_mux(outbound, profile, default_tls=True)
        return outbound

    def _build_vmess(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        if not str(profile.uuid or "").strip():
            raise OutboundBuildError("VMess требует UUID")
        outbound = self._base_dial_outbound(profile, tag, "vmess")
        outbound["uuid"] = profile.uuid

        security = self._param(profile, "vmess_security", "cipher", "scy")
        if not security:
            candidate = self._param(profile, "security")
            if candidate and candidate.lower() not in {"tls", "reality", "none"}:
                security = candidate
        outbound["security"] = security or "auto"

        alter_id = _int_param(self._param(profile, "alterId", "alter_id", "aid"), minimum=0)
        if alter_id is not None:
            outbound["alter_id"] = alter_id

        if _truthy(self._param(profile, "global_padding", "globalPadding")):
            outbound["global_padding"] = True
        if _truthy(self._param(profile, "authenticated_length", "authenticatedLength")):
            outbound["authenticated_length"] = True

        self._attach_tls_transport_mux(outbound, profile, default_tls=False, allow_reality=False)
        return outbound

    def _build_hysteria2(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        password = self._param(profile, "password")
        if not password:
            raise OutboundBuildError("Hysteria2 требует password")
        outbound = self._base_dial_outbound(profile, tag, "hysteria2")
        outbound["password"] = password

        for source, target in (
            ("up_mbps", "up_mbps"),
            ("upmbps", "up_mbps"),
            ("download_bandwidth", "down_mbps"),
            ("down_mbps", "down_mbps"),
            ("downmbps", "down_mbps"),
        ):
            value = _int_param(self._param(profile, source), minimum=1)
            if value is not None:
                outbound[target] = value

        obfs_type = self._param(profile, "obfs", "obfs_type")
        if obfs_type and obfs_type.lower() not in {"none", "0", "false"}:
            obfs_password = self._param(profile, "obfs-password", "obfs_password", "obfsPassword")
            if not obfs_password:
                raise OutboundBuildError("Hysteria2 obfs требует obfs-password")
            outbound["obfs"] = {
                "type": obfs_type,
                "password": obfs_password,
            }

        tls = self._build_tls(profile, default_enabled=True, allow_reality=False)
        if tls:
            outbound["tls"] = tls
        return outbound

    def _build_tuic(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        if not str(profile.uuid or "").strip():
            raise OutboundBuildError("TUIC требует UUID")
        password = self._param(profile, "password")
        if not password:
            raise OutboundBuildError("TUIC требует password")
        outbound = self._base_dial_outbound(profile, tag, "tuic")
        outbound["uuid"] = profile.uuid
        outbound["password"] = password

        congestion_control = self._param(profile, "congestion_control", "congestionControl", "congestion")
        if congestion_control:
            outbound["congestion_control"] = congestion_control
        udp_relay_mode = self._param(profile, "udp_relay_mode", "udpRelayMode", "udp_relay")
        if udp_relay_mode:
            outbound["udp_relay_mode"] = udp_relay_mode
        if _truthy(self._param(profile, "zero_rtt_handshake", "zeroRttHandshake", "zero_rtt")):
            outbound["zero_rtt_handshake"] = True
        heartbeat = self._param(profile, "heartbeat", "heartbeat_interval", "heartbeatInterval")
        if heartbeat:
            outbound["heartbeat"] = heartbeat

        tls = self._build_tls(profile, default_enabled=True, allow_reality=False)
        if tls:
            outbound["tls"] = tls
        return outbound

    def _build_shadowsocks(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        method = self._param(profile, "method", "cipher")
        password = self._param(profile, "password")
        if not method or not password:
            raise OutboundBuildError("Shadowsocks требует method и password")
        outbound = self._base_dial_outbound(profile, tag, "shadowsocks")
        outbound["method"] = method
        outbound["password"] = password

        plugin = self._param(profile, "plugin")
        if plugin:
            outbound["plugin"] = plugin
            plugin_opts = self._param(profile, "plugin_opts", "plugin-opts")
            if plugin_opts:
                outbound["plugin_opts"] = plugin_opts
        return outbound

    def _build_wireguard(self, profile: ServerProfile, tag: str) -> dict[str, Any]:
        private_key = self._param(profile, "private_key", "privateKey")
        peer_public_key = self._param(profile, "peer_public_key", "peerPublicKey", "public_key", "publicKey")
        local_address = _split_csv(self._param(profile, "local_address", "localAddress", "address", "addresses"))
        if not private_key or not peer_public_key or not local_address:
            raise OutboundBuildError("WireGuard требует private_key, peer_public_key и local_address")
        outbound = self._base_dial_outbound(profile, tag, "wireguard")
        outbound["private_key"] = private_key
        outbound["peer_public_key"] = peer_public_key
        outbound["local_address"] = local_address

        pre_shared_key = self._param(profile, "pre_shared_key", "preSharedKey", "preshared_key")
        if pre_shared_key:
            outbound["pre_shared_key"] = pre_shared_key
        mtu = _int_param(self._param(profile, "mtu"), minimum=1280)
        if mtu:
            outbound["mtu"] = mtu
        workers = _int_param(self._param(profile, "workers"), minimum=1)
        if workers:
            outbound["workers"] = workers
        reserved = self._parse_reserved(self._param(profile, "reserved"))
        if reserved:
            outbound["reserved"] = reserved
        return outbound

    def _attach_tls_transport_mux(
        self,
        outbound: dict[str, Any],
        profile: ServerProfile,
        *,
        default_tls: bool,
        allow_reality: bool = True,
    ) -> None:
        tls = self._build_tls(profile, default_enabled=default_tls, allow_reality=allow_reality)
        if tls:
            outbound["tls"] = tls

        transport = self._build_transport(profile)
        if transport:
            outbound["transport"] = transport

        multiplex = self._build_multiplex(profile)
        if multiplex:
            outbound["multiplex"] = multiplex

    def _build_tls(
        self,
        profile: ServerProfile,
        *,
        default_enabled: bool,
        allow_reality: bool = True,
    ) -> dict[str, Any] | None:
        security = (self._param(profile, "security") or "").lower()
        tls_requested = default_enabled
        if security in {"tls", "reality"}:
            tls_requested = True
        if security in {"none", "notls", "false"} or _falsy(self._param(profile, "tls")):
            tls_requested = False
        if not tls_requested:
            return None
        if security == "reality" and not allow_reality:
            raise OutboundBuildError(f"{profile.protocol.upper()} не поддерживает Reality в этом генераторе")

        tls: dict[str, Any] = {"enabled": True}
        server_name = self._param(profile, "sni", "serverName", "server_name") or profile.address
        if server_name:
            tls["server_name"] = server_name

        alpn = _split_csv(self._param(profile, "alpn"))
        if alpn:
            tls["alpn"] = alpn

        fingerprint = self._param(profile, "fp", "fingerprint")
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

        if _truthy(self._param(profile, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify")):
            tls["insecure"] = True

        if security == "reality":
            public_key = self._param(profile, "pbk", "publicKey", "public_key")
            if not public_key:
                raise OutboundBuildError(f"{profile.protocol.upper()} Reality требует параметр pbk/publicKey")
            public_key = self._validate_reality_public_key(public_key, profile.protocol)
            reality: dict[str, Any] = {"enabled": True, "public_key": public_key}
            short_id = self._param(profile, "sid", "shortId", "short_id")
            spider_x = self._param(profile, "spx", "spiderX", "spider_x")
            if short_id:
                short_id = self._validate_reality_short_id(short_id, profile.protocol)
                reality["short_id"] = short_id
            if spider_x:
                reality["spider_x"] = spider_x
            tls["reality"] = reality

        return tls

    def _build_transport(self, profile: ServerProfile) -> dict[str, Any] | None:
        network = (self._param(profile, "type", "network") or "tcp").lower()
        path = self._param(profile, "path")
        host = self._param(profile, "host", "authority")

        if network in {"tcp", "raw", ""}:
            header_type = (self._param(profile, "headerType", "header_type") or "").lower()
            if header_type == "http":
                transport: dict[str, Any] = {"type": "http"}
                if host:
                    transport["host"] = _split_csv(host) or [host]
                if path:
                    transport["path"] = path
                return transport
            return None

        if network in {"ws", "websocket"}:
            transport = {"type": "ws"}
            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
            return transport

        if network in {"grpc", "gun"}:
            service_name = self._param(profile, "serviceName", "service_name") or ""
            return {"type": "grpc", "service_name": service_name}

        if network in {"http", "h2"}:
            transport = {"type": "http"}
            if host:
                transport["host"] = _split_csv(host) or [host]
            if path:
                transport["path"] = path
            return transport

        if network in {"quic"}:
            return {"type": "quic"}

        if network in {"httpupgrade", "http_upgrade"}:
            transport = {"type": "httpupgrade"}
            if host:
                transport["host"] = host
            if path:
                transport["path"] = path
            return transport

        raise OutboundBuildError(f"Транспорт '{network}' пока не поддержан генератором sing-box")

    def _build_multiplex(self, profile: ServerProfile) -> dict[str, Any] | None:
        if not _truthy(self._param(profile, "mux", "multiplex")):
            return None
        protocol = self._param(profile, "muxProtocol", "mux_protocol") or "smux"
        max_connections = _int_param(self._param(profile, "muxMaxConnections", "mux_max_connections"), minimum=1)
        multiplex: dict[str, Any] = {"enabled": True, "protocol": protocol}
        if max_connections is not None:
            multiplex["max_connections"] = max_connections
        return multiplex

    @staticmethod
    def _param(profile: ServerProfile, *names: str) -> str | None:
        lower_map = {key.lower(): value for key, value in profile.params.items()}
        for name in names:
            value = lower_map.get(name.lower())
            if value is not None and value != "":
                return value
        return None

    @staticmethod
    def _parse_reserved(value: str | None) -> list[int] | None:
        if not value:
            return None
        parts = re.split(r"[\s,;:]+", str(value).strip().strip("[]"))
        reserved: list[int] = []
        for part in parts:
            if not part:
                continue
            try:
                item = int(part)
            except ValueError:
                return None
            if item < 0 or item > 255:
                return None
            reserved.append(item)
        return reserved if len(reserved) == 3 else None

    @staticmethod
    def _validate_reality_public_key(value: str, protocol: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise OutboundBuildError(f"{protocol.upper()} Reality требует параметр pbk/publicKey")
        if (
            len(text) < 16
            or len(text) > 128
            or not REALITY_PUBLIC_KEY_RE.fullmatch(text)
            or "=" in text.rstrip("=")
        ):
            raise OutboundBuildError(
                f"{protocol.upper()} Reality: некорректный pbk/publicKey. "
                "Ожидается base64url public key без пробелов."
            )
        return text

    @staticmethod
    def _validate_reality_short_id(value: str, protocol: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if len(text) > 16 or len(text) % 2 != 0 or not REALITY_SHORT_ID_RE.fullmatch(text):
            raise OutboundBuildError(
                f"{protocol.upper()} Reality: некорректный sid/short_id. "
                "Ожидается hex-строка чётной длины до 16 символов."
            )
        return text

    @staticmethod
    def _require_endpoint(profile: ServerProfile) -> None:
        if not str(profile.address or "").strip():
            raise OutboundBuildError("У выбранного профиля не указан адрес сервера")
        try:
            port = int(profile.port)
        except (TypeError, ValueError) as exc:
            raise OutboundBuildError("У выбранного профиля указан некорректный порт") from exc
        if port <= 0 or port > 65535:
            raise OutboundBuildError("У выбранного профиля порт вне диапазона 1-65535")
