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
import base64
import json
import sys
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

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
    from core.connectivity import (
        DEFAULT_CONNECTIVITY_CHECK_URLS,
        normalize_connectivity_timeout_ms,
        normalize_connectivity_urls,
    )
    from core.app_updater import app_release_api_url, is_newer_version, select_windows_asset, update_info_from_release
    from core.diagnostics import build_diagnostics_archive, redact_diagnostics_data, redact_diagnostics_text
    from core.domain_activity import (
        DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT,
        DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT,
        DOMAIN_ACTIVITY_RULE_FILTER_MATCHED,
        DOMAIN_ACTIVITY_SORT_HITS,
        DomainActivityTracker,
        summarize_domain_activity,
    )
    from core.error_messages import format_safe_traceback, format_user_error, sanitize_error_text
    from core.latency_scanner import KARING_URL_TEST_LIST, LatencyScanner
    from core.server_parser import parse_outbound, parse_server_uri
    from core.rules_manager import RulesImportError, RulesManager
    from core.singbox_manager import SingBoxManager
    from core.smart_connect import SmartConnectManager
    from core.subscription_manager import SubscriptionError, SubscriptionManager
    from models.connection import (
        QUALITY_EVENT_FAILURE,
        QUALITY_EVENT_LATENCY,
        QUALITY_EVENT_SUCCESS,
        SERVER_QUALITY_HISTORY_LIMIT,
        SMART_GROUP_MODE_LOAD_BALANCE,
        SMART_GROUP_MODE_MULTI_HOP,
        SMART_STRATEGY_FAILOVER_ORDER,
        ServerQualityEvent,
        ServerQualityStats,
        SmartGroup,
    )
    from models.profile import Subscription, VlessProfile
    from models.rules import RouteRuleSetResource, RoutingRuleSet, SplitRules, domain_site_suffix
    from models.settings import (
        BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD,
        BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS,
        BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD,
        BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS,
        SELF_HEALING_MAX_COOLDOWN_SECONDS,
        SELF_HEALING_MAX_MAX_ATTEMPTS,
        SELF_HEALING_MIN_COOLDOWN_SECONDS,
        SELF_HEALING_MIN_MAX_ATTEMPTS,
        AppSettings,
    )
    from core.config_builder import SingBoxConfigBuilder
    from utils.windows import (
        FIREWALL_KILL_SWITCH_GROUP,
        build_firewall_kill_switch_clear_script,
        build_firewall_kill_switch_enable_script,
    )

    samples = [
        "vless://00000000-0000-4000-8000-000000000000@example.com:443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision"
        "&sni=example.com&fp=chrome&pbk=public-key&sid=abcd#VLESS Demo",
        "trojan://password@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=public-key&sid=abcd#Trojan Demo",
        "hysteria2://password@example.com:443?sni=example.com&obfs=salamander&obfs-password=secret#HY2 Demo",
        "tuic://00000000-0000-4000-8000-000000000000:password@example.com:443?sni=example.com&congestion_control=bbr#TUIC Demo",
        "ss://2022-blake3-aes-128-gcm:password@example.com:8388#SS2022 Demo",
    ]
    vmess_payload = {
        "v": "2",
        "ps": "VMess Demo",
        "add": "example.com",
        "port": "443",
        "id": "00000000-0000-4000-8000-000000000000",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "host": "example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "example.com",
    }
    vmess_link = "vmess://" + base64.b64encode(json.dumps(vmess_payload).encode("utf-8")).decode("ascii")
    profiles = [parse_server_uri(sample) for sample in [*samples, vmess_link]]
    profiles.append(
        parse_outbound(
            {
                "type": "wireguard",
                "tag": "WireGuard Demo",
                "server": "example.com",
                "server_port": 51820,
                "local_address": ["172.16.0.2/32"],
                "private_key": "private-key",
                "peer_public_key": "peer-public-key",
            }
        )
    )
    rules = SplitRules(enabled=False)
    builder = SingBoxConfigBuilder()
    for mode in ("proxy", "tun"):
        settings = AppSettings(mode=mode)
        for profile in profiles:
            config = builder.build(profile, settings, rules, log_path=None)
            assert config["outbounds"][0]["type"] == profile.protocol
            assert config["route"]["final"] == "proxy"
            assert config["inbounds"][0]["type"] == ("tun" if mode == "tun" else "mixed")
    settings = AppSettings(mode="proxy")
    custom_connectivity_settings = AppSettings.from_dict(
        {
            "connectivity_check_urls": "https://one.example/check, ftp://bad\nhttp://two.example/ping",
            "connectivity_check_timeout_ms": "9000",
        }
    )
    assert custom_connectivity_settings.connectivity_check_urls == [
        "https://one.example/check",
        "http://two.example/ping",
    ]
    assert custom_connectivity_settings.connectivity_check_timeout_ms == 9000
    assert normalize_connectivity_urls(["https://a.example", "ftp://bad", "https://a.example"]) == ["https://a.example"]
    assert normalize_connectivity_urls("") == list(DEFAULT_CONNECTIVITY_CHECK_URLS)
    assert normalize_connectivity_timeout_ms(50) == 1000
    assert normalize_connectivity_timeout_ms(999999) == 30000
    assert list(KARING_URL_TEST_LIST) == list(DEFAULT_CONNECTIVITY_CHECK_URLS)
    assert list(SingBoxManager.CONNECTIVITY_TEST_URLS) == list(DEFAULT_CONNECTIVITY_CHECK_URLS)
    profile = profiles[0]
    ipv6_settings = AppSettings(
        mode="tun",
        enable_ipv6=True,
        tun_ipv6_address="fdfe:dcba:9876::1/126",
        dns_strategy="prefer_ipv6",
    )
    ipv6_config = builder.build(profile, ipv6_settings, rules, log_path=None)
    assert ipv6_config["dns"]["strategy"] == "prefer_ipv6"
    assert ipv6_config["inbounds"][0]["address"] == ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
    fakeip_server = next(server for server in ipv6_config["dns"]["servers"] if server["tag"] == "fakeip")
    assert fakeip_server["inet6_range"] == "fc00::/18"
    ipv4_only_settings = AppSettings(mode="tun", enable_ipv6=False, dns_strategy="prefer_ipv6")
    ipv4_only_config = builder.build(profile, ipv4_only_settings, rules, log_path=None)
    assert ipv4_only_config["dns"]["strategy"] == "ipv4_only"
    assert ipv4_only_config["inbounds"][0]["address"] == ["172.19.0.1/30"]
    fakeip_server = next(server for server in ipv4_only_config["dns"]["servers"] if server["tag"] == "fakeip")
    assert "inet6_range" not in fakeip_server
    assert ipv4_only_config["dns"]["rules"][-1]["query_type"] == ["A"]
    strict_route_config = builder.build(profile, AppSettings(mode="tun", kill_switch=True), rules, log_path=None)
    assert strict_route_config["inbounds"][0]["strict_route"] is True

    multi_hop_profiles = {
        "hop-a": VlessProfile(
            id="hop-a",
            name="Hop A",
            protocol="vless",
            address="hop-a.example.com",
            port=443,
            uuid="00000000-0000-4000-8000-000000000001",
        ),
        "hop-b": VlessProfile(
            id="hop-b",
            name="Hop B",
            protocol="vless",
            address="hop-b.example.com",
            port=443,
            uuid="00000000-0000-4000-8000-000000000002",
        ),
    }
    multi_hop_config = builder.build_group(
        SmartGroup(name="Chain", mode=SMART_GROUP_MODE_MULTI_HOP, profile_ids=["hop-a", "hop-b"]),
        multi_hop_profiles,
        settings,
        rules,
        log_path=None,
    )
    assert [item["tag"] for item in multi_hop_config["outbounds"][:2]] == ["hop-1", "proxy"]
    assert multi_hop_config["outbounds"][1]["detour"] == "hop-1"
    load_balance_config = builder.build_group(
        SmartGroup(name="LB", mode=SMART_GROUP_MODE_LOAD_BALANCE, profile_ids=["hop-a", "hop-b"]),
        multi_hop_profiles,
        settings,
        rules,
        log_path=None,
    )
    lb_proxy = next(item for item in load_balance_config["outbounds"] if item.get("tag") == "proxy")
    assert lb_proxy["type"] == "urltest"
    assert lb_proxy["outbounds"] == ["lb-1", "lb-2"]
    firewall_settings = AppSettings.from_dict({"firewall_kill_switch": "true"})
    assert firewall_settings.firewall_kill_switch is True
    update_settings = AppSettings.from_dict({"auto_check_app_updates": "yes"})
    assert update_settings.auto_check_app_updates is True
    assert AppSettings.from_dict({"auto_check_app_updates": "no"}).auto_check_app_updates is False
    assert AppSettings().smart_connect_enabled is True
    assert AppSettings.from_dict({"smart_connect_enabled": "off"}).smart_connect_enabled is False
    assert app_release_api_url("https://github.com/communism420/Razreshenie-VPN-Client").endswith(
        "/communism420/Razreshenie-VPN-Client/releases/latest"
    )
    assert is_newer_version("v1.1.10", "1.1.6")
    assert not is_newer_version("1.1.6", "1.1.6")
    assert not is_newer_version("1.1.6-beta1", "1.1.6")
    update_asset = select_windows_asset(
        [
            {"name": "Razreshenie-VPN-Client-linux-x64.zip", "browser_download_url": "https://example.invalid/linux"},
            {"name": "Razreshenie-VPN-Client-setup-windows-x64.exe", "browser_download_url": "https://example.invalid/setup", "size": 12},
            {"name": "checksums.txt", "browser_download_url": "https://example.invalid/checksums"},
        ]
    )
    assert update_asset is not None
    assert update_asset.name.endswith("windows-x64.exe")
    update_info = update_info_from_release(
        {
            "tag_name": "v1.1.10",
            "name": "Razreshenie VPN Client 1.1.10",
            "html_url": "https://github.com/communism420/Razreshenie-VPN-Client/releases/tag/v1.1.10",
            "assets": [
                {
                    "name": "Razreshenie-VPN-Client-setup-windows-x64.exe",
                    "browser_download_url": "https://example.invalid/setup",
                    "size": 12,
                },
                {
                    "name": "Razreshenie-VPN-Client-setup-windows-x64.exe.sha256",
                    "browser_download_url": "https://example.invalid/checksums",
                },
            ],
        },
        current_version="1.1.6",
    )
    assert update_info.update_available
    assert update_info.asset is not None
    assert update_info.checksum_asset is not None
    firewall_enable_script = build_firewall_kill_switch_enable_script(
        r"C:\Razreshenie\sing-box.exe",
        r"C:\Razreshenie\Razreshenie VPN Client.exe",
    )
    assert FIREWALL_KILL_SWITCH_GROUP in firewall_enable_script
    assert "DefaultOutboundAction Block" in firewall_enable_script
    assert "sing-box.exe" in firewall_enable_script
    firewall_clear_script = build_firewall_kill_switch_clear_script({"Domain": "Allow", "Private": "Block"})
    assert FIREWALL_KILL_SWITCH_GROUP in firewall_clear_script
    assert "DefaultOutboundAction Allow" in firewall_clear_script
    assert "DefaultOutboundAction Block" in firewall_clear_script
    assert "Set-NetFirewallProfile" not in build_firewall_kill_switch_clear_script(None)
    health_settings = AppSettings.from_dict(
        {
            "background_health_check_enabled": "false",
            "background_health_check_interval_seconds": 1,
            "background_health_check_failure_threshold": 99,
        }
    )
    assert health_settings.background_health_check_enabled is False
    assert health_settings.background_health_check_interval_seconds == BACKGROUND_HEALTH_CHECK_MIN_INTERVAL_SECONDS
    assert health_settings.background_health_check_failure_threshold == BACKGROUND_HEALTH_CHECK_MAX_FAILURE_THRESHOLD
    health_settings = AppSettings.from_dict(
        {
            "background_health_check_interval_seconds": 999999,
            "background_health_check_failure_threshold": 0,
        }
    )
    assert health_settings.background_health_check_interval_seconds == BACKGROUND_HEALTH_CHECK_MAX_INTERVAL_SECONDS
    assert health_settings.background_health_check_failure_threshold == BACKGROUND_HEALTH_CHECK_MIN_FAILURE_THRESHOLD
    self_healing_settings = AppSettings.from_dict(
        {
            "self_healing_enabled": "off",
            "self_healing_max_attempts": 0,
            "self_healing_cooldown_seconds": 1,
        }
    )
    assert self_healing_settings.self_healing_enabled is False
    assert self_healing_settings.self_healing_max_attempts == SELF_HEALING_MIN_MAX_ATTEMPTS
    assert self_healing_settings.self_healing_cooldown_seconds == SELF_HEALING_MIN_COOLDOWN_SECONDS
    self_healing_settings = AppSettings.from_dict(
        {
            "self_healing_max_attempts": 999,
            "self_healing_cooldown_seconds": 999999,
        }
    )
    assert self_healing_settings.self_healing_max_attempts == SELF_HEALING_MAX_MAX_ATTEMPTS
    assert self_healing_settings.self_healing_cooldown_seconds == SELF_HEALING_MAX_COOLDOWN_SECONDS
    stopped_connectivity = SingBoxManager().check_current_connectivity(settings)
    assert not stopped_connectivity.success
    assert stopped_connectivity.attempts[0].via == "process"
    assert "sing-box" in SingBoxManager().last_runtime_error()
    diagnostic_uuid = "11111111-1111-4111-8111-111111111111"
    diagnostic_secret = "diag-secret-password"
    diagnostic_host = "diag-secret.example"
    diagnostic_domain = "bank.example"
    diagnostic_ipv6 = "2001:db8::1234"
    diagnostic_windows_path = r"C:\Program Files\Secret App\app.exe"
    diagnostic_url = (
        f"vless://{diagnostic_uuid}@{diagnostic_host}:443"
        f"?password={diagnostic_secret}&pbk=diag-public-key&sid=diag-short-id#Diag"
    )
    redacted_json = json.dumps(
        redact_diagnostics_data(
            {
                "uuid": diagnostic_uuid,
                "url": f"https://{diagnostic_host}/sub?token={diagnostic_secret}",
                "outbounds": [
                    {
                        "type": "trojan",
                        "server": diagnostic_host,
                        "server_port": 443,
                        "password": diagnostic_secret,
                    }
                ],
                "rules": {"domain": ["private.example"], "process_path": ["C:/Users/Alice/App/app.exe"]},
            }
        ),
        ensure_ascii=False,
    )
    redacted_text = redact_diagnostics_text(
        f"{diagnostic_url} password={diagnostic_secret} server={diagnostic_host} "
        f"https://{diagnostic_host}/subscription "
        f"dns query {diagnostic_domain} from {diagnostic_ipv6} "
        f"process_path:{diagnostic_windows_path} process_path_regex:(?i).*\\\\chrome\\.exe$"
    )
    for secret in (
        diagnostic_uuid,
        diagnostic_secret,
        diagnostic_host,
        diagnostic_url,
        diagnostic_domain,
        diagnostic_ipv6,
        diagnostic_windows_path,
        "private.example",
        "Alice",
        "chrome",
    ):
        assert secret not in redacted_json
        assert secret not in redacted_text
    assert "trojan" in redacted_json
    with TemporaryDirectory() as temp_dir:
        archive_path = build_diagnostics_archive(
            Path(temp_dir) / "diagnostics.zip",
            settings=AppSettings(),
            profiles=[
                VlessProfile(
                    name=diagnostic_host,
                    address=diagnostic_host,
                    port=443,
                    uuid=diagnostic_uuid,
                    raw_url=diagnostic_url,
                    params={"password": diagnostic_secret},
                )
            ],
            subscriptions=[
                Subscription(name=diagnostic_host, url=f"https://{diagnostic_host}/sub?token={diagnostic_secret}")
            ],
            split_rules=SplitRules(),
            quality_stats={},
            smart_groups=[],
            singbox=SingBoxManager(),
            log_lines=[
                f"{diagnostic_url} password={diagnostic_secret} server={diagnostic_host} "
                f"dns query {diagnostic_domain} from {diagnostic_ipv6} process_path:{diagnostic_windows_path}"
            ],
        )
        with zipfile.ZipFile(archive_path) as archive:
            archive_names = archive.namelist()
            archive_payload = "\n".join(
                archive.read(name).decode("utf-8", errors="replace")
                for name in archive_names
                if name.endswith((".json", ".log", ".txt"))
            )
        for secret in (
            diagnostic_uuid,
            diagnostic_secret,
            diagnostic_host,
            diagnostic_url,
            diagnostic_domain,
            diagnostic_ipv6,
            diagnostic_windows_path,
        ):
            assert secret not in archive_payload
        assert "manifest.json" in archive_names
    permission_message = format_user_error(PermissionError("Access is denied"))
    assert permission_message.category == "permission"
    assert "Недостаточно прав" in permission_message.display_text
    port_message = format_user_error(RuntimeError("Локальный proxy-порт 127.0.0.1:2080 уже занят"))
    assert port_message.category == "port"
    config_message = format_user_error(RuntimeError(f"sing-box отклонил конфигурацию: password={diagnostic_secret}"))
    assert config_message.category == "config"
    assert diagnostic_secret not in config_message.display_text
    subscription_message = format_user_error(
        RuntimeError(f"В подписке не найдено корректных серверов: {diagnostic_url}")
    )
    assert subscription_message.category == "subscription"
    assert diagnostic_url not in subscription_message.display_text
    assert format_user_error("ошибка обновления", context="Подписка").category == "subscription"
    try:
        raise ValueError(f"raw failure: {diagnostic_url} password={diagnostic_secret}")
    except ValueError as exc:
        user_message = format_user_error(exc)
        safe_traceback = format_safe_traceback(exc)
    assert diagnostic_url not in user_message.display_text
    assert diagnostic_secret not in user_message.display_text
    assert diagnostic_url not in safe_traceback
    assert diagnostic_secret not in safe_traceback
    assert diagnostic_secret not in sanitize_error_text(f"password={diagnostic_secret}")
    config = builder.build(profile, settings, rules, log_path=None)
    assert config["outbounds"][0]["type"] == "vless"
    assert config["route"]["final"] == "proxy"

    smart_profiles = [
        VlessProfile(
            id="smart-a",
            name="A",
            address="a.example.com",
            port=443,
            subscription_id="sub-1",
            group="Auto",
            latency_ms=90,
        ),
        VlessProfile(
            id="smart-b",
            name="B",
            address="b.example.com",
            port=443,
            subscription_id="sub-1",
            group="Auto",
            latency_ms=30,
        ),
        VlessProfile(
            id="smart-c",
            name="C",
            address="c.example.com",
            port=443,
            subscription_id="sub-1",
            group="Auto",
            latency_ms=160,
        ),
    ]
    smart_manager = SmartConnectManager(
        {
            "smart-a": ServerQualityStats(profile_id="smart-a", latency_ewma_ms=85, success_count=1),
            "smart-b": ServerQualityStats(
                profile_id="smart-b",
                latency_ewma_ms=25,
                failure_count=4,
                consecutive_failures=3,
                cooldown_until="2999-01-01T00:00:00+00:00",
            ),
        }
    )
    assert [item.id for item in smart_manager.candidate_profiles(smart_profiles[0], smart_profiles)] == [
        "smart-a",
        "smart-c",
        "smart-b",
    ]
    assert smart_manager.choose_best(smart_profiles[0], smart_profiles).selected.id == "smart-a"
    smart_manager.record_latency("smart-c", 40, checked_at="2026-01-01T00:00:00+00:00")
    smart_c_stats = smart_manager.quality_stats["smart-c"]
    assert smart_c_stats.last_event is not None
    assert smart_c_stats.last_event.event == QUALITY_EVENT_LATENCY
    assert smart_c_stats.recent_average_latency_ms == 40
    assert smart_manager.choose_best(smart_profiles[0], smart_profiles).selected.id == "smart-c"
    smart_manager.record_latency("smart-c", None, checked_at="2026-01-01T00:01:00+00:00")
    assert smart_manager.quality_stats["smart-c"].consecutive_failures == 1
    assert smart_manager.quality_stats["smart-c"].last_event is not None
    assert smart_manager.quality_stats["smart-c"].last_event.event == QUALITY_EVENT_FAILURE
    assert smart_manager.quality_stats["smart-c"].last_event.message == "latency timeout"
    assert smart_manager.quality_stats["smart-c"].recent_success_rate == 0.5
    assert smart_manager.choose_best(
        smart_profiles[0],
        smart_profiles,
        latency_overrides={"smart-a": 90, "smart-c": None},
    ).selected.id == "smart-a"
    smart_manager.record_success("smart-c", checked_at="2026-01-01T00:02:00+00:00")
    assert smart_manager.quality_stats["smart-c"].last_event is not None
    assert smart_manager.quality_stats["smart-c"].last_event.event == QUALITY_EVENT_SUCCESS
    failover_group = SmartGroup(
        name="Manual failover",
        strategy=SMART_STRATEGY_FAILOVER_ORDER,
        profile_ids=["smart-b", "smart-a"],
    )
    failover_manager = SmartConnectManager(smart_groups=[failover_group])
    assert [item.id for item in failover_manager.candidate_profiles(smart_profiles[1], smart_profiles)] == [
        "smart-b",
        "smart-a",
    ]
    created_group, created_members = SmartConnectManager().create_or_update_failover_group(
        smart_profiles[0],
        smart_profiles,
        name="Auto failover",
    )
    assert created_group.name == "Auto failover"
    assert created_group.profile_ids == ["smart-a", "smart-b", "smart-c"]
    assert [member.id for member in created_members] == ["smart-a", "smart-b", "smart-c"]
    ordered_failover_manager = SmartConnectManager(
        smart_groups=[
            SmartGroup(
                name="Ordered failover",
                strategy=SMART_STRATEGY_FAILOVER_ORDER,
                profile_ids=["smart-a", "smart-b", "smart-c"],
            )
        ]
    )
    assert ordered_failover_manager.choose_failover_next(
        smart_profiles[0],
        smart_profiles,
        current_profile=smart_profiles[0],
        failed_ids={"smart-a"},
    ).selected.id == "smart-b"
    assert ordered_failover_manager.choose_failover_next(
        smart_profiles[0],
        smart_profiles,
        current_profile=smart_profiles[1],
        failed_ids={"smart-a", "smart-b"},
    ).selected.id == "smart-c"
    assert ordered_failover_manager.choose_failover_next(
        smart_profiles[0],
        smart_profiles,
        current_profile=smart_profiles[1],
        failed_ids={"smart-a", "smart-b"},
        latency_overrides={"smart-c": None},
    ).selected is None
    assert ServerQualityStats.from_dict(smart_manager.quality_stats["smart-c"].to_dict()).profile_id == "smart-c"
    history_stats = ServerQualityStats(profile_id="history")
    for index in range(SERVER_QUALITY_HISTORY_LIMIT + 5):
        history_stats.add_event(
            QUALITY_EVENT_LATENCY,
            timestamp=f"2026-01-01T00:00:{index % 60:02d}+00:00",
            success=True,
            latency_ms=index + 1,
        )
    assert len(history_stats.history) == SERVER_QUALITY_HISTORY_LIMIT
    assert history_stats.history[0].latency_ms == 6
    assert history_stats.recent_average_latency_ms == 30
    history_roundtrip = ServerQualityStats.from_dict(history_stats.to_dict())
    assert len(history_roundtrip.history) == SERVER_QUALITY_HISTORY_LIMIT
    assert history_roundtrip.history[-1].event == QUALITY_EVENT_LATENCY
    assert ServerQualityEvent.from_dict({"event": "bad", "success": "false"}).event == QUALITY_EVENT_FAILURE
    assert SmartGroup.from_dict(failover_group.to_dict()).strategy == SMART_STRATEGY_FAILOVER_ORDER
    assert SmartGroup.from_dict({"name": "Disabled", "enabled": "false"}).enabled is False
    empty_latency_scan = LatencyScanner().scan_profiles_sync([], settings=settings)
    assert empty_latency_scan.results == {}
    assert empty_latency_scan.summary.total_profiles == 0
    assert empty_latency_scan.summary.successful_profiles == 0

    srs_rules = SplitRules(
        enabled=True,
        rule_set_resources=[
            RouteRuleSetResource(
                name="Local RU SRS",
                type="local",
                tag="ru-sites",
                format="binary",
                path="rules/ru-sites.srs",
            ),
            RouteRuleSetResource(
                name="Remote Ads SRS",
                type="remote",
                tag="ads",
                format="binary",
                url="https://example.com/ads.srs",
                update_interval="12h",
            ),
        ],
        rule_sets=[
            RoutingRuleSet(
                name="RU direct",
                outbound="direct",
                priority=10,
                rule_set_tags=["ru-sites"],
            ),
            RoutingRuleSet(
                name="Ads via source IP",
                outbound="proxy",
                priority=20,
                rule_set_tags=["ads"],
                rule_set_ip_cidr_match_source=True,
            ),
        ],
    )
    srs_config = builder.build(profile, settings, srs_rules, log_path=None)
    route_rule_sets = srs_config["route"]["rule_set"]
    assert route_rule_sets[0] == {"type": "local", "tag": "ru-sites", "format": "binary", "path": "rules/ru-sites.srs"}
    assert route_rule_sets[1]["type"] == "remote"
    assert route_rule_sets[1]["url"] == "https://example.com/ads.srs"
    assert route_rule_sets[1]["update_interval"] == "12h"
    route_rules = srs_config["route"]["rules"]
    assert any(rule.get("rule_set") == ["ru-sites"] and rule.get("outbound") == "direct" for rule in route_rules)
    assert any(
        rule.get("rule_set") == ["ads"]
        and rule.get("outbound") == "proxy"
        and rule.get("rule_set_ip_cidr_match_source") is True
        for rule in route_rules
    )
    rules_manager = RulesManager()
    imported_inline_rules = rules_manager.from_text(
        "\n".join(
            [
                "geosite:ru",
                "geoip:ru",
                "regexp:^stun\\..+",
                "process_path_regex:(?i).*\\\\chrome\\.exe$",
                "process_path:C:\\\\Program Files\\\\App\\\\app.exe",
                "process_name:telegram.exe",
                "telegram.exe",
                'process:C:\\\\Tools\\\\Legacy.exe --profile test',
                '"C:/Program Files/App/app.exe" --flag',
                "process-path-regex:(?i).*\\\\Telegram\\\\.*\\.exe$",
                "domain:*.video.example.com",
            ]
        ),
        "direct",
    )
    assert imported_inline_rules.geosite == ["ru"]
    assert imported_inline_rules.geoip == ["ru"]
    assert imported_inline_rules.domain_regex == ["^stun\\..+"]
    assert imported_inline_rules.process_path_regex == [
        "(?i).*\\\\chrome\\.exe$",
        "(?i).*\\\\Telegram\\\\.*\\.exe$",
    ]
    assert imported_inline_rules.process_path == ["C:\\Program Files\\App\\app.exe"]
    assert imported_inline_rules.process_name == ["Legacy.exe", "telegram.exe"]
    assert "video.example.com" in imported_inline_rules.domain_suffix

    process_config = builder.build(
        profile,
        settings,
        SplitRules(
            enabled=True,
            rule_sets=[
                RoutingRuleSet(
                    name="Windows process direct",
                    outbound="direct",
                    process_name=["Telegram.exe", "telegram.exe"],
                    process_path=['"C:/Program Files/App/app.exe" --flag'],
                    process_path_regex=["(?i).*\\\\chrome\\.exe$"],
                )
            ],
        ),
        log_path=None,
    )
    process_route = next(rule for rule in process_config["route"]["rules"] if rule.get("process_name"))
    assert process_route["process_name"] == ["Telegram.exe"]
    assert process_route["process_path"] == ["C:\\Program Files\\App\\app.exe"]
    assert process_route["process_path_regex"] == ["(?i).*\\\\chrome\\.exe$"]
    assert domain_site_suffix("www.example.co.uk") == "example.co.uk"

    direct_zone_config = builder.build(
        profile,
        AppSettings(mode="tun"),
        SplitRules(
            enabled=True,
            rule_sets=[
                RoutingRuleSet(
                    name="Direct player exact domain",
                    outbound="direct",
                    domains=["www.familyguy.example"],
                )
            ],
        ),
        log_path=None,
    )
    direct_dns_rule = next(
        rule
        for rule in direct_zone_config["dns"]["rules"]
        if rule.get("domain") == ["www.familyguy.example"]
    )
    assert direct_dns_rule["server"] == "fakeip"
    assert direct_dns_rule["query_type"] == ["A", "AAAA"]
    assert "familyguy.example" in direct_dns_rule["domain_suffix"]
    direct_route_rule = next(
        rule
        for rule in direct_zone_config["route"]["rules"]
        if rule.get("domain") == ["www.familyguy.example"]
    )
    assert direct_route_rule["outbound"] == "direct"
    assert "familyguy.example" in direct_route_rule["domain_suffix"]
    direct_zone_proxy_config = builder.build(
        profile,
        AppSettings(mode="proxy"),
        SplitRules(
            enabled=True,
            rule_sets=[
                RoutingRuleSet(
                    name="Direct player proxy-mode",
                    outbound="direct",
                    domains=["www.familyguy.example"],
                )
            ],
        ),
        log_path=None,
    )
    direct_proxy_dns_rule = next(
        rule
        for rule in direct_zone_proxy_config["dns"]["rules"]
        if rule.get("domain") == ["www.familyguy.example"]
    )
    assert direct_proxy_dns_rule["server"] == "bootstrap-dns"

    builtin_direct_config = builder.build(profile, AppSettings(mode="tun"), SplitRules(), log_path=None)
    builtin_direct_dns = next(
        rule
        for rule in builtin_direct_config["dns"]["rules"]
        if "ozon.ru" in rule.get("domain_suffix", [])
    )
    assert builtin_direct_dns["server"] == "fakeip"
    builtin_direct_route = next(
        rule
        for rule in builtin_direct_config["route"]["rules"]
        if rule.get("outbound") == "direct" and "ozon.ru" in rule.get("domain_suffix", [])
    )
    assert "wildberries.ru" in builtin_direct_route["domain_suffix"]
    assert "ozone.ru" in builtin_direct_route["domain_suffix"]
    assert "ozonusercontent.com" in builtin_direct_route["domain_suffix"]

    activity_tracker = DomainActivityTracker()
    activity_rules = SplitRules(
        enabled=True,
        rule_sets=[
            RoutingRuleSet(
                name="Direct RU",
                outbound="direct",
                domain_suffix=["ru"],
            )
        ],
    )
    assert activity_tracker.ingest_log_line("[sing-box] outbound/proxy example.com", activity_rules)
    assert activity_tracker.ingest_log_line("[sing-box] outbound/proxy example.com", activity_rules)
    assert activity_tracker.ingest_log_line("[sing-box] outbound/direct yandex.ru", activity_rules)
    assert activity_tracker.ingest_log_line("[sing-box] resolved openai.com", activity_rules)
    activity_entries = activity_tracker.snapshot(sort_mode=DOMAIN_ACTIVITY_SORT_HITS)
    assert activity_entries[0].domain == "example.com"
    activity_summary = summarize_domain_activity(activity_entries)
    assert activity_summary.total_domains == 3
    assert activity_summary.proxy_hits == 3
    assert activity_summary.direct_hits == 1
    assert activity_summary.proxy_hit_percent == 75
    assert [entry.domain for entry in activity_tracker.snapshot(rule_filter=DOMAIN_ACTIVITY_RULE_FILTER_MATCHED)] == [
        "yandex.ru"
    ]
    assert [entry.domain for entry in activity_tracker.snapshot(rule_filter=DOMAIN_ACTIVITY_RULE_FILTER_EXPLICIT)] == [
        "example.com"
    ]
    assert [entry.domain for entry in activity_tracker.snapshot(rule_filter=DOMAIN_ACTIVITY_RULE_FILTER_DEFAULT)] == [
        "openai.com"
    ]
    assert [entry.domain for entry in activity_tracker.snapshot(query="direct")] == ["yandex.ru"]
    activity_zone_tracker = DomainActivityTracker()
    activity_zone_rules = SplitRules(
        enabled=True,
        rule_sets=[
            RoutingRuleSet(
                name="Direct player exact",
                outbound="direct",
                domains=["www.familyguy.example"],
            )
        ],
    )
    assert activity_zone_tracker.ingest_log_line("[sing-box] resolved cdn.familyguy.example", activity_zone_rules)
    activity_zone_entry = activity_zone_tracker.snapshot()[0]
    assert activity_zone_entry.route == "direct"
    assert activity_zone_entry.rule_name == "Direct player exact"

    json_rules = rules_manager.from_json(
        {
            "rules": [
                {
                    "geosite": ["ru", "category-ru"],
                    "geoip": "private",
                    "domain_regex": ["^.*\\.ru$"],
                    "rule_set": ["ru-sites"],
                }
            ]
        },
        "direct",
    )
    assert json_rules.geosite == ["category-ru", "ru"]
    assert json_rules.geoip == ["private"]
    assert json_rules.rule_set_tags == ["ru-sites"]

    with TemporaryDirectory() as tmp:
        srs_path = Path(tmp) / "ru-sites.srs"
        srs_path.write_bytes(b"SRS")
        srs_file_result = rules_manager.import_file(srs_path, "direct")
        assert len(srs_file_result.rule_set_resources) == 1
        assert srs_file_result.rule_set_resources[0].type == "local"
        assert srs_file_result.rule_set_resources[0].format == "binary"
        assert srs_file_result.rule_sets[0].rule_set_tags == [srs_file_result.rule_set_resources[0].tag]
        try:
            rules_manager.from_file(srs_path, "direct")
        except RulesImportError:
            pass
        else:
            raise AssertionError("legacy from_file must reject SRS resource results")

    srs_url_result = rules_manager.import_url("https://example.com/geo/ru.srs", "direct")
    assert srs_url_result.rule_set_resources[0].type == "remote"
    assert srs_url_result.rule_set_resources[0].url == "https://example.com/geo/ru.srs"
    assert srs_url_result.rule_sets[0].rule_set_tags == [srs_url_result.rule_set_resources[0].tag]

    subscription_manager = SubscriptionManager()
    clash_yaml = """
proxies:
  - name: Clash SS2022
    type: ss
    server: example.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: password
  - name: Clash Trojan
    type: trojan
    server: example.com
    port: 443
    password: password
    sni: example.com
    skip-cert-verify: true
proxy-groups:
  - name: Auto
    type: url-test
    proxies:
      - Clash SS2022
      - Clash Trojan
"""
    clash_profiles = subscription_manager.parse_text(clash_yaml, "clash")
    assert [profile.protocol for profile in clash_profiles] == ["shadowsocks", "trojan"]
    assert all(profile.group == "Auto" for profile in clash_profiles)

    sing_box_json = json.dumps(
        {
            "outbounds": [
                {"type": "selector", "tag": "Main", "outbounds": ["SB VLESS"]},
                {
                    "type": "vless",
                    "tag": "SB VLESS",
                    "server": "example.com",
                    "server_port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000000",
                    "tls": {"enabled": True, "server_name": "example.com"},
                },
            ]
        }
    )
    sing_box_profiles = subscription_manager.parse_text(sing_box_json, "sing-box")
    assert len(sing_box_profiles) == 1
    assert sing_box_profiles[0].group == "Main"

    nekoray_json = json.dumps(
        {
            "groups": [
                {
                    "name": "Neko Group",
                    "profiles": [
                        {
                            "remarks": "Neko VMess",
                            "protocol": "vmess",
                            "address": "example.com",
                            "port": 443,
                            "id": "00000000-0000-4000-8000-000000000000",
                            "security": "auto",
                            "tls": True,
                            "sni": "example.com",
                        }
                    ],
                }
            ]
        }
    )
    nekoray_profiles = subscription_manager.parse_text(nekoray_json, "nekoray")
    assert len(nekoray_profiles) == 1
    assert nekoray_profiles[0].protocol == "vmess"
    assert nekoray_profiles[0].group == "Neko Group"

    progress_events = []
    multi_profiles = subscription_manager.parse_many(
        [
            ("clash.yaml", clash_yaml),
            ("sing-box.json", sing_box_json),
            ("nekoray.json", nekoray_json),
        ],
        "multi",
        progress_events.append,
    )
    assert len(multi_profiles) == 4
    assert [event.current for event in progress_events] == [1, 2, 3]
    assert progress_events[-1].imported == 4

    class BatchCheckSubscriptionManager(SubscriptionManager):
        def fetch(self, subscription: Subscription):
            if subscription.url == "fail":
                raise SubscriptionError("demo failure")
            profiles = self.parse_text(subscription.url, subscription.id)
            subscription.profile_count = len(profiles)
            subscription.last_error = None
            return profiles, subscription

    batch_manager = BatchCheckSubscriptionManager()
    batch_progress = []
    batch_results = batch_manager.fetch_many(
        [
            Subscription(name="OK", url=samples[0]),
            Subscription(name="Fail", url="fail"),
        ],
        max_workers=2,
        progress_callback=batch_progress.append,
    )
    assert len(batch_results) == 2
    assert sum(1 for result in batch_results if result.success) == 1
    assert sum(1 for result in batch_results if not result.success) == 1
    assert batch_progress[-1].current == 2
    assert batch_progress[-1].errors == 1
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
