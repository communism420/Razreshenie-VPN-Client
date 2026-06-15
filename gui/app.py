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

"""PyQt6 Fluent GUI, переработанный по архитектуре zapret-kvn."""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from PyQt6.QtCore import (
    QObject,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QCloseEvent,
)
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QInputDialog,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
)
from qfluentwidgets import (
    FluentIcon as FIF,
    FluentWindow,
    InfoBar,
    InfoBarPosition,
    NavigationItemPosition,
    Theme,
    setTheme,
    setThemeColor,
)

from gui.common import (
    ACCENT,
    app_logo_icon,
    install_emoji_font_fallbacks,
)
from gui.dialogs import (
    MATCH_KIND_PROCESS_NAME,
    MATCH_KIND_PROCESS_PATH,
    MATCH_KIND_PROCESS_PATH_REGEX,
    ONBOARDING_ACTION_ADD_SUBSCRIPTION,
    ONBOARDING_ACTION_DOWNLOAD_CORE,
    ONBOARDING_ACTION_IMPORT_SERVER,
    ONBOARDING_ACTION_OPEN_SETTINGS,
    ONBOARDING_ACTION_SKIP,
    OnboardingDialog,
    OnboardingResult,
    PerAppRuleDialog,
    SmartGroupEditorDialog,
)
from gui.pages.activity import DomainActivityPage
from gui.pages.about import AboutPage
from gui.pages.dashboard import DashboardPage
from gui.pages.logs import LogsPage
from gui.pages.routing import RoutingPage
from gui.pages.servers import ServersPage
from gui.pages.settings import SettingsPage
from gui.pages.subscriptions import SubscriptionsPage
from gui.widgets import JsonEditorDialog
from core import app_state
from core.app_updater import AppUpdateInfo, check_for_app_update, download_update_asset
from core.connection_service import ConnectionService, ConnectionStartResult
from core.connectivity import ConnectivityCheckResult
from core.diagnostics import build_diagnostics_archive
from core.domain_activity import DomainActivityTracker
from core.error_messages import format_safe_traceback, format_user_error, sanitize_error_text
from core.latency_scanner import LatencyScanner, LatencyScanSummary
from core.resilience_service import (
    HEALTH_STATUS_FAILED,
    HEALTH_STATUS_OK,
    HEALTH_STATUS_RECOVER,
    RECOVERY_ACTION_FAILOVER,
    RECOVERY_ACTION_RESTART,
    FailoverAttemptResult,
    ResilienceService,
)
from core.rules_manager import RulesImportError, RulesImportResult, RulesManager
from core.smart_connect import SmartConnectManager
from core.singbox_manager import SingBoxError, SingBoxManager
from core.subscription_manager import SubscriptionFetchResult, SubscriptionManager
from models.connection import SMART_GROUP_MODE_FAILOVER, SMART_GROUP_MODE_LOAD_BALANCE, SmartGroup, normalize_smart_group_mode
from models.profile import Subscription, VlessProfile, utc_now_iso
from models.rules import (
    BUILTIN_DIRECT_DOMAIN_SUFFIXES,
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
    domain_site_suffix,
    normalize_outbound,
)
from models.settings import (
    AppSettings,
)
from utils import paths, windows
from utils.app_logger import LogBuffer, setup_logger
from utils.network import (
    TrafficMonitor,
    check_dns_resolver,
    format_bytes,
    format_speed,
    get_public_ip,
    measure_server_latency_ms,
)
from utils.scheduler import RepeatingTask
from utils.version import (
    APP_NAME,
    APP_VERSION,
)


LATENCY_SCAN_TIMEOUT_MS = 15000
LATENCY_SCAN_WORKERS = 20
LATENCY_BATCH_SIZE = 48
LATENCY_BATCH_INTERVAL_SECONDS = 0.25
LATENCY_UI_DRAIN_INTERVAL_MS = 16
LATENCY_UI_DRAIN_LIMIT = 24
SMART_CONNECT_SCAN_LIMIT = 8
LIVE_ACTIVITY_RULE_SOURCE_TYPE = "live_activity"
LIVE_ACTIVITY_RULE_SOURCE = "Live Activity"
PER_APP_RULE_SOURCE_TYPE = "per_app"
PER_APP_RULE_SOURCE = "Per-app routing"


class UiBridge(QObject):
    call = pyqtSignal(object)
    log_line = pyqtSignal(str, str)
    activity_changed = pyqtSignal()


class RazreshenieWindow(FluentWindow):
    def __init__(self) -> None:
        super().__init__()
        paths.ensure_app_dirs()
        self.bridge = UiBridge(self)
        self.bridge.call.connect(lambda callback: callback())
        self.bridge.log_line.connect(self._append_log_line)
        self.bridge.activity_changed.connect(self._schedule_activity_refresh)
        self.log_buffer = LogBuffer()
        self.domain_activity = DomainActivityTracker()
        self.logger = setup_logger(paths.log_file_path(), self._on_log_from_thread)
        self.settings = app_state.load_settings()
        self.settings.app_name = APP_NAME
        self.settings.portable_mode = paths.is_portable_mode()
        self.profiles = app_state.load_profiles()
        self._profiles_by_id = {profile.id: profile for profile in self.profiles}
        self.subscriptions = app_state.load_subscriptions()
        self.split_rules = app_state.load_split_rules()
        self.rules_manager = RulesManager()
        self.subscription_manager = SubscriptionManager()
        self.smart_connect = SmartConnectManager(app_state.load_quality_stats(), app_state.load_smart_groups())
        self.smart_connect.prune_missing_profiles(profile.id for profile in self.profiles)
        self._sync_subscription_profile_counts(save=True)
        self.singbox = SingBoxManager(self.logger)
        self.latency_scanner = LatencyScanner(
            timeout_ms=LATENCY_SCAN_TIMEOUT_MS,
            max_workers=LATENCY_SCAN_WORKERS,
            batch_size=LATENCY_BATCH_SIZE,
            batch_interval_seconds=LATENCY_BATCH_INTERVAL_SECONDS,
            logger=self.logger,
            binary_provider=self.singbox.ensure_binary,
        )
        self.connection_service = ConnectionService(
            singbox=self.singbox,
            smart_connect=self.smart_connect,
            latency_scanner=self.latency_scanner,
            logger=self.logger,
            scan_limit=SMART_CONNECT_SCAN_LIMIT,
        )
        self.resilience = ResilienceService(
            connection_service=self.connection_service,
            logger=self.logger,
            scan_limit=SMART_CONNECT_SCAN_LIMIT,
        )
        self.traffic = TrafficMonitor()
        self.scheduler: RepeatingTask | None = None
        self._closing = False
        self._busy = False
        self._ip_refreshing = False
        self._ping_refreshing = False
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self._latency_result_queue: deque[tuple[str, int | None]] = deque()
        self._pending_latency_summary: LatencyScanSummary | None = None
        self._core_version_cache: str | None = None
        self._last_ip_refresh = 0
        self._last_ping_refresh = 0
        self._ip_label = "IP: —"
        self._ping_label = "Пинг: —"
        self._speed_label = "↓ 0.0 Б/с   ↑ 0.0 Б/с"
        self._activity_signal_lock = threading.Lock()
        self._activity_signal_pending = False
        self._active_connection_profile_ids: tuple[str, ...] = ()
        self._active_connection_group_id: str | None = None
        self._active_connection_started_at_iso: str | None = None
        self._active_connection_started_monotonic: float | None = None
        self.tray: QSystemTrayIcon | None = None

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.setWindowIcon(app_logo_icon())
        self.resize(1280, 760)
        self.setMinimumSize(760, 520)

        self.dashboard_page = DashboardPage(self)
        self.servers_page = ServersPage(self)
        self.subscriptions_page = SubscriptionsPage(self)
        self.routing_page = RoutingPage(self)
        self.activity_page = DomainActivityPage(self)
        self.logs_page = LogsPage(self)
        self.settings_page = SettingsPage(self)
        self.about_page = AboutPage(self)
        self.settings_autosave_timer = QTimer(self)
        self.settings_autosave_timer.setSingleShot(True)
        self.settings_autosave_timer.setInterval(350)
        self.settings_autosave_timer.timeout.connect(self.save_settings)
        self._create_navigation()
        self._create_tray()
        self._connect_signals()
        self.activity_refresh_timer = QTimer(self)
        self.activity_refresh_timer.setSingleShot(True)
        self.activity_refresh_timer.setInterval(180)
        self.activity_refresh_timer.timeout.connect(self._refresh_activity_page)
        self._refresh_all_views()
        self._start_subscription_scheduler()

        self.metrics_timer = QTimer(self)
        self.metrics_timer.setInterval(1000)
        self.metrics_timer.timeout.connect(self._status_loop)
        self.metrics_timer.start()
        self.latency_result_timer = QTimer(self)
        self.latency_result_timer.setInterval(LATENCY_UI_DRAIN_INTERVAL_MS)
        self.latency_result_timer.timeout.connect(self._drain_latency_result_queue)
        self.activity_timer = QTimer(self)
        self.activity_timer.setInterval(3000)
        self.activity_timer.timeout.connect(lambda: self._schedule_activity_refresh(0))
        self.activity_timer.start()
        QTimer.singleShot(250, self._post_init)

    def _create_navigation(self) -> None:
        self.navigationInterface.setMinimumExpandWidth(700)
        self.navigationInterface.setExpandWidth(200)
        self.addSubInterface(self.dashboard_page, FIF.SPEED_HIGH, "Панель")
        self.addSubInterface(self.servers_page, FIF.LINK, "Серверы")
        self.addSubInterface(self.subscriptions_page, FIF.UPDATE, "Подписки")
        self.addSubInterface(self.routing_page, FIF.CODE, "Маршрутизация")
        self.addSubInterface(self.activity_page, FIF.SEND, "Активность")
        self.addSubInterface(self.logs_page, FIF.DOCUMENT, "Логи")
        self.addSubInterface(self.about_page, FIF.INFO, "О проекте", NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FIF.SETTING, "Настройки", NavigationItemPosition.BOTTOM)

    def _create_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(app_logo_icon())
        self.tray.setToolTip(f"{APP_NAME} {APP_VERSION}")
        menu = QMenu()
        self.tray_show_action = QAction("Показать", self)
        self.tray_connect_action = QAction("Подключить", self)
        self.tray_disconnect_action = QAction("Отключить", self)
        self.tray_quit_action = QAction("Выход", self)
        menu.addAction(self.tray_show_action)
        menu.addAction(self.tray_connect_action)
        menu.addAction(self.tray_disconnect_action)
        menu.addSeparator()
        menu.addAction(self.tray_quit_action)
        self.tray.setContextMenu(menu)
        self.tray.show()
        self.tray_show_action.triggered.connect(self.show_normal)
        self.tray_connect_action.triggered.connect(self.connect_vpn)
        self.tray_disconnect_action.triggered.connect(self.disconnect_vpn)
        self.tray_quit_action.triggered.connect(self.exit_app)
        self.tray.activated.connect(lambda reason: self.show_normal() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)

    def _connect_signals(self) -> None:
        self.dashboard_page.toggle_connection_requested.connect(self.toggle_connection)
        self.dashboard_page.profile_selected.connect(self.set_active_profile)
        self.dashboard_page.mode_changed.connect(self.set_mode)
        self.dashboard_page.import_requested.connect(self.import_server_link)
        self.dashboard_page.dns_requested.connect(self.check_dns)
        self.dashboard_page.download_core_requested.connect(self.download_core)
        self.dashboard_page.rules_requested.connect(lambda: self.switchTo(self.routing_page))

        self.servers_page.import_requested.connect(self.import_server_link)
        self.servers_page.import_files_requested.connect(self.import_server_files)
        self.servers_page.activate_requested.connect(self.set_active_profile)
        self.servers_page.edit_requested.connect(self.edit_profile_by_id)
        self.servers_page.delete_requested.connect(self.delete_profile_by_id)
        self.servers_page.ping_requested.connect(self.test_profile_latency_by_id)
        self.servers_page.ping_all_requested.connect(self.test_all_latencies)
        self.servers_page.sort_latency_requested.connect(self.sort_profiles_by_latency)
        self.servers_page.failover_group_requested.connect(self.create_failover_group_by_id)
        self.servers_page.smart_group_edit_requested.connect(self.edit_smart_group_by_id)
        self.servers_page.smart_group_start_requested.connect(self.start_smart_group_by_id)
        self.servers_page.validate_requested.connect(self.validate_current_config)

        self.subscriptions_page.add_requested.connect(self.add_subscription)
        self.subscriptions_page.update_requested.connect(self.update_subscription_by_id)
        self.subscriptions_page.update_all_requested.connect(self.update_all_subscriptions)
        self.subscriptions_page.delete_requested.connect(self.delete_subscription_by_id)

        self.routing_page.load_file_requested.connect(self.load_rules_file)
        self.routing_page.load_url_requested.connect(self.load_rules_url)
        self.routing_page.per_app_rule_requested.connect(self.add_per_app_rule)
        self.routing_page.rule_outbound_requested.connect(self.set_rule_set_outbound)
        self.routing_page.rule_enabled_requested.connect(self.set_rule_set_enabled)
        self.routing_page.rule_move_requested.connect(self.move_rule_set)
        self.routing_page.delete_rule_requested.connect(self.delete_rule_set)
        self.routing_page.clear_rules_requested.connect(self.clear_rule_sets)

        self.logs_page.clear_requested.connect(self.clear_log_window)
        self.logs_page.export_requested.connect(self.export_logs)
        self.activity_page.filters_changed.connect(lambda: self._schedule_activity_refresh(120))
        self.activity_page.route_rule_requested.connect(self.add_activity_route_rule)
        self.activity_page.clear_requested.connect(self.clear_domain_activity)
        self.about_page.check_update_requested.connect(self.check_app_update)
        self.settings_page.settings_changed.connect(self._schedule_settings_save)
        self.settings_page.reset_requested.connect(self.reset_all_app_data)

    def _schedule_settings_save(self) -> None:
        if self._closing:
            return
        self.settings_autosave_timer.start()

    def _flush_pending_settings_save(self) -> None:
        if self.settings_autosave_timer.isActive():
            self.settings_autosave_timer.stop()
            self.save_settings(restart_connected=False, show_success=False)

    def _post_init(self) -> None:
        self.logger.info("Приложение запущено. Данные: %s", paths.data_dir())
        if windows.is_admin() and not self.singbox.is_running():
            self._clear_firewall_kill_switch_safely()
        if self.settings.first_run:
            self._run_first_run_onboarding()
        if self.settings.auto_check_app_updates:
            QTimer.singleShot(1200, lambda: self.check_app_update(silent=True))
        if self.settings.auto_connect and self.profiles:
            self.connect_vpn()

    def _run_first_run_onboarding(self) -> None:
        dialog = OnboardingDialog(self.settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            result = dialog.onboarding_result()
        else:
            result = self._default_onboarding_result()
        self._apply_onboarding_result(result)
        self._run_onboarding_action(result.action)

    def _default_onboarding_result(self) -> OnboardingResult:
        return OnboardingResult(
            mode=self.settings.mode,
            auto_update_subscriptions=self.settings.auto_update_subscriptions,
            background_health_check_enabled=self.settings.background_health_check_enabled,
            minimize_to_tray=self.settings.minimize_to_tray,
            auto_start_windows=self.settings.auto_start_windows,
            action=ONBOARDING_ACTION_SKIP,
        )

    def _apply_onboarding_result(self, result: OnboardingResult) -> None:
        before_runtime = self._settings_runtime_key(self.settings)
        previous_auto_start = bool(self.settings.auto_start_windows)
        self.settings.mode = "tun" if result.mode == "tun" else "proxy"
        self.settings.auto_update_subscriptions = bool(result.auto_update_subscriptions)
        self.settings.background_health_check_enabled = bool(result.background_health_check_enabled)
        self.settings.minimize_to_tray = bool(result.minimize_to_tray)
        self.settings.auto_start_windows = bool(result.auto_start_windows)
        self.settings.first_run = False
        if previous_auto_start != self.settings.auto_start_windows:
            try:
                windows.set_autostart(self.settings.auto_start_windows)
            except Exception as exc:
                self.logger.error("Не удалось применить автозапуск Windows из onboarding: %s", sanitize_error_text(exc))
        app_state.save_settings(self.settings)
        self._start_subscription_scheduler()
        self._refresh_all_views()
        if before_runtime != self._settings_runtime_key(self.settings):
            self._restart_if_connected("Перезапуск после мастера первого запуска…")

    def _run_onboarding_action(self, action: str) -> None:
        if action == ONBOARDING_ACTION_IMPORT_SERVER:
            self.switchTo(self.servers_page)
            QTimer.singleShot(0, self.import_server_link)
            return
        if action == ONBOARDING_ACTION_ADD_SUBSCRIPTION:
            self.switchTo(self.subscriptions_page)
            QTimer.singleShot(0, self.add_subscription)
            return
        if action == ONBOARDING_ACTION_DOWNLOAD_CORE:
            self.switchTo(self.about_page)
            QTimer.singleShot(0, self.download_core)
            return
        if action == ONBOARDING_ACTION_OPEN_SETTINGS:
            self.switchTo(self.settings_page)

    def _refresh_all_views(self) -> None:
        self._rebuild_profile_index()
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        active = self._active_profile()
        active_id = active.id if active else None
        self.dashboard_page.set_profiles(self.profiles, active_id)
        self.dashboard_page.set_mode(self.settings.mode)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self.dashboard_page.set_rules_summary(self._rules_summary_line())
        self.servers_page.set_profiles(
            self.profiles,
            active_id,
            self.subscriptions,
            self.smart_connect.quality_stats,
            self.smart_connect.smart_groups,
            self.settings.smart_connect_enabled,
        )
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
        self.routing_page.set_rules(self.split_rules, self._rules_summary_text())
        self.settings_page.set_values(self.settings)
        self.about_page.set_core_version(self._core_version())
        self.logs_page.set_lines(self.log_buffer.snapshot("all"))
        self.domain_activity.refresh_routes(self.split_rules)
        self._refresh_activity_page()
        self._refresh_tray_text()

    def _refresh_server_views(self) -> None:
        self._rebuild_profile_index()
        active = self._active_profile()
        active_id = active.id if active else None
        self.dashboard_page.set_profiles(self.profiles, active_id)
        self.servers_page.set_profiles(
            self.profiles,
            active_id,
            self.subscriptions,
            self.smart_connect.quality_stats,
            self.smart_connect.smart_groups,
            self.settings.smart_connect_enabled,
        )

    def _refresh_servers_table(self) -> None:
        self._rebuild_profile_index()
        active = self._active_profile()
        active_id = active.id if active else None
        self.servers_page.set_profiles(
            self.profiles,
            active_id,
            self.subscriptions,
            self.smart_connect.quality_stats,
            self.smart_connect.smart_groups,
            self.settings.smart_connect_enabled,
        )

    def _subscription_profile_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for profile in self.profiles:
            if not profile.subscription_id:
                continue
            counts[profile.subscription_id] = counts.get(profile.subscription_id, 0) + 1
        return counts

    def _sync_subscription_profile_counts(self, *, save: bool) -> dict[str, int]:
        counts = self._subscription_profile_counts()
        changed = False
        for subscription in self.subscriptions:
            actual_count = counts.get(subscription.id, 0)
            if subscription.profile_count != actual_count:
                subscription.profile_count = actual_count
                changed = True
        if changed and save:
            app_state.save_subscriptions(self.subscriptions)
        return counts

    def _core_version(self, *, refresh: bool = False) -> str:
        if refresh or self._core_version_cache is None:
            self._core_version_cache = self.singbox.version()
        return self._core_version_cache

    def _active_profile(self) -> VlessProfile | None:
        if self.settings.active_profile_id:
            profile = self._profiles_by_id.get(self.settings.active_profile_id)
            if profile:
                return profile
        return self.profiles[0] if self.profiles else None

    def _rebuild_profile_index(self) -> None:
        self._profiles_by_id = {profile.id: profile for profile in self.profiles}

    def _profile_by_id(self, profile_id: str) -> VlessProfile | None:
        profile = self._profiles_by_id.get(profile_id)
        if profile is None and self.profiles:
            self._rebuild_profile_index()
            profile = self._profiles_by_id.get(profile_id)
        return profile

    def _subscription_by_id(self, subscription_id: str) -> Subscription | None:
        return next((item for item in self.subscriptions if item.id == subscription_id), None)

    def _rule_set_by_id(self, rule_set_id: str) -> RoutingRuleSet | None:
        return next((item for item in self.split_rules.rule_sets if item.id == rule_set_id), None)

    def _smart_group_by_id(self, group_id: str) -> SmartGroup | None:
        return next((item for item in self.smart_connect.smart_groups if item.id == group_id), None)

    def create_failover_group_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        members = self.smart_connect.group_profiles(profile, self.profiles)
        if len(members) < 2:
            self._show_status("warning", "Для failover-группы нужно минимум два сервера в одной группе")
            return
        group, members = self.smart_connect.create_or_update_failover_group(
            profile,
            self.profiles,
            name=self._failover_group_name(profile),
        )
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._refresh_servers_table()
        self._show_status("success", f"Failover-группа сохранена: {group.name} · серверов: {len(members)}")

    def edit_smart_group_by_id(self, group_id: str) -> None:
        group = self._smart_group_by_id(group_id)
        if not group:
            self._show_status("warning", "Группа не найдена")
            return
        dialog = SmartGroupEditorDialog(group, self.profiles, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.group_data()
        if data is None:
            return
        group.name = data.name
        group.enabled = data.enabled
        group.mode = data.mode
        group.strategy = data.strategy
        group.profile_ids = list(data.profile_ids)
        group.load_balance_interval = data.load_balance_interval
        group.load_balance_tolerance_ms = data.load_balance_tolerance_ms
        group.touch()
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._refresh_servers_table()
        self._show_status("success", f"Группа сохранена: {group.name}")

    def start_smart_group_by_id(self, group_id: str, *, reset_recovery_state: bool = True) -> None:
        group = self._smart_group_by_id(group_id)
        if not group:
            self._show_status("warning", "Группа не найдена")
            return
        if not group.enabled:
            self._show_status("warning", "Группа отключена")
            return
        mode = normalize_smart_group_mode(group.mode)
        if (self.settings.mode == "tun" or self.settings.firewall_kill_switch) and not windows.is_admin():
            reason = (
                "Для подключения группы с Firewall Kill Switch нужны права администратора."
                if self.settings.firewall_kill_switch
                else "Для подключения группы в TUN-режиме нужны права администратора."
            )
            self._request_admin_for_tun(reason)
            return
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return
        if reset_recovery_state:
            self._reset_self_healing_state()
        self.resilience.clear_manual_disconnect_requested()

        def worker() -> ConnectionStartResult:
            return self.connection_service.start_group(
                group,
                profiles=self.profiles,
                settings=self.settings,
                split_rules=self.split_rules,
                record_latency=self._set_profile_latency,
                save_profiles=self._save_profiles_now,
                save_quality_stats=self._save_quality_stats_now,
            )

        if mode == SMART_GROUP_MODE_LOAD_BALANCE:
            busy = "Load Balance…"
        elif mode == SMART_GROUP_MODE_FAILOVER:
            busy = "Подключение группы…"
        else:
            busy = "Multi-hop…"
        self._run_background(worker, self._finish_connection_start, busy=busy)

    def _failover_group_name(self, profile: VlessProfile) -> str:
        subscription = self._subscription_by_id(profile.subscription_id) if profile.subscription_id else None
        source_group = " ".join(str(profile.group or "").split())
        if subscription and source_group:
            return f"{subscription.name} / {source_group}"
        if subscription:
            return subscription.name
        if source_group:
            return f"Без подписки / {source_group}"
        return "Без подписки"

    def set_active_profile(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if self.settings.active_profile_id == profile_id:
            return
        was_running = self.singbox.is_running()
        self.settings.active_profile_id = profile_id
        app_state.save_settings(self.settings)
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile_id)
        self.dashboard_page.set_connection(self.singbox.is_running(), self._busy)
        self._refresh_tray_text()
        if was_running:
            self._start_or_restart_vpn(profile, "Переключение сервера…")

    def set_mode(self, mode: str) -> None:
        previous_mode = self.settings.mode
        next_mode = "tun" if mode == "tun" else "proxy"
        if next_mode == "tun" and not windows.is_admin():
            self.settings.mode = "tun"
            app_state.save_settings(self.settings)
            if self._request_admin_for_tun("Для включения TUN-режима нужны права администратора."):
                return
            self.settings.mode = previous_mode if previous_mode != "tun" else "proxy"
            app_state.save_settings(self.settings)
            self.dashboard_page.set_mode(self.settings.mode)
            return

        self.settings.mode = next_mode
        app_state.save_settings(self.settings)
        self.dashboard_page.set_mode(self.settings.mode)
        if previous_mode != next_mode:
            self._restart_if_connected("Перезапуск режима подключения…")

    def toggle_connection(self) -> None:
        if self.singbox.is_running():
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self) -> None:
        profile = self._active_profile()
        if not profile:
            self._show_status("warning", "Импортируйте сервер или подписку")
            return
        if (self.settings.mode == "tun" or self.settings.firewall_kill_switch) and not windows.is_admin():
            app_state.save_settings(self.settings)
            reason = (
                "Для подключения с Firewall Kill Switch нужны права администратора."
                if self.settings.firewall_kill_switch
                else "Для подключения в TUN-режиме нужны права администратора."
            )
            self._request_admin_for_tun(reason)
            return
        self._reset_self_healing_state()
        self.resilience.clear_manual_disconnect_requested()
        if self.settings.smart_connect_enabled:
            self._smart_connect_and_start(profile)
        else:
            self._direct_connect_and_start(profile)

    def _smart_connect_and_start(self, anchor_profile: VlessProfile) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return

        def worker() -> ConnectionStartResult:
            return self.connection_service.start_smart(
                anchor_profile,
                profiles=self.profiles,
                settings=self.settings,
                split_rules=self.split_rules,
                record_latency=self._set_profile_latency,
                save_profiles=self._save_profiles_now,
                save_quality_stats=self._save_quality_stats_now,
            )

        self._run_background(
            worker,
            self._finish_connection_start,
            busy="Smart Connect…",
        )

    def _direct_connect_and_start(self, profile: VlessProfile) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return

        def worker() -> ConnectionStartResult:
            return self.connection_service.start_direct(
                profile,
                settings=self.settings,
                split_rules=self.split_rules,
                save_quality_stats=self._save_quality_stats_now,
            )

        self._run_background(
            worker,
            self._finish_connection_start,
            busy="Подключение…",
        )

    def _select_smart_connect_profile(self, anchor_profile: VlessProfile) -> VlessProfile:
        return self.connection_service.select_smart_profile(
            anchor_profile,
            profiles=self.profiles,
            settings=self.settings,
            record_latency=self._set_profile_latency,
            save_profiles=self._save_profiles_now,
            save_quality_stats=self._save_quality_stats_now,
        )

    def _finish_connection_start(self, result: ConnectionStartResult) -> None:
        if result.group_id:
            self._finish_group_connection_start(result)
        else:
            self._finish_smart_connect(result.anchor_profile, result.selected_profile)

    def _finish_smart_connect(self, anchor_profile: VlessProfile, profile: VlessProfile) -> None:
        self.settings.active_profile_id = profile.id
        app_state.save_settings(self.settings)
        self._begin_failover_session(anchor_profile)
        self._refresh_server_views()
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile.id)
        self._connected_ui(profile)

    def _finish_group_connection_start(self, result: ConnectionStartResult) -> None:
        profile = result.selected_profile
        self.settings.active_profile_id = profile.id
        app_state.save_settings(self.settings)
        if normalize_smart_group_mode(result.group_mode) == SMART_GROUP_MODE_FAILOVER:
            self._begin_failover_session(result.anchor_profile)
        else:
            self._clear_failover_session()
        self._refresh_server_views()
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile.id)
        self._connected_ui(
            profile,
            display_name=result.display_name,
            profile_ids=result.profile_ids,
            group_id=result.group_id,
        )

    def _start_profile_core(self, profile: VlessProfile) -> None:
        self.connection_service.start_profile_core(
            profile,
            settings=self.settings,
            split_rules=self.split_rules,
        )

    def _enable_firewall_kill_switch(self) -> None:
        self.connection_service.enable_firewall_kill_switch()

    def _clear_firewall_kill_switch_safely(self) -> None:
        self.connection_service.clear_firewall_kill_switch_safely()

    def _start_or_restart_vpn(self, profile: VlessProfile, busy: str) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return
        def worker() -> None:
            self._start_profile_core(profile)

        self._run_background(worker, lambda _result: self._finish_manual_connection(profile), busy=busy)

    def _finish_manual_connection(self, profile: VlessProfile) -> None:
        self._begin_failover_session(profile)
        self._connected_ui(profile)

    def _restart_if_connected(self, busy: str) -> None:
        if not self.singbox.is_running():
            return
        active_group = self._active_smart_group()
        if active_group and normalize_smart_group_mode(active_group.mode) != SMART_GROUP_MODE_FAILOVER:
            self.start_smart_group_by_id(active_group.id, reset_recovery_state=False)
            return
        profile = self._active_profile()
        if not profile:
            return
        self._start_or_restart_vpn(profile, busy)

    def disconnect_vpn(self) -> None:
        self.resilience.mark_manual_disconnect_requested()
        self._reset_self_healing_state()
        def worker() -> None:
            self.connection_service.stop(self.settings)

        self._run_background(worker, lambda _result: self._disconnected_ui(), busy="Отключение…")

    def _connected_ui(
        self,
        profile: VlessProfile,
        *,
        display_name: str | None = None,
        profile_ids: tuple[str, ...] | None = None,
        group_id: str | None = None,
    ) -> None:
        self.resilience.on_connected()
        self.dashboard_page.set_connection(True)
        self._active_connection_profile_ids = tuple(profile_ids or (profile.id,))
        self._active_connection_group_id = group_id
        self._active_connection_started_at_iso = utc_now_iso()
        self._active_connection_started_monotonic = time.monotonic()
        self.traffic.reset()
        self.dashboard_page.clear_graph()
        self._refresh_tray_text()
        name = display_name or profile.name
        self._show_status("success", f"Подключено: {name}")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", f"Подключено: {name}")

    def _disconnected_ui(self) -> None:
        self._record_active_connection_usage()
        self.resilience.on_disconnected()
        self.dashboard_page.set_connection(False)
        self._refresh_tray_text()
        self._show_status("info", "Соединение остановлено")
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", "Соединение остановлено")

    def _begin_failover_session(self, anchor_profile: VlessProfile) -> None:
        self.resilience.begin_failover_session(anchor_profile)

    def _clear_failover_session(self) -> None:
        self.resilience.clear_failover_session()

    def _active_smart_group(self) -> SmartGroup | None:
        if not self._active_connection_group_id:
            return None
        return self._smart_group_by_id(self._active_connection_group_id)

    def _record_active_connection_usage(self) -> None:
        if not self._active_connection_profile_ids or self._active_connection_started_monotonic is None:
            return
        sample = self.traffic.sample(active=False)
        connected_seconds = max(0, int(time.monotonic() - self._active_connection_started_monotonic))
        download_bytes = max(0, int(sample.total_download))
        upload_bytes = max(0, int(sample.total_upload))
        connected_at = self._active_connection_started_at_iso
        disconnected_at = utc_now_iso()
        profile_ids = tuple(profile_id for profile_id in self._active_connection_profile_ids if profile_id)
        group = self._active_smart_group()

        if group:
            group.record_usage(
                connected_seconds=connected_seconds,
                download_bytes=download_bytes,
                upload_bytes=upload_bytes,
                connected_at=connected_at,
                disconnected_at=disconnected_at,
            )
            if normalize_smart_group_mode(group.mode) == SMART_GROUP_MODE_LOAD_BALANCE and profile_ids:
                per_profile_download = download_bytes // len(profile_ids)
                per_profile_upload = upload_bytes // len(profile_ids)
            else:
                per_profile_download = download_bytes
                per_profile_upload = upload_bytes
        else:
            per_profile_download = download_bytes
            per_profile_upload = upload_bytes

        for profile_id in profile_ids:
            self.smart_connect.record_usage(
                profile_id,
                connected_seconds=connected_seconds,
                download_bytes=per_profile_download,
                upload_bytes=per_profile_upload,
                connected_at=connected_at,
                disconnected_at=disconnected_at,
            )
        app_state.save_quality_stats(self.smart_connect.quality_stats)
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._active_connection_profile_ids = ()
        self._active_connection_group_id = None
        self._active_connection_started_at_iso = None
        self._active_connection_started_monotonic = None

    def _should_auto_failover(self) -> bool:
        return self.resilience.should_auto_failover(busy=self._busy, closing=self._closing)

    def _start_failover_after_drop(self, failed_profile: VlessProfile) -> None:
        if not self.resilience.begin_failover_after_drop(
            failed_profile,
            busy=self._busy,
            closing=self._closing,
            save_quality_stats=self._save_quality_stats_now,
        ):
            return

        def worker() -> FailoverAttemptResult:
            try:
                return self._run_failover_attempt(failed_profile)
            except Exception as exc:
                message = format_user_error(exc, context="Failover")
                self.logger.error("Failover failed: %s\n%s", message.display_text, format_safe_traceback(exc))
                return FailoverAttemptResult(None, message.display_text)

        self._run_background(worker, self._finish_failover_attempt, busy="Failover…")

    def _run_failover_attempt(self, failed_profile: VlessProfile) -> FailoverAttemptResult:
        return self.resilience.run_failover_attempt(
            failed_profile,
            profiles=self.profiles,
            settings=self.settings,
            split_rules=self.split_rules,
            profile_lookup=self._profile_by_id,
            record_latency=self._set_profile_latency,
            save_profiles=self._save_profiles_now,
            save_quality_stats=self._save_quality_stats_now,
        )

    def _finish_failover_attempt(self, result: FailoverAttemptResult) -> None:
        self.resilience.finish_failover_attempt()
        profile, error = result.profile, result.error
        if profile:
            self.settings.active_profile_id = profile.id
            app_state.save_settings(self.settings)
            self._refresh_server_views()
            self.dashboard_page.set_active_profile(profile)
            self.servers_page.set_active_id(profile.id)
            self._connected_ui(profile)
            self._show_status("success", f"Failover: переключено на {profile.name}")
            return

        self._handle_unrecoverable_connection_failure(error or "Failover: нет доступного сервера")

    def _maybe_run_background_health_check(self, now: int, running: bool) -> None:
        profile = self.resilience.start_health_check_if_due(
            now=now,
            running=running,
            settings=self.settings,
            busy=self._busy,
            closing=self._closing,
            active_profile=self._active_profile(),
        )
        if not profile:
            return
        settings_snapshot = AppSettings.from_dict(self.settings.to_dict())

        def worker() -> ConnectivityCheckResult:
            return self.singbox.check_current_connectivity(settings_snapshot)

        self._run_background(
            worker,
            lambda result, profile_id=profile.id: self._finish_background_health_check(profile_id, result),
            set_busy=False,
        )

    def _finish_background_health_check(self, profile_id: str, result: ConnectivityCheckResult) -> None:
        profile = self._profile_by_id(profile_id)
        outcome = self.resilience.handle_health_check_result(
            profile,
            result,
            running=self.singbox.is_running(),
            closing=self._closing,
            settings=self.settings,
            record_latency=self._set_profile_latency,
            save_profiles=self._save_profiles_now,
            save_quality_stats=self._save_quality_stats_now,
        )
        if outcome.status == HEALTH_STATUS_OK:
            self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
            self.servers_page.update_latency_cells(list(outcome.changed_profile_ids))
            return
        if outcome.status not in {HEALTH_STATUS_FAILED, HEALTH_STATUS_RECOVER}:
            return

        self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
        self.servers_page.update_latency_cells(list(outcome.changed_profile_ids))
        if outcome.status == HEALTH_STATUS_RECOVER and profile:
            self._recover_unhealthy_connection(profile, outcome.reason)

    def _recover_unhealthy_connection(self, profile: VlessProfile, reason: str) -> None:
        active_group = self._active_smart_group()
        if active_group and normalize_smart_group_mode(active_group.mode) != SMART_GROUP_MODE_FAILOVER:
            self.logger.warning("Health monitor: переподключаю группу %s: %s", active_group.name, reason)
            self.start_smart_group_by_id(active_group.id, reset_recovery_state=False)
            return
        plan = self.resilience.plan_health_recovery(
            profile,
            reason,
            settings=self.settings,
            profiles=self.profiles,
            profile_lookup=self._profile_by_id,
            busy=self._busy,
            closing=self._closing,
        )
        if plan.action == RECOVERY_ACTION_FAILOVER:
            self._show_status("warning", f"Health monitor: соединение нестабильно, переключаю сервер. {sanitize_error_text(plan.reason)}")
            self._start_failover_after_drop(profile)
            return
        if plan.action == RECOVERY_ACTION_RESTART:
            self._restart_unhealthy_profile(profile, plan.reason)
            return

    def _restart_unhealthy_profile(self, profile: VlessProfile, reason: str) -> None:
        if self._busy:
            return
        self.logger.warning("Health monitor: переподключаю текущий сервер %s: %s", profile.name, reason)

        def worker() -> FailoverAttemptResult:
            return self.resilience.run_health_reconnect(
                profile,
                settings=self.settings,
                split_rules=self.split_rules,
                save_quality_stats=self._save_quality_stats_now,
            )

        self._run_background(worker, self._finish_health_reconnect, busy="Восстановление подключения…")

    def _finish_health_reconnect(self, result: FailoverAttemptResult) -> None:
        profile, error = result.profile, result.error
        if profile:
            self.settings.active_profile_id = profile.id
            app_state.save_settings(self.settings)
            self._begin_failover_session(profile)
            self._refresh_server_views()
            self.dashboard_page.set_active_profile(profile)
            self.servers_page.set_active_id(profile.id)
            self._connected_ui(profile)
            self._show_status("success", f"Health monitor: подключение восстановлено: {profile.name}")
            return

        self._handle_unrecoverable_connection_failure(f"Health monitor: переподключение не удалось: {error}")

    def _handle_unexpected_core_stop(self) -> None:
        failed_profile = self._active_profile()
        active_group = self._active_smart_group()
        reason = sanitize_error_text(self.singbox.last_runtime_error())
        self.singbox.mark_stopped_if_exited()
        self.resilience.mark_core_stopped()
        self.logger.warning("Watchdog: sing-box остановился вне ручного отключения: %s", reason)
        if not failed_profile:
            self._handle_unrecoverable_connection_failure("sing-box остановился, но активный профиль не найден")
            return
        if not self._should_self_heal_after_drop(failed_profile):
            self._handle_unrecoverable_connection_failure(reason)
            return
        decision = self.resilience.register_self_healing_attempt(self.settings, reason)
        if not decision.allowed:
            if decision.message:
                self._show_status("error", decision.message)
            self._handle_unrecoverable_connection_failure(reason)
            return
        self._show_status("warning", f"Watchdog: sing-box остановился, восстанавливаю подключение. {reason}")
        if active_group and normalize_smart_group_mode(active_group.mode) != SMART_GROUP_MODE_FAILOVER:
            self.start_smart_group_by_id(active_group.id, reset_recovery_state=False)
            return
        self._recover_unhealthy_connection(failed_profile, reason)

    def _should_self_heal_after_drop(self, profile: VlessProfile | None) -> bool:
        return self.resilience.should_self_heal_after_drop(
            profile,
            settings=self.settings,
            busy=self._busy,
            closing=self._closing,
        )

    def _register_self_healing_attempt(self, reason: str) -> bool:
        decision = self.resilience.register_self_healing_attempt(self.settings, reason)
        if decision.message:
            self._show_status("error", decision.message)
        return decision.allowed

    def _reset_self_healing_state(self) -> None:
        self.resilience.reset_self_healing_state()

    def _handle_unrecoverable_connection_failure(self, message: str) -> None:
        self._record_active_connection_usage()
        self.resilience.mark_unrecoverable_failure()
        self._clear_proxy_guard_safely()
        self.dashboard_page.set_connection(False)
        self._refresh_tray_text()
        message = sanitize_error_text(message)
        if self.settings.firewall_kill_switch:
            message = f"{message}. Firewall Kill Switch оставлен включенным в fail-closed режиме."
        self._show_status("error", message)
        if self.settings.show_notifications:
            windows.show_toast("Razreshenie VPN", "Подключение не восстановлено")

    def _clear_proxy_guard_safely(self) -> None:
        if not self.settings.enable_system_proxy_guard:
            return
        try:
            windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
        except Exception as exc:
            self.logger.error("Не удалось отключить Windows proxy guard после сбоя: %s", sanitize_error_text(exc))

    def _self_healing_max_attempts(self) -> int:
        return self.resilience.self_healing_max_attempts(self.settings)

    def _self_healing_cooldown_seconds(self) -> int:
        return self.resilience.self_healing_cooldown_seconds(self.settings)

    def _background_health_interval_seconds(self) -> int:
        return self.resilience.background_health_interval_seconds(self.settings)

    def _background_health_failure_threshold(self) -> int:
        return self.resilience.background_health_failure_threshold(self.settings)

    def _request_admin_for_tun(self, reason: str) -> bool:
        if windows.is_admin():
            return True
        self.logger.info("%s Запрашиваю повышенные права через Windows UAC.", reason)
        self._show_status("info", f"{reason} Сейчас откроется запрос Windows UAC.")
        if windows.relaunch_as_admin():
            QTimer.singleShot(250, self.exit_app)
            return True
        self._show_status("error", "Windows не выдала права администратора или запрос был отменен")
        return False

    def import_server_link(self) -> None:
        value, ok = QInputDialog.getMultiLineText(
            self,
            "Импорт серверов",
            "Вставьте ссылки, base64-подписку, Clash YAML/JSON или sing-box JSON",
        )
        if not ok or not value.strip():
            return
        sources = self._text_import_sources(value)

        def worker() -> tuple[list[VlessProfile], str]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Импорт {event.current}/{event.total}: {event.source}",
                    )
                )

            profiles = self.subscription_manager.parse_many(sources, progress_callback=progress)
            return profiles, "из текста"

        self._run_background(
            worker,
            lambda result: self._apply_imported_profiles(result[0], result[1]),
            busy="Импорт серверов…",
        )

    def import_server_files(self) -> None:
        file_names, _ = QFileDialog.getOpenFileNames(
            self,
            "Импорт серверов из файлов",
            "",
            "Подписки (*.txt *.json *.yaml *.yml);;TXT (*.txt);;JSON (*.json);;YAML (*.yaml *.yml);;Все файлы (*.*)",
        )
        if not file_names:
            return
        file_paths = [Path(file_name) for file_name in file_names]

        def worker() -> tuple[list[VlessProfile], str]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Импорт {event.current}/{event.total}: {Path(event.source).name}",
                    )
                )

            profiles = self.subscription_manager.parse_files(file_paths, progress_callback=progress)
            return profiles, "из файлов"

        self._run_background(
            worker,
            lambda result: self._apply_imported_profiles(result[0], result[1]),
            busy="Импорт файлов…",
        )

    def _text_import_sources(self, text: str) -> list[tuple[str, str]]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) > 1 and all("://" in line for line in lines):
            return [(f"строка {index}", line) for index, line in enumerate(lines, start=1)]
        return [("вставленный текст", text)]

    def _apply_imported_profiles(self, profiles: list[VlessProfile], source_label: str) -> None:
        if not profiles:
            self._show_status("warning", "Серверы не импортированы")
            return
        self.profiles.extend(profiles)
        self.settings.active_profile_id = profiles[0].id
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()
        self._show_status("success", f"Импортировано {len(profiles)} серверов {source_label}")

    def edit_profile_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        dialog = JsonEditorDialog("Редактирование профиля", profile.to_dict(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = VlessProfile.from_dict(dialog.data())
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._show_status("error", format_user_error(exc, context="Редактирование профиля").display_text)
            return
        updated.touch()
        self.profiles = [updated if item.id == profile_id else item for item in self.profiles]
        app_state.save_profiles(self.profiles)
        self._refresh_all_views()

    def delete_profile_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if QMessageBox.question(self, "Удалить профиль", f"Удалить {profile.name}?") != QMessageBox.StandardButton.Yes:
            return
        self.profiles = [item for item in self.profiles if item.id != profile_id]
        if self.settings.active_profile_id == profile_id:
            self.settings.active_profile_id = self.profiles[0].id if self.profiles else None
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()

    def test_profile_latency_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        self._start_latency_scan((profile,))

    def test_all_latencies(self) -> None:
        self._start_latency_scan(self.profiles)

    def _start_latency_scan(self, profiles: tuple[VlessProfile, ...] | list[VlessProfile]) -> None:
        if self._latency_scan_running or self.latency_scanner.is_running:
            self._show_status("info", "Проверка отклика уже выполняется")
            return
        if not profiles:
            self._show_status("warning", "Сначала импортируйте серверы")
            return

        total_profiles = len(profiles)
        self._latency_result_queue.clear()
        self._pending_latency_summary = None
        self._latency_scan_running = True
        self._latency_scan_total = total_profiles
        self._latency_scan_completed = 0
        self.servers_page.set_latency_busy(True)
        self.servers_page.set_latency_progress(0, total_profiles)

        def on_batch(results: list[tuple[str, int | None]]) -> None:
            self.bridge.call.emit(lambda results=results: self._queue_latency_results(results))

        def on_done(summary: LatencyScanSummary) -> None:
            self.bridge.call.emit(lambda summary=summary: self._queue_latency_finish(summary))

        def on_error(exc: Exception) -> None:
            self.bridge.call.emit(lambda exc=exc: self._fail_latency_scan(exc))

        started = self.latency_scanner.scan_profiles(
            profiles,
            settings=self.settings,
            on_batch=on_batch,
            on_done=on_done,
            on_error=on_error,
        )
        if not started:
            self._latency_scan_running = False
            self._latency_scan_total = 0
            self._latency_scan_completed = 0
            self._pending_latency_summary = None
            self._latency_result_queue.clear()
            self.servers_page.set_latency_busy(False)
            self._show_status("info", "Проверка отклика уже выполняется")

    def _queue_latency_results(self, results: list[tuple[str, int | None]]) -> None:
        self._latency_result_queue.extend(results)
        if not self.latency_result_timer.isActive():
            self.latency_result_timer.start()

    def _queue_latency_finish(self, summary: LatencyScanSummary) -> None:
        self._pending_latency_summary = summary
        if not self.latency_result_timer.isActive():
            self.latency_result_timer.start()

    def _drain_latency_result_queue(self) -> None:
        if not self._latency_result_queue:
            self.latency_result_timer.stop()
            if self._pending_latency_summary is not None:
                summary = self._pending_latency_summary
                self._pending_latency_summary = None
                self._finish_latency_scan(summary)
            return

        batch: list[tuple[str, int | None]] = []
        while self._latency_result_queue and len(batch) < LATENCY_UI_DRAIN_LIMIT:
            batch.append(self._latency_result_queue.popleft())
        self._apply_latency_result_batch(batch)

    def _apply_latency_result_batch(self, results: list[tuple[str, int | None]]) -> None:
        changed_ids: list[str] = []
        checked_at = utc_now_iso()
        for profile_id, latency in results:
            if self._set_profile_latency(profile_id, latency, checked_at):
                changed_ids.append(profile_id)
        self._latency_scan_completed = min(self._latency_scan_total, self._latency_scan_completed + len(results))
        self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
        self.servers_page.update_latency_cells(changed_ids)
        self.servers_page.set_latency_progress(self._latency_scan_completed, self._latency_scan_total)

    def _finish_latency_scan(self, summary: LatencyScanSummary) -> None:
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self.servers_page.set_latency_busy(False)
        self._save_profiles_background()
        if summary.cancelled:
            self._show_status("info", "Проверка отклика остановлена")
            return
        self._show_status(
            "success",
            (
                f"Проверено: {summary.total_profiles}, успешно: {summary.successful_profiles}, "
                f"таймаутов: {summary.timeout_profiles}"
            ),
        )

    def _fail_latency_scan(self, exc: Exception) -> None:
        self._latency_scan_running = False
        self._latency_scan_total = 0
        self._latency_scan_completed = 0
        self._pending_latency_summary = None
        self._latency_result_queue.clear()
        if self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        self.servers_page.set_latency_busy(False)
        self._show_status("error", format_user_error(exc, context="Проверка отклика").display_text)

    def _set_profile_latency(
        self,
        profile_id: str,
        latency: int | None,
        checked_at: str | None = None,
    ) -> VlessProfile | None:
        profile = self._profile_by_id(profile_id)
        if profile:
            profile.latency_ms = latency
            timestamp = checked_at or utc_now_iso()
            profile.latency_checked_at = timestamp
            profile.updated_at = timestamp
            self.smart_connect.record_latency(profile_id, latency, checked_at=timestamp)
        return profile

    def _save_profiles_now(self) -> None:
        app_state.save_profiles(self.profiles)

    def _save_quality_stats_now(self) -> None:
        app_state.save_quality_stats(self.smart_connect.quality_stats)

    def _save_profiles_background(self) -> None:
        snapshot = list(self.profiles)
        quality_snapshot = dict(self.smart_connect.quality_stats)

        def worker() -> None:
            try:
                app_state.save_profiles(snapshot)
                app_state.save_quality_stats(quality_snapshot)
            except Exception as exc:
                self.logger.error("Не удалось сохранить профили после проверки отклика: %s", sanitize_error_text(exc))

        threading.Thread(target=worker, name="RazreshenieProfileSave", daemon=True).start()

    def sort_profiles_by_latency(self) -> None:
        self.profiles.sort(key=lambda item: (item.latency_ms is None, item.latency_ms or 10**9, item.name.lower()))
        app_state.save_profiles(self.profiles)
        self._refresh_server_views()

    def add_subscription(self) -> None:
        url, ok = QInputDialog.getText(self, "Добавить подписку", "URL подписки")
        if not ok or not url.strip():
            return
        parsed = urlparse(url.strip())
        subscription = Subscription(
            name=parsed.netloc or "Подписка",
            url=url.strip(),
            update_interval_hours=self.settings.subscription_update_interval_hours,
        )
        self.subscriptions.append(subscription)
        app_state.save_subscriptions(self.subscriptions)
        self._refresh_all_views()
        self.update_subscription(subscription)

    def update_subscription_by_id(self, subscription_id: str) -> None:
        subscription = self._subscription_by_id(subscription_id)
        if subscription:
            self.update_subscription(subscription)

    def update_subscription(self, subscription: Subscription) -> None:
        self._sync_subscription_profile_counts(save=True)

        def worker() -> SubscriptionFetchResult:
            try:
                profiles, updated_subscription = self.subscription_manager.fetch(subscription)
            except Exception as exc:
                message = format_user_error(exc, context="Подписка").display_text
                subscription.last_error = message
                return SubscriptionFetchResult(subscription=subscription, error=message)
            return SubscriptionFetchResult(subscription=updated_subscription, profiles=profiles)

        self.subscriptions_page.set_update_busy(True)
        self._run_background(worker, self._finish_subscription_update, busy="Обновление подписки…")

    def _finish_subscription_update(self, result: SubscriptionFetchResult) -> None:
        try:
            if result.success:
                self._apply_subscription_update(result.subscription, result.profiles)
            else:
                message = format_user_error(result.error or "ошибка обновления", context="Подписка").display_text
                self._record_subscription_error(result.subscription, message)
                self._show_status("error", message)
        finally:
            self.subscriptions_page.set_update_busy(False)

    def _apply_subscription_update(
        self,
        subscription: Subscription,
        profiles: list[VlessProfile],
        *,
        show_status: bool = True,
    ) -> None:
        subscription_counts = self._merge_subscription_update(subscription, profiles)
        self._save_subscription_state()
        self._refresh_server_views()
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
        self._refresh_tray_text()
        if show_status:
            self._show_status("success", f"Подписка обновлена: {subscription.name} · серверов: {subscription.profile_count}")

    def _merge_subscription_update(self, subscription: Subscription, profiles: list[VlessProfile]) -> dict[str, int]:
        active_before = self._active_profile()
        active_key = self.subscription_manager.profile_key(active_before) if active_before else None
        old_subscription_profiles = [profile for profile in self.profiles if profile.subscription_id == subscription.id]
        other_profiles = [profile for profile in self.profiles if profile.subscription_id != subscription.id]
        merged_profiles = self._merge_subscription_profiles(old_subscription_profiles, profiles)
        subscription.profile_count = len(merged_profiles)
        self.profiles = other_profiles + merged_profiles
        self.subscriptions = [subscription if item.id == subscription.id else item for item in self.subscriptions]
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        if active_key and not any(profile.id == self.settings.active_profile_id for profile in self.profiles):
            restored = next((profile for profile in merged_profiles if self.subscription_manager.profile_key(profile) == active_key), None)
            self.settings.active_profile_id = restored.id if restored else ""
        if not self.settings.active_profile_id and self.profiles:
            self.settings.active_profile_id = self.profiles[0].id
        return subscription_counts

    def _record_subscription_error(self, subscription: Subscription, error: str) -> None:
        subscription.last_error = error
        self.subscriptions = [subscription if item.id == subscription.id else item for item in self.subscriptions]
        subscription_counts = self._sync_subscription_profile_counts(save=False)
        app_state.save_subscriptions(self.subscriptions)
        self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)

    def _save_subscription_state(self) -> None:
        app_state.save_profiles(self.profiles)
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_settings(self.settings)

    def _merge_subscription_profiles(
        self,
        existing_profiles: list[VlessProfile],
        incoming_profiles: list[VlessProfile],
    ) -> list[VlessProfile]:
        existing_by_key: dict[str, deque[VlessProfile]] = {}
        for profile in existing_profiles:
            key = self.subscription_manager.profile_key(profile)
            existing_by_key.setdefault(key, deque()).append(profile)

        merged: list[VlessProfile] = []

        for incoming in incoming_profiles:
            key = self.subscription_manager.profile_key(incoming)
            existing_profiles_for_key = existing_by_key.get(key)
            existing = existing_profiles_for_key.popleft() if existing_profiles_for_key else None
            if existing is not None:
                incoming.id = existing.id
                incoming.created_at = existing.created_at
                incoming.latency_ms = existing.latency_ms
                incoming.latency_checked_at = existing.latency_checked_at
            merged.append(incoming)

        return merged

    def update_all_subscriptions(self) -> None:
        subscriptions = [subscription for subscription in list(self.subscriptions) if subscription.enabled]
        if not subscriptions:
            self._show_status("warning", "Нет включенных подписок")
            return
        self._sync_subscription_profile_counts(save=True)

        def worker() -> list[SubscriptionFetchResult]:
            def progress(event) -> None:
                self.bridge.call.emit(
                    lambda event=event: self._show_status(
                        "info",
                        f"Обновление {event.current}/{event.total}: {event.subscription.name}",
                    )
                )

            return self.subscription_manager.fetch_many(subscriptions, progress_callback=progress)

        self.subscriptions_page.set_update_busy(True)
        self._run_background(worker, self._apply_subscription_batch_update, busy="Обновление подписок…")

    def _apply_subscription_batch_update(self, results: list[SubscriptionFetchResult]) -> None:
        try:
            updated = 0
            failed: list[str] = []
            subscription_counts: dict[str, int] = self._subscription_profile_counts()
            for result in results:
                if result.success:
                    subscription_counts = self._merge_subscription_update(result.subscription, result.profiles)
                    updated += 1
                else:
                    failed.append(result.subscription.name)
                    result.subscription.last_error = format_user_error(
                        result.error or "ошибка обновления",
                        context="Подписка",
                    ).display_text
                    self.subscriptions = [
                        result.subscription if item.id == result.subscription.id else item
                        for item in self.subscriptions
                    ]

            subscription_counts = self._sync_subscription_profile_counts(save=False)
            self._save_subscription_state()
            self._refresh_server_views()
            self.subscriptions_page.set_subscriptions(self.subscriptions, subscription_counts)
            self._refresh_tray_text()
            if failed:
                self._show_status("warning", f"Обновлено: {updated}, ошибок: {len(failed)}")
            else:
                self._show_status("success", f"Обновлено подписок: {updated}")
        finally:
            self.subscriptions_page.set_update_busy(False)

    def delete_subscription_by_id(self, subscription_id: str) -> None:
        subscription = self._subscription_by_id(subscription_id)
        if not subscription:
            return
        if QMessageBox.question(self, "Удалить подписку", f"Удалить {subscription.name} и ее профили?") != QMessageBox.StandardButton.Yes:
            return
        self.subscriptions = [item for item in self.subscriptions if item.id != subscription_id]
        self.profiles = [profile for profile in self.profiles if profile.subscription_id != subscription_id]
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_profiles(self.profiles)
        self._refresh_all_views()

    def load_rules_file(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Загрузить правила",
            "",
            "Правила (*.json *.txt *.srs);;SRS (*.srs);;JSON (*.json);;TXT (*.txt);;Все файлы (*.*)",
        )
        if not file_name:
            return
        path = Path(file_name)
        default_outbound = ROUTE_OUTBOUND_DIRECT if path.suffix.lower() in {".txt", ".srs"} else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.import_file(path, default_outbound))

    def load_rules_url(self) -> None:
        url, ok = QInputDialog.getText(self, "Загрузка правил", "URL на JSON, TXT или SRS")
        if not ok or not url.strip():
            return
        parsed = urlparse(url.strip())
        default_outbound = ROUTE_OUTBOUND_DIRECT if Path(parsed.path).suffix.lower() in {".txt", ".srs"} else ROUTE_OUTBOUND_PROXY
        self._load_rules(lambda: self.rules_manager.import_url(url.strip(), default_outbound))

    def add_per_app_rule(self) -> None:
        dialog = PerAppRuleDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.rule_data()
        if not data:
            self._show_status("warning", "Не удалось создать правило приложения")
            return

        normalized_rule = self._build_per_app_rule(data.name, data.outbound, data.match_kind, data.value)
        if not normalized_rule:
            self._show_status("warning", "Не удалось нормализовать правило приложения")
            return

        existing = self._find_per_app_rule(data.match_kind, data.value)
        if existing:
            self._apply_per_app_match(existing, data.match_kind, data.value)
            existing.name = data.name
            existing.outbound = normalize_outbound(data.outbound)
            existing.enabled = True
            existing.source_type = PER_APP_RULE_SOURCE_TYPE
            existing.source = PER_APP_RULE_SOURCE
            target_rule = RoutingRuleSet.from_dict(existing.to_dict())
            self.split_rules.rule_sets = [
                target_rule if item.id == existing.id else item
                for item in self.split_rules.rule_sets
            ]
            status = "обновлено"
        else:
            self.split_rules.rule_sets.append(normalized_rule)
            target_rule = normalized_rule
            status = "создано"

        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(target_rule.id)
        self._show_status("success", f"Per-app routing: {status}: {target_rule.name} -> {target_rule.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _build_per_app_rule(self, name: str, outbound: str, match_kind: str, value: str) -> RoutingRuleSet | None:
        rule_set = RoutingRuleSet(
            name=name,
            enabled=True,
            outbound=normalize_outbound(outbound),
            source_type=PER_APP_RULE_SOURCE_TYPE,
            source=PER_APP_RULE_SOURCE,
            priority=self._next_rule_priority(),
        )
        if not self._apply_per_app_match(rule_set, match_kind, value):
            return None
        normalized = RoutingRuleSet.from_dict(rule_set.to_dict())
        return normalized if not normalized.is_empty else None

    @staticmethod
    def _apply_per_app_match(rule_set: RoutingRuleSet, match_kind: str, value: str) -> bool:
        clean_value = str(value or "").strip()
        if not clean_value:
            return False
        rule_set.process_name = []
        rule_set.process_path = []
        rule_set.process_path_regex = []
        if match_kind == MATCH_KIND_PROCESS_NAME:
            rule_set.process_name = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH:
            rule_set.process_path = [clean_value]
        elif match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            rule_set.process_path_regex = [clean_value]
        else:
            return False
        return True

    def _find_per_app_rule(self, match_kind: str, value: str) -> RoutingRuleSet | None:
        target = str(value or "").strip().casefold()
        if not target:
            return None
        for rule_set in self.split_rules.rule_sets:
            if rule_set.source_type != PER_APP_RULE_SOURCE_TYPE:
                continue
            values = self._per_app_values(rule_set, match_kind)
            if target in {item.casefold() for item in values}:
                return rule_set
        return None

    @staticmethod
    def _per_app_values(rule_set: RoutingRuleSet, match_kind: str) -> list[str]:
        if match_kind == MATCH_KIND_PROCESS_NAME:
            return rule_set.process_name
        if match_kind == MATCH_KIND_PROCESS_PATH:
            return rule_set.process_path
        if match_kind == MATCH_KIND_PROCESS_PATH_REGEX:
            return rule_set.process_path_regex
        return []

    def _load_rules(self, loader: Callable[[], RulesImportResult]) -> None:
        try:
            result = loader()
        except RulesImportError as exc:
            self._show_status("error", format_user_error(exc, context="Маршрутизация").display_text)
            return
        if not result.rule_sets:
            self._show_status("error", "Импорт не вернул правил маршрутизации")
            return
        self._append_rule_set_resources(result.rule_set_resources)
        for rule_set in result.rule_sets:
            rule_set.priority = self._next_rule_priority()
            self.split_rules.rule_sets.append(rule_set)
        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(result.rule_sets[0].id)
        resource_count = len(result.rule_set_resources)
        resource_text = f" · resources: {resource_count}" if resource_count else ""
        item_count = sum(rule_set.total_items for rule_set in result.rule_sets)
        self._show_status("success", f"Добавлены правила: {len(result.rule_sets)} · элементов: {item_count}{resource_text}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _append_rule_set_resources(self, resources: list[RouteRuleSetResource]) -> None:
        if not resources:
            return
        by_tag = {resource.tag: resource for resource in self.split_rules.rule_set_resources if resource.tag}
        for resource in resources:
            if not resource.tag:
                continue
            by_tag[resource.tag] = resource
        self.split_rules.rule_set_resources = list(by_tag.values())

    def _next_rule_priority(self) -> int:
        if not self.split_rules.rule_sets:
            return 1000
        return max((rule_set.priority for rule_set in self.split_rules.rule_sets), default=990) + 10

    def set_rule_set_outbound(self, rule_set_id: str, outbound: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.outbound = normalize_outbound(outbound)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._show_status("success", f"{rule_set.name}: {rule_set.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def set_rule_set_enabled(self, rule_set_id: str, enabled: bool) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = bool(enabled)
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def toggle_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        rule_set.enabled = not rule_set.enabled
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def move_rule_set(self, rule_set_id: str, direction: int) -> None:
        ordered = self._ordered_rule_sets()
        current_index = next((index for index, item in enumerate(ordered) if item.id == rule_set_id), None)
        if current_index is None:
            return
        target_index = current_index + int(direction)
        if target_index < 0 or target_index >= len(ordered):
            return
        ordered[current_index], ordered[target_index] = ordered[target_index], ordered[current_index]
        self.split_rules.rule_sets = ordered
        self._renumber_rule_priorities()
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(rule_set_id)
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _ordered_rule_sets(self) -> list[RoutingRuleSet]:
        return [item for _index, item in sorted(enumerate(self.split_rules.rule_sets), key=lambda pair: (pair[1].priority, pair[0]))]

    def _renumber_rule_priorities(self) -> None:
        for index, rule_set in enumerate(self.split_rules.rule_sets, start=1):
            rule_set.priority = index * 10

    def delete_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        if QMessageBox.question(self, "Удалить правила", f"Удалить {rule_set.name}?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules.rule_sets = [item for item in self.split_rules.rule_sets if item.id != rule_set_id]
        self._prune_unused_rule_set_resources()
        self.split_rules.enabled = any(item.enabled for item in self.split_rules.rule_sets)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _prune_unused_rule_set_resources(self) -> None:
        used_tags = {
            tag
            for rule_set in self.split_rules.rule_sets
            for tag in rule_set.rule_set_tags
        }
        self.split_rules.rule_set_resources = [
            resource
            for resource in self.split_rules.rule_set_resources
            if resource.tag in used_tags
        ]

    def clear_rule_sets(self) -> None:
        if not self.split_rules.rule_sets and not self.split_rules.rule_set_resources:
            return
        if QMessageBox.question(self, "Очистить маршрутизацию", "Удалить все наборы правил маршрутизации?") != QMessageBox.StandardButton.Yes:
            return
        self.split_rules = SplitRules(enabled=False)
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self._restart_if_connected("Перезапуск маршрутизации…")

    def add_activity_route_rule(self, domain: str, match_kind: str, outbound: str) -> None:
        clean_domain = self._normalize_activity_domain(domain)
        if not clean_domain:
            self._show_status("warning", "Не удалось создать правило: домен не распознан")
            return

        normalized_outbound = normalize_outbound(outbound)
        rule_set, created = self._activity_rule_set(normalized_outbound)
        target_values, rule_value, label = self._activity_rule_target(rule_set, clean_domain, match_kind)
        was_enabled = rule_set.enabled and self.split_rules.enabled
        if rule_value.lower() in {item.lower() for item in target_values}:
            if not was_enabled:
                rule_set.enabled = True
                rule_set.outbound = normalized_outbound
                self.split_rules.enabled = True
                app_state.save_split_rules(self.split_rules)
                self._refresh_all_views()
                self.routing_page.select_rule(rule_set.id)
                self._show_status("success", f"Live Activity: правило включено: {rule_value}")
                self._restart_if_connected("Перезапуск маршрутизации…")
                return
            self.routing_page.select_rule(rule_set.id)
            self._show_status("info", f"Правило уже есть: {rule_value}")
            return

        rule_set.enabled = True
        rule_set.outbound = normalized_outbound
        target_values.append(rule_value)
        target_values.sort(key=str.lower)
        self.split_rules.enabled = True
        app_state.save_split_rules(self.split_rules)
        self._refresh_all_views()
        self.routing_page.select_rule(rule_set.id)
        created_text = "создан набор, " if created else ""
        self._show_status("success", f"Live Activity: {created_text}{label} {rule_value} -> {rule_set.outbound_label}")
        self._restart_if_connected("Перезапуск маршрутизации…")

    def _activity_rule_set(self, outbound: str) -> tuple[RoutingRuleSet, bool]:
        normalized_outbound = normalize_outbound(outbound)
        for rule_set in self.split_rules.rule_sets:
            if rule_set.source_type == LIVE_ACTIVITY_RULE_SOURCE_TYPE and normalize_outbound(rule_set.outbound) == normalized_outbound:
                return rule_set, False

        route_name = "напрямую" if normalized_outbound == ROUTE_OUTBOUND_DIRECT else "через VPN"
        rule_set = RoutingRuleSet(
            name=f"Live Activity: {route_name}",
            enabled=True,
            outbound=normalized_outbound,
            source_type=LIVE_ACTIVITY_RULE_SOURCE_TYPE,
            source=LIVE_ACTIVITY_RULE_SOURCE,
            priority=self._activity_rule_priority(normalized_outbound),
        )
        self.split_rules.rule_sets.append(rule_set)
        return rule_set, True

    def _activity_rule_priority(self, outbound: str) -> int:
        used_priorities = {rule_set.priority for rule_set in self.split_rules.rule_sets}
        priority = 100 if normalize_outbound(outbound) == ROUTE_OUTBOUND_DIRECT else 110
        while priority in used_priorities:
            priority += 1
        return priority

    def _activity_rule_target(
        self,
        rule_set: RoutingRuleSet,
        domain: str,
        match_kind: str,
    ) -> tuple[list[str], str, str]:
        if match_kind == "domain_suffix":
            return rule_set.domain_suffix, self._activity_domain_suffix(domain), "зона"
        return rule_set.domains, domain, "домен"

    @staticmethod
    def _normalize_activity_domain(domain: str) -> str:
        text = str(domain or "").strip().lower().strip(".")
        if "://" in text:
            text = urlparse(text).hostname or ""
        text = text.strip().strip(".")
        if not text or "." not in text:
            return ""
        if any(char.isspace() for char in text):
            return ""
        return text

    @staticmethod
    def _activity_domain_suffix(domain: str) -> str:
        return domain_site_suffix(domain)

    def save_settings(self, *, restart_connected: bool = True, show_success: bool = True) -> None:
        before_runtime = self._settings_runtime_key(self.settings)
        before_firewall_kill_switch = bool(self.settings.firewall_kill_switch)
        before_auto_start = bool(self.settings.auto_start_windows)
        try:
            next_settings = self.settings_page.apply_to_settings(AppSettings.from_dict(self.settings.to_dict()))
            if next_settings.to_dict() == self.settings.to_dict():
                return
            firewall_turning_on = bool(next_settings.firewall_kill_switch) and not before_firewall_kill_switch
            if firewall_turning_on and windows.is_windows() and not windows.is_admin():
                self._show_status("info", "Firewall Kill Switch требует права администратора. Сейчас откроется запрос Windows UAC.")
                if windows.relaunch_as_admin():
                    app_state.save_settings(next_settings)
                    QTimer.singleShot(250, self.exit_app)
                    return
                self._show_status("error", "Windows не выдала права администратора или запрос был отменен")
                self.settings_page.set_values(self.settings)
                return
            self.settings = next_settings
            paths.set_portable_mode(self.settings.portable_mode)
            if before_auto_start != bool(self.settings.auto_start_windows):
                windows.set_autostart(self.settings.auto_start_windows)
            if before_firewall_kill_switch and not self.settings.firewall_kill_switch:
                self._clear_firewall_kill_switch_safely()
            app_state.save_settings(self.settings)
            self._start_subscription_scheduler()
        except Exception as exc:
            self.logger.error("Settings save failed: %s\n%s", format_user_error(exc).display_text, format_safe_traceback(exc))
            self._show_status("error", format_user_error(exc, context="Настройки").display_text)
            self.settings_page.set_values(self.settings)
            return
        if show_success:
            self._show_status("success", "Настройки сохранены автоматически")
        if restart_connected and before_runtime != self._settings_runtime_key(self.settings):
            self._restart_if_connected("Перезапуск подключения…")

    @staticmethod
    def _settings_runtime_key(settings: AppSettings) -> tuple[object, ...]:
        return (
            settings.mode,
            settings.mixed_listen_host,
            int(settings.mixed_port),
            settings.tun_interface_name,
            settings.tun_address,
            settings.tun_ipv6_address,
            int(settings.tun_mtu),
            bool(settings.enable_ipv6),
            settings.dns_strategy,
            tuple(settings.dns_servers),
            tuple(settings.connectivity_check_urls),
            int(settings.connectivity_check_timeout_ms),
            bool(settings.kill_switch),
            bool(settings.firewall_kill_switch),
            bool(settings.enable_system_proxy_guard),
            settings.log_level,
        )

    def validate_current_config(self) -> None:
        profile = self._active_profile()
        if not profile:
            self._show_status("warning", "Нет активного профиля")
            return

        def worker() -> tuple[bool, str]:
            config_path = self.singbox.build_and_save_config(profile, self.settings, self.split_rules)
            return self.singbox.check_config(config_path)

        def done(result: tuple[bool, str]) -> None:
            ok, output = result
            self._show_status("success" if ok else "error", output)

        self._run_background(worker, done, busy="Проверка config…")

    def check_app_update(self, *, silent: bool = False) -> None:
        def worker() -> AppUpdateInfo | BaseException:
            try:
                return check_for_app_update(current_version=APP_VERSION)
            except Exception as exc:
                return exc

        def done(result: AppUpdateInfo | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_app_update_error(result, "Проверка обновлений", silent=silent)
                return
            if not result.update_available:
                if not silent:
                    self._show_status("info", f"Установлена актуальная версия: {APP_VERSION}")
                return
            self._show_app_update_prompt(result)

        self._run_background(
            worker,
            done,
            busy=None if silent else "Проверка обновлений…",
            set_busy=not silent,
        )

    def _show_app_update_prompt(self, update: AppUpdateInfo) -> None:
        asset_line = "Windows-файл в release не найден"
        if update.asset:
            size = f" · {format_bytes(update.asset.size)}" if update.asset.size else ""
            asset_line = f"{update.asset.name}{size}"

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Доступно обновление")
        dialog.setText(f"Доступна версия {update.latest_version}")
        dialog.setInformativeText(
            f"Установлена версия: {update.current_version}\n"
            f"Release: {update.release_name or update.latest_version}\n"
            f"Файл: {asset_line}\n\n"
            "Приложение скачает файл в локальную папку downloads/app-updates. "
            "Автоматическая замена запущенного exe не выполняется."
        )
        download_button = None
        if update.asset:
            download_button = dialog.addButton("Скачать", QMessageBox.ButtonRole.AcceptRole)
        release_button = dialog.addButton("Открыть release", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        if download_button is not None and clicked is download_button:
            self.download_app_update(update)
            return
        if clicked is release_button:
            webbrowser.open(update.release_url)

    def download_app_update(self, update: AppUpdateInfo) -> None:
        if not update.asset:
            self._show_status("warning", "В release нет подходящего Windows-файла обновления")
            webbrowser.open(update.release_url)
            return

        def worker() -> Path | BaseException:
            try:
                return download_update_asset(update)
            except Exception as exc:
                return exc

        def done(result: Path | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_app_update_error(result, "Загрузка обновления", silent=False)
                return
            self._show_status("success", f"Обновление скачано: {result.name}")
            self._prompt_downloaded_update(result)

        self._run_background(worker, done, busy="Скачивание обновления…")

    def _prompt_downloaded_update(self, path: Path) -> None:
        is_installer = path.suffix.lower() in {".exe", ".msi"}
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Обновление скачано")
        dialog.setText(path.name)
        dialog.setInformativeText(
            "Перед установкой новой версии закройте VPN-подключение и само приложение.\n\n"
            f"Файл сохранён: {path}"
        )
        open_label = "Запустить файл" if is_installer else "Показать файл"
        open_button = dialog.addButton(open_label, QMessageBox.ButtonRole.AcceptRole)
        folder_button = dialog.addButton("Открыть папку", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Позже", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        try:
            if clicked is open_button:
                if is_installer:
                    windows.open_path(path)
                else:
                    windows.reveal_in_file_manager(path)
            elif clicked is folder_button:
                windows.open_path(path.parent)
        except Exception as exc:
            self.logger.error("Не удалось открыть скачанное обновление: %s\n%s", sanitize_error_text(exc), format_safe_traceback(exc))
            self._show_status("error", f"Не удалось открыть файл: {sanitize_error_text(exc)}")

    def _handle_app_update_error(self, error: BaseException, action: str, *, silent: bool) -> None:
        message = sanitize_error_text(error) or "неизвестная ошибка"
        self.logger.warning("%s приложения не выполнена: %s\n%s", action, message, format_safe_traceback(error))
        if not silent:
            self._show_status("error", f"{action}: {message}")

    def download_core(self) -> None:
        def done(exe: Path) -> None:
            self._core_version_cache = None
            self.about_page.set_core_version(self._core_version(refresh=True))
            self._show_status("success", f"Установлен: {exe}")

        self._run_background(lambda: self.singbox.download_latest(), done, busy="Загрузка sing-box…")

    def check_dns(self) -> None:
        self._run_background(lambda: check_dns_resolver(), lambda result: QMessageBox.information(self, "DNS leak check", result), busy="Проверка DNS…")

    def clear_log_window(self) -> None:
        self.logs_page.clear_view()

    def clear_domain_activity(self) -> None:
        self.domain_activity.clear()
        self._refresh_activity_page()

    def export_logs(self) -> None:
        default_name = f"razreshenie-diagnostics-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт диагностики",
            default_name,
            "Zip archive (*.zip)",
        )
        if not target:
            return

        def worker() -> Path:
            return build_diagnostics_archive(
                target,
                settings=self.settings,
                profiles=self.profiles,
                subscriptions=self.subscriptions,
                split_rules=self.split_rules,
                quality_stats=self.smart_connect.quality_stats,
                smart_groups=self.smart_connect.smart_groups,
                singbox=self.singbox,
                log_lines=self.log_buffer.snapshot("all"),
            )

        def done(path: Path) -> None:
            self._show_status("success", f"Диагностика сохранена: {path}")

        self._run_background(worker, done, busy="Экспорт диагностики…")

    def reset_all_app_data(self) -> None:
        confirmation = QMessageBox(self)
        confirmation.setIcon(QMessageBox.Icon.Warning)
        confirmation.setWindowTitle("Удалить все настройки?")
        confirmation.setText("Удалить все настройки Razreshenie VPN Client?")
        confirmation.setInformativeText(
            "Будут удалены все серверы, подписки, правила маршрутизации, настройки, "
            "runtime-конфиги и скачанный sing-box core.\n\n"
            "После удаления VPN-клиент будет полностью закрыт. Это действие нельзя отменить."
        )
        confirmation.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        confirmation.setDefaultButton(QMessageBox.StandardButton.No)
        confirmation.button(QMessageBox.StandardButton.Yes).setText("Удалить и закрыть")
        confirmation.button(QMessageBox.StandardButton.No).setText("Отмена")
        if confirmation.exec() != QMessageBox.StandardButton.Yes:
            return

        def worker() -> None:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self._clear_firewall_kill_switch_safely()
            windows.set_autostart(False)
            self._delete_runtime_data()

        self._run_background(worker, lambda _result: self._finish_reset_and_exit(), busy="Сброс данных…")

    def _delete_runtime_data(self) -> None:
        app_dirs = paths.ensure_app_dirs()
        root = paths.data_dir().resolve()
        for file_path in (paths.settings_path(), paths.profiles_path(), paths.subscriptions_path(), paths.rules_path()):
            resolved = file_path.resolve()
            if resolved.exists() and self._is_inside(resolved, root):
                resolved.unlink()
        for dir_path in (app_dirs["configs"], app_dirs["cores"], app_dirs["downloads"], app_dirs["rules"], app_dirs["backups"]):
            resolved = dir_path.resolve()
            if resolved.exists() and self._is_inside(resolved, root):
                shutil.rmtree(resolved)

    def _finish_reset_and_exit(self) -> None:
        self.logger.info("Все настройки, серверы и sing-box удалены. Приложение закрывается.")
        self._busy = False
        self._closing = True
        if self.metrics_timer.isActive():
            self.metrics_timer.stop()
        if self.activity_timer.isActive():
            self.activity_timer.stop()
        if self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.stop()
        if self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        self.latency_scanner.stop()
        if self.tray:
            self.tray.hide()
        self.hide()
        self.close()
        QApplication.quit()

    def _status_loop(self) -> None:
        running = self.singbox.is_running()
        if not running and self.resilience.last_connection_running:
            self._handle_unexpected_core_stop()
        elif running:
            self.resilience.last_connection_running = True
        elif not self.resilience.failover_in_progress:
            self.resilience.last_connection_running = False
        sample = self.traffic.sample(active=running)
        self._speed_label = f"↓ {format_speed(sample.download)}   ↑ {format_speed(sample.upload)}"
        now = int(time.time())
        self._maybe_run_background_health_check(now, running)
        if now - self._last_ip_refresh > 30 and not self._ip_refreshing:
            self._last_ip_refresh = now
            self._ip_refreshing = True

            def ip_done(ip: str) -> None:
                self._set_ip(f"IP: {ip}")
                self._ip_refreshing = False

            self._run_background(get_public_ip, ip_done, set_busy=False)
        if now - self._last_ping_refresh > 10 and not self._ping_refreshing:
            self._last_ping_refresh = now
            profile = self._active_profile()
            if profile:
                self._ping_refreshing = True
                address, port = profile.address, profile.port

                def ping_worker() -> str:
                    latency = measure_server_latency_ms(address, port, timeout_ms=1000)
                    return f"{latency} мс" if latency is not None else "таймаут"

                def ping_done(ping: str) -> None:
                    self._set_ping(f"Пинг: {ping}")
                    self._ping_refreshing = False

                self._run_background(ping_worker, ping_done, set_busy=False)
        self.dashboard_page.set_metrics(
            self._ip_label,
            self._ping_label,
            self._speed_label,
            sample.download,
            sample.upload,
            format_bytes(sample.total_download),
            format_bytes(sample.total_upload),
        )

    def _set_ip(self, text: str) -> None:
        self._ip_label = text

    def _set_ping(self, text: str) -> None:
        self._ping_label = text

    def _start_subscription_scheduler(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        if self.settings.auto_update_subscriptions:
            interval = self.settings.subscription_update_interval_hours * 3600
            self.scheduler = RepeatingTask(interval, lambda: self.bridge.call.emit(self.update_all_subscriptions))
            self.scheduler.start()

    def _run_background(
        self,
        worker: Callable[[], object],
        on_success: Callable[[object], None] | None = None,
        *,
        busy: str | None = None,
        set_busy: bool = True,
    ) -> None:
        if set_busy and busy:
            self._busy = True
            self.dashboard_page.set_connection(self.singbox.is_running(), busy=True, message=busy)

        def target() -> None:
            try:
                result = worker()
            except Exception as exc:
                message = format_user_error(exc)
                self.logger.error("Background task failed [%s]: %s\n%s", message.category, message.display_text, format_safe_traceback(exc))
                self.bridge.call.emit(lambda message=message: self._show_status("error", message.display_text))
            else:
                if on_success:
                    self.bridge.call.emit(lambda result=result: on_success(result))
            finally:
                if set_busy:
                    self.bridge.call.emit(self._clear_busy)

        threading.Thread(target=target, daemon=True).start()

    def _clear_busy(self) -> None:
        if self._closing:
            return
        self._busy = False
        self.dashboard_page.set_connection(self.singbox.is_running())

    def _rules_summary_line(self) -> str:
        status = "включены" if self.split_rules.enabled_rule_sets else "отключены"
        default_label = "текущий сервер" if self.split_rules.effective_default_outbound == ROUTE_OUTBOUND_PROXY else "напрямую"
        return (
            f"Правила: {status} · наборов: {len(self.split_rules.rule_sets)} · "
            f"активных: {len(self.split_rules.enabled_rule_sets)} · остальной трафик: {default_label} · "
            f"rule-set resources: {len(self.split_rules.rule_set_resources)} · "
            f"встроенный bypass: {len(BUILTIN_DIRECT_DOMAIN_SUFFIXES)} доменов"
        )

    def _rules_summary_text(self) -> str:
        lines = [
            self._rules_summary_line(),
            "",
            "Каждый набор ниже имеет собственный маршрут: текущий сервер или напрямую.",
            (
                f"Встроенный bypass всегда отправляет напрямую {len(BUILTIN_DIRECT_DOMAIN_SUFFIXES)} доменов "
                f"из whitelist.json. Примеры: {', '.join(BUILTIN_DIRECT_DOMAIN_SUFFIXES[:12])}."
            ),
            "",
        ]
        if not self.split_rules.rule_sets:
            lines.append("Пользовательские правила не загружены.")
            return "\n".join(lines)

        resource_by_tag = {
            resource.tag: resource
            for resource in self.split_rules.rule_set_resources
            if resource.tag
        }
        for index, rule_set in enumerate(self._ordered_rule_sets(), start=1):
            preview = (
                rule_set.domains
                + rule_set.domain_suffix
                + rule_set.domain_keyword
                + rule_set.domain_regex
                + [f"geosite:{item}" for item in rule_set.geosite]
                + [f"geoip:{item}" for item in rule_set.geoip]
                + rule_set.ip_cidr
                + rule_set.process_name
                + rule_set.process_path
                + rule_set.process_path_regex
                + [f"rule_set:{item}" for item in rule_set.rule_set_tags]
            )[:12]
            lines.extend(
                [
                    f"{index}. {rule_set.name}",
                    f"   Маршрут: {rule_set.outbound_label}",
                    f"   Статус: {'включен' if rule_set.enabled else 'отключен'}",
                    f"   Приоритет: {rule_set.priority}",
                    f"   Источник: {rule_set.source or '—'}",
                    f"   Элементов: {rule_set.total_items}",
                    f"   Домены exact: {len(rule_set.domains)}",
                    f"   Домены suffix: {len(rule_set.domain_suffix)}",
                    f"   Ключевые слова доменов: {len(rule_set.domain_keyword)}",
                    f"   Domain regex: {len(rule_set.domain_regex)}",
                    f"   Geosite: {len(rule_set.geosite)}",
                    f"   GeoIP: {len(rule_set.geoip)}",
                    f"   IP/CIDR: {len(rule_set.ip_cidr)}",
                    f"   Процессы: {len(rule_set.process_name)}",
                    f"   Process path: {len(rule_set.process_path)}",
                    f"   Process path regex: {len(rule_set.process_path_regex)}",
                    f"   Rule-set: {', '.join(rule_set.rule_set_tags) if rule_set.rule_set_tags else '—'}",
                    f"   Первые элементы: {', '.join(preview) if preview else '—'}",
                    "",
                ]
            )
            for tag in rule_set.rule_set_tags:
                resource = resource_by_tag.get(tag)
                if resource:
                    location = resource.url or resource.path or resource.source or "—"
                    lines.extend(
                        [
                            f"   Resource {tag}: {resource.type}/{resource.format}",
                            f"   Location: {location}",
                            "",
                        ]
                    )
        return "\n".join(lines)

    def _show_status(self, level: str, message: str) -> None:
        if level == "error":
            InfoBar.error("Ошибка", message, position=InfoBarPosition.TOP_RIGHT, duration=6000, parent=self)
        elif level == "warning":
            InfoBar.warning("Внимание", message, position=InfoBarPosition.TOP_RIGHT, duration=3500, parent=self)
        elif level == "success":
            InfoBar.success("Успешно", message, position=InfoBarPosition.TOP_RIGHT, duration=2500, parent=self)
        else:
            InfoBar.info("Инфо", message, position=InfoBarPosition.TOP_RIGHT, duration=2500, parent=self)

    def _on_log_from_thread(self, level: str, message: str) -> None:
        self.log_buffer.append(level, message)
        if self.domain_activity.ingest_log_line(message, self.split_rules):
            should_emit = False
            with self._activity_signal_lock:
                if not self._activity_signal_pending:
                    self._activity_signal_pending = True
                    should_emit = True
            if should_emit:
                self.bridge.activity_changed.emit()
        self.bridge.log_line.emit(level, message)

    def _append_log_line(self, _level: str, message: str) -> None:
        self.logs_page.append_line(message)

    def _schedule_activity_refresh(self, delay_ms: int = 180) -> None:
        if self._closing:
            return
        if delay_ms <= 0:
            if self.activity_refresh_timer.isActive():
                self.activity_refresh_timer.stop()
            self._refresh_activity_page()
            return
        if not self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.start(delay_ms)

    def _refresh_activity_page(self) -> None:
        entries = self.domain_activity.snapshot(
            self.activity_page.query(),
            self.activity_page.route_filter(),
            self.activity_page.rule_filter(),
            self.activity_page.sort_mode(),
        )
        self.activity_page.set_entries(entries)
        with self._activity_signal_lock:
            self._activity_signal_pending = False

    def _refresh_tray_text(self) -> None:
        if not self.tray:
            return
        status = "подключено" if self.singbox.is_running() else "отключено"
        self.tray.setToolTip(f"{APP_NAME} {APP_VERSION} — {status}")
        if hasattr(self, "tray_connect_action"):
            self.tray_connect_action.setEnabled(not self.singbox.is_running())
            self.tray_disconnect_action.setEnabled(self.singbox.is_running())

    def show_normal(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            event.accept()
            return
        if self.settings.minimize_to_tray and not self._closing:
            event.ignore()
            self.hide()
            windows.show_toast("Razreshenie VPN", "Приложение свернуто в трей")
            return
        self._flush_pending_settings_save()
        self._closing = True
        self._shutdown_runtime()
        event.accept()
        QApplication.quit()

    def exit_app(self) -> None:
        if self._closing:
            QApplication.quit()
            return
        self._flush_pending_settings_save()
        self._closing = True
        self._shutdown_runtime()
        self.close()
        QApplication.quit()

    def _shutdown_runtime(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
            self.scheduler = None
        self.latency_scanner.stop()
        if hasattr(self, "latency_result_timer") and self.latency_result_timer.isActive():
            self.latency_result_timer.stop()
        if hasattr(self, "activity_refresh_timer") and self.activity_refresh_timer.isActive():
            self.activity_refresh_timer.stop()
        try:
            self.singbox.stop()
            if self.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, self.settings.mixed_listen_host, self.settings.mixed_port)
            self._clear_firewall_kill_switch_safely()
        finally:
            if self.tray:
                self.tray.hide()

    @staticmethod
    def _is_inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False


class RazreshenieApp:
    """Совместимая обертка для main.py: предоставляет mainloop как у Tk-приложения."""

    def __init__(self) -> None:
        self.qt_app = QApplication.instance() or QApplication(sys.argv)
        self.qt_app.setApplicationName(APP_NAME)
        self.qt_app.setApplicationVersion(APP_VERSION)
        install_emoji_font_fallbacks()
        setTheme(Theme.DARK)
        setThemeColor(ACCENT)
        self.window = RazreshenieWindow()

    def mainloop(self) -> int:
        self.window.show()
        return int(self.qt_app.exec())
