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
import sys
import threading
import time
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
from gui.controllers.app_update import AppUpdateController
from gui.controllers.maintenance import MaintenanceController
from gui.widgets import JsonEditorDialog
from core import app_state
from core.connection_service import ConnectionService, ConnectionStartResult
from core.connection_runtime import ConnectionRuntimeState
from core.connectivity import ConnectivityCheckResult
from core.domain_activity import DomainActivityTracker
from core.error_messages import format_safe_traceback, format_user_error, sanitize_error_text
from core.latency_scanner import LatencyScanner, LatencyScanSummary
from core.profile_state_service import ProfileStateService
from core.resilience_service import (
    HEALTH_STATUS_FAILED,
    HEALTH_STATUS_OK,
    HEALTH_STATUS_RECOVER,
    RECOVERY_ACTION_FAILOVER,
    RECOVERY_ACTION_RESTART,
    RECOVERY_ACTION_RESTART_GROUP,
    FailoverAttemptResult,
    RecoveryPlan,
    ResilienceService,
)
from core.routing_service import RoutingMutationResult, RoutingService, RoutingServiceError
from core.rules_manager import RulesImportError, RulesImportResult, RulesManager
from core.smart_connect import SmartConnectManager
from core.smart_group_service import SmartGroupEdit, SmartGroupService, SmartGroupServiceError
from core.singbox_manager import SingBoxError, SingBoxManager
from core.subscription_manager import SubscriptionFetchResult, SubscriptionManager
from core.subscription_state_service import SubscriptionStateChange, SubscriptionStateService
from models.connection import SMART_GROUP_MODE_FAILOVER, SmartGroup, normalize_smart_group_mode
from models.profile import Subscription, VlessProfile
from models.rules import (
    BUILTIN_DIRECT_DOMAIN_SUFFIXES,
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RoutingRuleSet,
    SplitRules,
)
from models.settings import (
    AppSettings,
)
from utils import paths, windows
from utils.app_logger import LogBuffer, setup_logger
from utils.network import (
    TrafficMonitor,
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
        self.routing_service = RoutingService()
        self.subscription_manager = SubscriptionManager()
        self.subscription_state = SubscriptionStateService(self.subscription_manager.profile_key)
        self.smart_connect = SmartConnectManager(app_state.load_quality_stats(), app_state.load_smart_groups())
        self.profile_state = ProfileStateService(self.smart_connect)
        self.smart_group_service = SmartGroupService(self.smart_connect)
        self.app_update_controller = AppUpdateController(self)
        self.maintenance_controller = MaintenanceController(self)
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
        self.connection_runtime = ConnectionRuntimeState(
            smart_connect=self.smart_connect,
            smart_groups=self.smart_connect.smart_groups,
        )
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
        return self.subscription_state.profile_counts(self.profiles)

    def _sync_subscription_profile_counts(self, *, save: bool) -> dict[str, int]:
        result = self.subscription_state.sync_profile_counts(self.subscriptions, self.profiles)
        if result.changed and save:
            app_state.save_subscriptions(self.subscriptions)
        return result.counts

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
        self._profiles_by_id = self.profile_state.profile_index(self.profiles)

    def _profile_by_id(self, profile_id: str) -> VlessProfile | None:
        profile = self._profiles_by_id.get(profile_id)
        if profile is None and self.profiles:
            self._rebuild_profile_index()
            profile = self._profiles_by_id.get(profile_id) or self.profile_state.profile_by_id(self.profiles, profile_id)
        return profile

    def _apply_profile_state(self, profiles: list[VlessProfile], active_profile_id: str | None) -> None:
        self.profiles = profiles
        self.settings.active_profile_id = active_profile_id
        self._rebuild_profile_index()

    def _subscription_by_id(self, subscription_id: str) -> Subscription | None:
        return self.subscription_state.subscription_by_id(self.subscriptions, subscription_id)

    def _rule_set_by_id(self, rule_set_id: str) -> RoutingRuleSet | None:
        return self.routing_service.rule_set_by_id(self.split_rules, rule_set_id)

    def _smart_group_by_id(self, group_id: str) -> SmartGroup | None:
        return self.smart_group_service.group_by_id(group_id)

    def create_failover_group_by_id(self, profile_id: str) -> None:
        if not self._profile_by_id(profile_id):
            return
        try:
            result = self.smart_group_service.create_failover_group(
                profile_id=profile_id,
                profiles=self.profiles,
                subscriptions=self.subscriptions,
            )
        except SmartGroupServiceError as exc:
            self._show_status("warning", str(exc))
            return
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._refresh_servers_table()
        self._show_status("success", result.status_message)

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
        try:
            result = self.smart_group_service.apply_edit(
                group,
                SmartGroupEdit(
                    name=data.name,
                    enabled=data.enabled,
                    mode=data.mode,
                    strategy=data.strategy,
                    profile_ids=list(data.profile_ids),
                    load_balance_interval=data.load_balance_interval,
                    load_balance_tolerance_ms=data.load_balance_tolerance_ms,
                ),
            )
        except SmartGroupServiceError as exc:
            self._show_status("warning", str(exc))
            return
        app_state.save_smart_groups(self.smart_connect.smart_groups)
        self._refresh_servers_table()
        self._show_status("success", result.status_message)

    def start_smart_group_by_id(self, group_id: str, *, reset_recovery_state: bool = True) -> None:
        decision = self.smart_group_service.plan_start(
            group_id=group_id,
            settings=self.settings,
            is_admin=windows.is_admin(),
            busy=self._busy,
        )
        if decision.admin_required:
            self._request_admin_for_tun(decision.admin_reason)
            return
        if not decision.allowed:
            if decision.status_message:
                self._show_status(decision.status_level, decision.status_message)
            return
        group = decision.group
        if not group:
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

        self._run_background(worker, self._finish_connection_start, busy=decision.busy_text)

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

    def _finish_connection_start(self, result: ConnectionStartResult) -> None:
        self.resilience.apply_connection_start(result)
        profile = result.selected_profile
        self.settings.active_profile_id = profile.id
        app_state.save_settings(self.settings)
        self._refresh_server_views()
        self.dashboard_page.set_active_profile(profile)
        self.servers_page.set_active_id(profile.id)
        self._connected_ui(
            profile,
            display_name=result.display_name,
            profile_ids=result.profile_ids,
            group_id=result.group_id,
        )

    def _clear_firewall_kill_switch_safely(self) -> None:
        self.connection_service.clear_firewall_kill_switch_safely()

    def _start_or_restart_vpn(self, profile: VlessProfile, busy: str) -> None:
        if self._busy:
            self._show_status("info", "Операция подключения уже выполняется")
            return
        def worker() -> ConnectionStartResult:
            self.connection_service.start_profile_core(
                profile,
                settings=self.settings,
                split_rules=self.split_rules,
            )
            return ConnectionStartResult(anchor_profile=profile, selected_profile=profile)

        self._run_background(worker, self._finish_connection_start, busy=busy)

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
        self.connection_runtime.begin(profile_ids=profile_ids or (profile.id,), group_id=group_id)
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

    def _active_smart_group(self) -> SmartGroup | None:
        return self.connection_runtime.active_group()

    def _record_active_connection_usage(self) -> None:
        if not self.connection_runtime.active_profile_ids:
            return
        sample = self.traffic.sample(active=False)
        self.connection_runtime.record_usage_and_clear(
            download_bytes=sample.total_download,
            upload_bytes=sample.total_upload,
            save_quality_stats=self._save_quality_stats_now,
            save_smart_groups=self._save_smart_groups_now,
        )

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
        plan = self.resilience.plan_health_recovery(
            profile,
            reason,
            settings=self.settings,
            profiles=self.profiles,
            profile_lookup=self._profile_by_id,
            busy=self._busy,
            closing=self._closing,
            active_group=self._active_smart_group(),
        )
        self._execute_recovery_plan(profile, plan, source="Health monitor", show_failover_warning=True)

    def _execute_recovery_plan(
        self,
        profile: VlessProfile,
        plan: RecoveryPlan,
        *,
        source: str,
        show_failover_warning: bool,
    ) -> None:
        if plan.action == RECOVERY_ACTION_RESTART_GROUP:
            group = self._smart_group_by_id(plan.group_id)
            if not group:
                self._handle_unrecoverable_connection_failure(f"{source}: активная группа не найдена")
                return
            self.logger.warning("%s: переподключаю группу %s: %s", source, group.name, plan.reason)
            self.start_smart_group_by_id(group.id, reset_recovery_state=False)
            return
        if plan.action == RECOVERY_ACTION_FAILOVER:
            if show_failover_warning:
                self._show_status(
                    "warning",
                    f"{source}: соединение нестабильно, переключаю сервер. {sanitize_error_text(plan.reason)}",
                )
            self._start_failover_after_drop(profile)
            return
        if plan.action == RECOVERY_ACTION_RESTART:
            self._restart_unhealthy_profile(profile, plan.reason, source=source)
            return

    def _restart_unhealthy_profile(self, profile: VlessProfile, reason: str, *, source: str = "Health monitor") -> None:
        if self._busy:
            return
        self.logger.warning("%s: переподключаю текущий сервер %s: %s", source, profile.name, reason)

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
            self._finish_connection_start(ConnectionStartResult(anchor_profile=profile, selected_profile=profile))
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
        plan = self.resilience.plan_health_recovery(
            failed_profile,
            reason,
            settings=self.settings,
            profiles=self.profiles,
            profile_lookup=self._profile_by_id,
            busy=self._busy,
            closing=self._closing,
            active_group=active_group,
        )
        self._execute_recovery_plan(failed_profile, plan, source="Watchdog", show_failover_warning=False)

    def _should_self_heal_after_drop(self, profile: VlessProfile | None) -> bool:
        return self.resilience.should_self_heal_after_drop(
            profile,
            settings=self.settings,
            busy=self._busy,
            closing=self._closing,
        )

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
        change = self.profile_state.apply_import(
            profiles=self.profiles,
            imported_profiles=profiles,
            active_profile_id=self.settings.active_profile_id,
        )
        self._apply_profile_state(change.profiles, change.active_profile_id)
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
        change = self.profile_state.replace_profile(
            profiles=self.profiles,
            profile_id=profile_id,
            updated_profile=updated,
            active_profile_id=self.settings.active_profile_id,
        )
        self._apply_profile_state(change.profiles, change.active_profile_id)
        app_state.save_profiles(self.profiles)
        app_state.save_settings(self.settings)
        self._refresh_all_views()

    def delete_profile_by_id(self, profile_id: str) -> None:
        profile = self._profile_by_id(profile_id)
        if not profile:
            return
        if QMessageBox.question(self, "Удалить профиль", f"Удалить {profile.name}?") != QMessageBox.StandardButton.Yes:
            return
        change = self.profile_state.delete_profile(
            profiles=self.profiles,
            profile_id=profile_id,
            active_profile_id=self.settings.active_profile_id,
        )
        self._apply_profile_state(change.profiles, change.active_profile_id)
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
        result = self.profile_state.apply_latency_batch(self.profiles, results)
        self._latency_scan_completed = min(self._latency_scan_total, self._latency_scan_completed + len(results))
        self.servers_page.set_quality_stats(self.smart_connect.quality_stats)
        self.servers_page.update_latency_cells(list(result.changed_profile_ids))
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
        return self.profile_state.set_profile_latency(self.profiles, profile_id, latency, checked_at=checked_at)

    def _save_profiles_now(self) -> None:
        app_state.save_profiles(self.profiles)

    def _save_quality_stats_now(self) -> None:
        app_state.save_quality_stats(self.smart_connect.quality_stats)

    def _save_smart_groups_now(self) -> None:
        app_state.save_smart_groups(self.smart_connect.smart_groups)

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
        change = self.profile_state.sort_by_latency(self.profiles, self.settings.active_profile_id)
        self._apply_profile_state(change.profiles, change.active_profile_id)
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
        change = self.subscription_state.apply_update(
            subscriptions=self.subscriptions,
            profiles=self.profiles,
            active_profile_id=self.settings.active_profile_id,
            subscription=subscription,
            incoming_profiles=profiles,
        )
        self._apply_subscription_state(change)
        self._save_subscription_state()
        self._refresh_server_views()
        self.subscriptions_page.set_subscriptions(self.subscriptions, change.profile_counts)
        self._refresh_tray_text()
        if show_status:
            self._show_status("success", f"Подписка обновлена: {subscription.name} · серверов: {subscription.profile_count}")

    def _record_subscription_error(self, subscription: Subscription, error: str) -> None:
        change = self.subscription_state.record_error(
            subscriptions=self.subscriptions,
            profiles=self.profiles,
            active_profile_id=self.settings.active_profile_id,
            subscription=subscription,
            error=error,
        )
        self._apply_subscription_state(change)
        app_state.save_subscriptions(self.subscriptions)
        self.subscriptions_page.set_subscriptions(self.subscriptions, change.profile_counts)

    def _apply_subscription_state(self, change: SubscriptionStateChange) -> None:
        self.subscriptions = change.subscriptions
        self.profiles = change.profiles
        self.settings.active_profile_id = change.active_profile_id
        self._rebuild_profile_index()

    def _save_subscription_state(self) -> None:
        app_state.save_profiles(self.profiles)
        app_state.save_subscriptions(self.subscriptions)
        app_state.save_settings(self.settings)

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
            change = self.subscription_state.apply_batch_results(
                subscriptions=self.subscriptions,
                profiles=self.profiles,
                active_profile_id=self.settings.active_profile_id,
                results=results,
                error_formatter=lambda error: format_user_error(error, context="Подписка").display_text,
            )
            self._apply_subscription_state(change)
            self._save_subscription_state()
            self._refresh_server_views()
            self.subscriptions_page.set_subscriptions(self.subscriptions, change.profile_counts)
            self._refresh_tray_text()
            if change.failed:
                self._show_status("warning", f"Обновлено: {change.updated}, ошибок: {len(change.failed)}")
            else:
                self._show_status("success", f"Обновлено подписок: {change.updated}")
        finally:
            self.subscriptions_page.set_update_busy(False)

    def delete_subscription_by_id(self, subscription_id: str) -> None:
        subscription = self._subscription_by_id(subscription_id)
        if not subscription:
            return
        if QMessageBox.question(self, "Удалить подписку", f"Удалить {subscription.name} и ее профили?") != QMessageBox.StandardButton.Yes:
            return
        change = self.subscription_state.delete_subscription(
            subscriptions=self.subscriptions,
            profiles=self.profiles,
            active_profile_id=self.settings.active_profile_id,
            subscription_id=subscription_id,
        )
        self._apply_subscription_state(change)
        self._save_subscription_state()
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

        try:
            result = self.routing_service.upsert_per_app_rule(
                self.split_rules,
                name=data.name,
                outbound=data.outbound,
                match_kind=data.match_kind,
                value=data.value,
            )
        except RoutingServiceError as exc:
            self._show_status("warning", str(exc))
            return
        self._apply_routing_result(result)

    def _load_rules(self, loader: Callable[[], RulesImportResult]) -> None:
        try:
            result = loader()
        except RulesImportError as exc:
            self._show_status("error", format_user_error(exc, context="Маршрутизация").display_text)
            return
        try:
            mutation = self.routing_service.add_import_result(self.split_rules, result)
        except RoutingServiceError as exc:
            self._show_status("error", str(exc))
            return
        self._apply_routing_result(mutation)

    def _apply_routing_result(self, result: RoutingMutationResult) -> None:
        if result.changed:
            app_state.save_split_rules(self.split_rules)
            self._refresh_all_views()
        if result.selected_rule_id:
            self.routing_page.select_rule(result.selected_rule_id)
        if result.status_message:
            self._show_status(result.status_level, result.status_message)
        if result.restart_required:
            self._restart_if_connected("Перезапуск маршрутизации…")

    def set_rule_set_outbound(self, rule_set_id: str, outbound: str) -> None:
        result = self.routing_service.set_rule_set_outbound(self.split_rules, rule_set_id, outbound)
        self._apply_routing_result(result)

    def set_rule_set_enabled(self, rule_set_id: str, enabled: bool) -> None:
        result = self.routing_service.set_rule_set_enabled(self.split_rules, rule_set_id, enabled)
        self._apply_routing_result(result)

    def toggle_rule_set(self, rule_set_id: str) -> None:
        result = self.routing_service.toggle_rule_set(self.split_rules, rule_set_id)
        self._apply_routing_result(result)

    def move_rule_set(self, rule_set_id: str, direction: int) -> None:
        result = self.routing_service.move_rule_set(self.split_rules, rule_set_id, direction)
        self._apply_routing_result(result)

    def delete_rule_set(self, rule_set_id: str) -> None:
        rule_set = self._rule_set_by_id(rule_set_id)
        if not rule_set:
            return
        if QMessageBox.question(self, "Удалить правила", f"Удалить {rule_set.name}?") != QMessageBox.StandardButton.Yes:
            return
        result = self.routing_service.delete_rule_set(self.split_rules, rule_set_id)
        self._apply_routing_result(result)

    def clear_rule_sets(self) -> None:
        if not self.split_rules.rule_sets and not self.split_rules.rule_set_resources:
            return
        if QMessageBox.question(self, "Очистить маршрутизацию", "Удалить все наборы правил маршрутизации?") != QMessageBox.StandardButton.Yes:
            return
        result = self.routing_service.clear_rule_sets(self.split_rules)
        self._apply_routing_result(result)

    def add_activity_route_rule(self, domain: str, match_kind: str, outbound: str) -> None:
        try:
            result = self.routing_service.add_activity_rule(
                self.split_rules,
                domain=domain,
                match_kind=match_kind,
                outbound=outbound,
            )
        except RoutingServiceError as exc:
            self._show_status("warning", str(exc))
            return
        self._apply_routing_result(result)

    def save_settings(self, *, restart_connected: bool = True, show_success: bool = True) -> None:
        before_runtime = self._settings_runtime_key(self.settings)
        before_firewall_kill_switch = bool(self.settings.firewall_kill_switch)
        before_auto_start = bool(self.settings.auto_start_windows)
        before_always_admin = bool(self.settings.always_run_as_admin)
        try:
            next_settings = self.settings_page.apply_to_settings(AppSettings.from_dict(self.settings.to_dict()))
            if next_settings.to_dict() == self.settings.to_dict():
                return
            always_admin_turning_on = bool(next_settings.always_run_as_admin) and not before_always_admin
            if always_admin_turning_on and windows.is_windows() and not windows.is_admin():
                self._show_status(
                    "info",
                    "Постоянный запуск от имени администратора включен. Сейчас откроется запрос Windows UAC.",
                )
                if windows.relaunch_as_admin():
                    app_state.save_settings(next_settings)
                    QTimer.singleShot(250, self.exit_app)
                    return
                self._show_status("error", "Windows не выдала права администратора или запрос был отменен")
                self.settings_page.set_values(self.settings)
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
        active_group = self._active_smart_group()
        profiles_by_id = {profile.id: profile for profile in self.profiles}

        if active_group and normalize_smart_group_mode(active_group.mode) != SMART_GROUP_MODE_FAILOVER:
            if not any(profile_id in profiles_by_id for profile_id in active_group.profile_ids):
                self._show_status("warning", "В активной группе нет доступных серверов")
                return

            def worker() -> tuple[bool, str]:
                return self.singbox.check_group_config(
                    active_group,
                    profiles_by_id,
                    self.settings,
                    self.split_rules,
                )

            busy = "Проверка group config…"
        else:
            profile = self._active_profile()
            if not profile:
                self._show_status("warning", "Нет активного профиля")
                return

            def worker() -> tuple[bool, str]:
                return self.singbox.check_profile_config(profile, self.settings, self.split_rules)

            busy = "Проверка config…"

        def done(result: tuple[bool, str]) -> None:
            ok, output = result
            self._show_status("success" if ok else "error", output)

        self._run_background(worker, done, busy=busy)

    def check_app_update(self, *, silent: bool = False) -> None:
        self.app_update_controller.check(silent=silent)

    def download_app_update(self, update) -> None:
        self.app_update_controller.download(update)

    def download_core(self) -> None:
        self.maintenance_controller.download_core()

    def check_dns(self) -> None:
        self.maintenance_controller.check_dns()

    def clear_log_window(self) -> None:
        self.maintenance_controller.clear_log_window()

    def clear_domain_activity(self) -> None:
        self.maintenance_controller.clear_domain_activity()

    def export_logs(self) -> None:
        self.maintenance_controller.export_logs()

    def reset_all_app_data(self) -> None:
        self.maintenance_controller.reset_all_app_data()

    def _status_loop(self) -> None:
        running = self.singbox.is_running()
        if not running and self.resilience.should_report_core_stop(closing=self._closing):
            self._handle_unexpected_core_stop()
        elif not running and self.resilience.manual_disconnect_requested:
            self.singbox.mark_stopped_if_exited()
            self.resilience.mark_core_stopped()
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
        for index, rule_set in enumerate(self.routing_service.ordered_rule_sets(self.split_rules), start=1):
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
