# -*- coding: utf-8 -*-
#
# Razreshenie VPN Client
# Copyright (C) 2026 Razreshenie VPN contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Maintenance, diagnostics and reset workflows for the main window."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import shutil
import time

from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from core.diagnostics import build_diagnostics_archive
from utils import paths, windows
from utils.network import check_dns_resolver


class MaintenanceController:
    """Owns diagnostics/export/reset workflows that are not core VPN logic."""

    def __init__(self, window: Any) -> None:
        self.window = window

    def download_core(self) -> None:
        app = self.window

        def done(exe: Path) -> None:
            app._core_version_cache = None
            app.about_page.set_core_version(app._core_version(refresh=True))
            app._show_status("success", f"Установлен: {exe}")

        app._run_background(lambda: app.singbox.download_latest(), done, busy="Загрузка sing-box…")

    def check_dns(self) -> None:
        app = self.window
        app._run_background(
            lambda: check_dns_resolver(),
            lambda result: QMessageBox.information(app, "DNS leak check", result),
            busy="Проверка DNS…",
        )

    def clear_log_window(self) -> None:
        self.window.logs_page.clear_view()

    def clear_domain_activity(self) -> None:
        app = self.window
        app.domain_activity.clear()
        app._refresh_activity_page()

    def export_logs(self) -> None:
        app = self.window
        default_name = f"razreshenie-diagnostics-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        target, _ = QFileDialog.getSaveFileName(
            app,
            "Экспорт диагностики",
            default_name,
            "Zip archive (*.zip)",
        )
        if not target:
            return

        def worker() -> Path:
            return build_diagnostics_archive(
                target,
                settings=app.settings,
                profiles=app.profiles,
                subscriptions=app.subscriptions,
                split_rules=app.split_rules,
                quality_stats=app.smart_connect.quality_stats,
                smart_groups=app.smart_connect.smart_groups,
                singbox=app.singbox,
                log_lines=app.log_buffer.snapshot("all"),
            )

        def done(path: Path) -> None:
            app._show_status("success", f"Диагностика сохранена: {path}")

        app._run_background(worker, done, busy="Экспорт диагностики…")

    def reset_all_app_data(self) -> None:
        app = self.window
        confirmation = QMessageBox(app)
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
            app.singbox.stop()
            if app.settings.enable_system_proxy_guard:
                windows.set_system_proxy(False, app.settings.mixed_listen_host, app.settings.mixed_port)
            app._clear_firewall_kill_switch_safely()
            windows.set_autostart(False)
            self._delete_runtime_data()

        app._run_background(worker, lambda _result: self._finish_reset_and_exit(), busy="Сброс данных…")

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
        app = self.window
        app.logger.info("Все настройки, серверы и sing-box удалены. Приложение закрывается.")
        app._busy = False
        app._closing = True
        if app.metrics_timer.isActive():
            app.metrics_timer.stop()
        if app.activity_timer.isActive():
            app.activity_timer.stop()
        if app.activity_refresh_timer.isActive():
            app.activity_refresh_timer.stop()
        if app.latency_result_timer.isActive():
            app.latency_result_timer.stop()
        if app.scheduler:
            app.scheduler.stop()
            app.scheduler = None
        app.latency_scanner.stop()
        if app.tray:
            app.tray.hide()
        app.hide()
        app.close()
        QApplication.quit()

    @staticmethod
    def _is_inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True
