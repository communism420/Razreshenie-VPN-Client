# -*- coding: utf-8 -*-
#
# Razreshenie VPN Client
# Copyright (C) 2026 Razreshenie VPN contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Application update workflow controller."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import webbrowser

from PyQt6.QtWidgets import QMessageBox

from core.app_updater import (
    AppUpdateInfo,
    PreparedInPlaceUpdate,
    check_for_app_update,
    current_executable_can_be_replaced,
    download_update_asset,
    launch_in_place_update,
    prepare_in_place_update,
)
from core.error_messages import format_safe_traceback, sanitize_error_text
from models.settings import APP_UPDATE_MODE_REPLACE_CURRENT, normalize_app_update_mode
from utils import windows
from utils.network import format_bytes
from utils.version import APP_VERSION


class AppUpdateController:
    """Owns app update prompts/download orchestration for the main window."""

    def __init__(self, window: Any) -> None:
        self.window = window

    def check(self, *, silent: bool = False) -> None:
        app = self.window

        def worker() -> AppUpdateInfo | BaseException:
            try:
                return check_for_app_update(current_version=APP_VERSION)
            except Exception as exc:
                return exc

        def done(result: AppUpdateInfo | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_error(result, "Проверка обновлений", silent=silent)
                return
            if not result.update_available:
                if not silent:
                    app._show_status("info", f"Установлена актуальная версия: {APP_VERSION}")
                return
            self._show_prompt(result)

        app._run_background(
            worker,
            done,
            busy=None if silent else "Проверка обновлений…",
            set_busy=not silent,
        )

    def download(self, update: AppUpdateInfo) -> None:
        app = self.window
        if not update.asset:
            app._show_status("warning", "В release нет подходящего Windows-файла обновления")
            webbrowser.open(update.release_url)
            return

        replace_mode = (
            normalize_app_update_mode(app.settings.app_update_mode) == APP_UPDATE_MODE_REPLACE_CURRENT
            and current_executable_can_be_replaced()
        )

        def worker() -> Path | PreparedInPlaceUpdate | BaseException:
            try:
                path = download_update_asset(update)
            except Exception as exc:
                return exc
            if not replace_mode:
                return path
            try:
                return prepare_in_place_update(path)
            except Exception as exc:
                app.logger.warning(
                    "Подготовка замены приложения недоступна, файл оставлен как ручное обновление: %s",
                    sanitize_error_text(exc),
                )
                return path

        def done(result: Path | PreparedInPlaceUpdate | BaseException) -> None:
            if isinstance(result, BaseException):
                self._handle_error(result, "Загрузка обновления", silent=False)
                return
            if isinstance(result, PreparedInPlaceUpdate):
                self._prompt_in_place(result)
                return
            app._show_status("success", f"Обновление скачано: {result.name}")
            self._prompt_downloaded(result)

        app._run_background(worker, done, busy="Скачивание обновления…")

    def _show_prompt(self, update: AppUpdateInfo) -> None:
        app = self.window
        asset_line = "Windows-файл в release не найден"
        if update.asset:
            size = f" · {format_bytes(update.asset.size)}" if update.asset.size else ""
            asset_line = f"{update.asset.name}{size}"
        replace_mode = normalize_app_update_mode(app.settings.app_update_mode) == APP_UPDATE_MODE_REPLACE_CURRENT
        can_replace = replace_mode and current_executable_can_be_replaced()
        mode_text = (
            "Приложение скачает новую версию, закроется и заменит текущий EXE в папке запуска."
            if can_replace
            else "Приложение скачает файл в локальную папку downloads/app-updates. Установка выполняется вручную."
        )
        if replace_mode and not can_replace:
            mode_text += "\n\nРежим замены текущего EXE выбран, но сейчас клиент запущен не из собранного .exe."

        dialog = QMessageBox(app)
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle("Доступно обновление")
        dialog.setText(f"Доступна версия {update.latest_version}")
        dialog.setInformativeText(
            f"Установлена версия: {update.current_version}\n"
            f"Release: {update.release_name or update.latest_version}\n"
            f"Файл: {asset_line}\n\n"
            f"{mode_text}"
        )
        download_button = None
        if update.asset:
            label = "Скачать и заменить" if can_replace else "Скачать"
            download_button = dialog.addButton(label, QMessageBox.ButtonRole.AcceptRole)
        release_button = dialog.addButton("Открыть release", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        if download_button is not None and clicked is download_button:
            self.download(update)
            return
        if clicked is release_button:
            webbrowser.open(update.release_url)

    def _prompt_in_place(self, plan: PreparedInPlaceUpdate) -> None:
        app = self.window
        dialog = QMessageBox(app)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle("Заменить текущий EXE?")
        dialog.setText("Обновление готово к установке")
        dialog.setInformativeText(
            "Приложение остановит VPN, закроется и заменит текущий EXE по тому же пути.\n"
            "Если старый файл ещё занят Windows, установщик дождётся выхода процесса и попробует принудительно завершить его.\n\n"
            f"Путь замены: {plan.install_path}\n"
            f"Временный файл обновления: {plan.downloaded_path}"
        )
        install_button = dialog.addButton("Закрыть и заменить", QMessageBox.ButtonRole.AcceptRole)
        folder_button = dialog.addButton("Открыть папку", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton("Позже", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        clicked = dialog.clickedButton()
        if clicked is folder_button:
            windows.open_path(plan.downloaded_path.parent)
            return
        if clicked is not install_button:
            app._show_status("info", f"Обновление скачано: {plan.downloaded_path.name}")
            return
        try:
            launch_in_place_update(plan)
        except Exception as exc:
            self._handle_error(exc, "Запуск замены приложения", silent=False)
            return
        app._show_status("info", "Приложение закрывается для установки обновления…")
        app.exit_app()

    def _prompt_downloaded(self, path: Path) -> None:
        app = self.window
        is_installer = path.suffix.lower() in {".exe", ".msi"}
        dialog = QMessageBox(app)
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
            app.logger.error(
                "Не удалось открыть скачанное обновление: %s\n%s",
                sanitize_error_text(exc),
                format_safe_traceback(exc),
            )
            app._show_status("error", f"Не удалось открыть файл: {sanitize_error_text(exc)}")

    def _handle_error(self, error: BaseException, action: str, *, silent: bool) -> None:
        app = self.window
        message = sanitize_error_text(error) or "неизвестная ошибка"
        app.logger.warning("%s приложения не выполнена: %s\n%s", action, message, format_safe_traceback(error))
        if not silent:
            app._show_status("error", f"{action}: {message}")
