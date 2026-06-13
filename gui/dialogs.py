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

"""Диалоги для расширенных GUI-сценариев."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PureWindowsPath

from PyQt6.QtWidgets import QDialog, QGridLayout, QHBoxLayout, QMessageBox, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    LineEdit,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    SwitchButton,
)

from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    clean_process_names,
    clean_process_path_regexes,
    clean_process_paths,
    normalize_outbound,
)
from models.settings import AppSettings


MATCH_KIND_PROCESS_NAME = "process_name"
MATCH_KIND_PROCESS_PATH = "process_path"
MATCH_KIND_PROCESS_PATH_REGEX = "process_path_regex"
ONBOARDING_ACTION_IMPORT_SERVER = "import_server"
ONBOARDING_ACTION_ADD_SUBSCRIPTION = "add_subscription"
ONBOARDING_ACTION_DOWNLOAD_CORE = "download_core"
ONBOARDING_ACTION_OPEN_SETTINGS = "open_settings"
ONBOARDING_ACTION_SKIP = "skip"


@dataclass(frozen=True, slots=True)
class ProcessOption:
    name: str
    path: str = ""
    pid: int | None = None

    @property
    def label(self) -> str:
        pid_text = f" · PID {self.pid}" if self.pid is not None else ""
        path_text = f" · {self.path}" if self.path else ""
        return f"{self.name}{pid_text}{path_text}"


@dataclass(frozen=True, slots=True)
class PerAppRuleData:
    name: str
    outbound: str
    match_kind: str
    value: str


@dataclass(frozen=True, slots=True)
class OnboardingResult:
    mode: str
    auto_update_subscriptions: bool
    background_health_check_enabled: bool
    minimize_to_tray: bool
    auto_start_windows: bool
    action: str


def _filename_from_path(path: str) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    return PureWindowsPath(text.replace("/", "\\")).name


def list_running_processes(limit: int = 300) -> list[ProcessOption]:
    try:
        import psutil
    except Exception:
        return []

    options: list[ProcessOption] = []
    seen: set[tuple[str, str]] = set()
    for process in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = process.info
        except (psutil.Error, OSError):
            continue
        name = str(info.get("name") or "").strip()
        path = str(info.get("exe") or "").strip()
        if not name and path:
            name = _filename_from_path(path)
        if not name:
            continue
        key = (name.casefold(), path.casefold())
        if key in seen:
            continue
        seen.add(key)
        pid = info.get("pid")
        options.append(ProcessOption(name=name, path=path, pid=pid if isinstance(pid, int) else None))

    options.sort(key=lambda item: (item.name.casefold(), item.path.casefold(), item.pid or 0))
    return options[: max(0, int(limit))]


class OnboardingDialog(QDialog):
    def __init__(self, settings: AppSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Первый запуск")
        self.resize(760, 520)
        self._result: OnboardingResult | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(14)
        layout.addWidget(SubtitleLabel("Razreshenie VPN Client", self))

        subtitle = CaptionLabel(
            "Быстрая настройка режима, фоновых проверок и первого действия после запуска.",
            self,
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        form = QGridLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        layout.addLayout(form, 1)

        self.mode_combo = ComboBox(self)
        self.mode_combo.addItem("Proxy: SOCKS5 + HTTP", userData="proxy")
        self.mode_combo.addItem("TUN: системный туннель", userData="tun")
        self.mode_combo.setCurrentIndex(1 if settings.mode == "tun" else 0)
        form.addWidget(BodyLabel("Режим подключения", self), 0, 0)
        form.addWidget(self.mode_combo, 0, 1)

        self.auto_update_switch = self._switch(bool(settings.auto_update_subscriptions))
        form.addWidget(BodyLabel("Автообновление подписок", self), 1, 0)
        form.addWidget(self.auto_update_switch, 1, 1)

        self.health_switch = self._switch(bool(settings.background_health_check_enabled))
        form.addWidget(BodyLabel("Фоновая проверка соединения", self), 2, 0)
        form.addWidget(self.health_switch, 2, 1)

        self.tray_switch = self._switch(bool(settings.minimize_to_tray))
        form.addWidget(BodyLabel("Сворачивать в трей", self), 3, 0)
        form.addWidget(self.tray_switch, 3, 1)

        self.auto_start_switch = self._switch(bool(settings.auto_start_windows))
        form.addWidget(BodyLabel("Автозапуск Windows", self), 4, 0)
        form.addWidget(self.auto_start_switch, 4, 1)

        self.action_combo = ComboBox(self)
        self.action_combo.addItem("Импортировать сервер", userData=ONBOARDING_ACTION_IMPORT_SERVER)
        self.action_combo.addItem("Добавить подписку", userData=ONBOARDING_ACTION_ADD_SUBSCRIPTION)
        self.action_combo.addItem("Скачать/обновить sing-box", userData=ONBOARDING_ACTION_DOWNLOAD_CORE)
        self.action_combo.addItem("Открыть настройки", userData=ONBOARDING_ACTION_OPEN_SETTINGS)
        self.action_combo.addItem("Ничего, открыть приложение", userData=ONBOARDING_ACTION_SKIP)
        form.addWidget(BodyLabel("После мастера", self), 5, 0)
        form.addWidget(self.action_combo, 5, 1)

        note = CaptionLabel(
            "TUN-режим может потребовать права администратора только при подключении. "
            "Мастер не подключает VPN автоматически.",
            self,
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.skip_btn = PushButton("Пропустить", self)
        self.done_btn = PrimaryPushButton(FIF.ACCEPT, "Готово", self)
        buttons.addWidget(self.skip_btn)
        buttons.addWidget(self.done_btn)
        layout.addLayout(buttons)

        self.skip_btn.clicked.connect(self._skip)
        self.done_btn.clicked.connect(self._accept)

    @staticmethod
    def _switch(checked: bool) -> SwitchButton:
        switch = SwitchButton()
        switch.setChecked(checked)
        return switch

    def onboarding_result(self) -> OnboardingResult:
        return self._result or self._build_result()

    def _build_result(self, *, action: str | None = None) -> OnboardingResult:
        selected_action = action or str(self.action_combo.currentData() or ONBOARDING_ACTION_SKIP)
        return OnboardingResult(
            mode="tun" if self.mode_combo.currentData() == "tun" else "proxy",
            auto_update_subscriptions=self.auto_update_switch.isChecked(),
            background_health_check_enabled=self.health_switch.isChecked(),
            minimize_to_tray=self.tray_switch.isChecked(),
            auto_start_windows=self.auto_start_switch.isChecked(),
            action=selected_action,
        )

    def _skip(self) -> None:
        self._result = self._build_result(action=ONBOARDING_ACTION_SKIP)
        self.accept()

    def _accept(self) -> None:
        self._result = self._build_result()
        self.accept()


class PerAppRuleDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Per-app routing")
        self.resize(720, 380)
        self._processes: list[ProcessOption] = []
        self._data: PerAppRuleData | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)
        layout.addWidget(SubtitleLabel("Маршрутизация приложения", self))
        hint = CaptionLabel(
            "Правило будет добавлено в sing-box routing через process_name, process_path или process_path_regex.",
            self,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QGridLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(10)
        layout.addLayout(form, 1)

        self.name_edit = LineEdit(self)
        self.name_edit.setPlaceholderText("Например: Telegram напрямую")
        form.addWidget(BodyLabel("Название", self), 0, 0)
        form.addWidget(self.name_edit, 0, 1)

        self.route_combo = ComboBox(self)
        self.route_combo.addItem("Текущий сервер", userData=ROUTE_OUTBOUND_PROXY)
        self.route_combo.addItem("Напрямую", userData=ROUTE_OUTBOUND_DIRECT)
        form.addWidget(BodyLabel("Маршрут", self), 1, 0)
        form.addWidget(self.route_combo, 1, 1)

        self.match_combo = ComboBox(self)
        self.match_combo.addItem("Имя процесса", userData=MATCH_KIND_PROCESS_NAME)
        self.match_combo.addItem("Полный путь", userData=MATCH_KIND_PROCESS_PATH)
        self.match_combo.addItem("Regex пути", userData=MATCH_KIND_PROCESS_PATH_REGEX)
        form.addWidget(BodyLabel("Тип правила", self), 2, 0)
        form.addWidget(self.match_combo, 2, 1)

        process_row = QHBoxLayout()
        process_row.setSpacing(8)
        self.process_combo = ComboBox(self)
        self.process_combo.setMinimumWidth(420)
        self.refresh_btn = PushButton(FIF.SYNC, "Обновить", self)
        process_row.addWidget(self.process_combo, 1)
        process_row.addWidget(self.refresh_btn)
        form.addWidget(BodyLabel("Активный процесс", self), 3, 0)
        form.addLayout(process_row, 3, 1)

        self.value_edit = LineEdit(self)
        self.value_edit.setPlaceholderText("Telegram.exe")
        form.addWidget(BodyLabel("Значение", self), 4, 0)
        form.addWidget(self.value_edit, 4, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.save_btn = PrimaryPushButton(FIF.ADD, "Создать", self)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.save_btn)
        layout.addLayout(buttons)

        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self._accept_if_valid)
        self.refresh_btn.clicked.connect(self._refresh_processes)
        self.process_combo.currentIndexChanged.connect(lambda _index: self._apply_selected_process())
        self.match_combo.currentIndexChanged.connect(lambda _index: self._on_match_kind_changed())
        self.route_combo.currentIndexChanged.connect(lambda _index: self._suggest_name_if_empty())

        self._refresh_processes()
        self._on_match_kind_changed()

    def rule_data(self) -> PerAppRuleData | None:
        return self._data or self._build_rule_data(show_errors=False)

    def _refresh_processes(self) -> None:
        self._processes = list_running_processes()
        self.process_combo.clear()
        if not self._processes:
            self.process_combo.addItem("Активные процессы не найдены", userData=-1)
            return
        for index, process in enumerate(self._processes):
            self.process_combo.addItem(process.label, userData=index)
        self._apply_selected_process()

    def _selected_process(self) -> ProcessOption | None:
        index = self.process_combo.currentData()
        if isinstance(index, int) and 0 <= index < len(self._processes):
            return self._processes[index]
        return None

    def _match_kind(self) -> str:
        value = str(self.match_combo.currentData() or MATCH_KIND_PROCESS_NAME)
        if value in {MATCH_KIND_PROCESS_NAME, MATCH_KIND_PROCESS_PATH, MATCH_KIND_PROCESS_PATH_REGEX}:
            return value
        return MATCH_KIND_PROCESS_NAME

    def _on_match_kind_changed(self) -> None:
        kind = self._match_kind()
        if kind == MATCH_KIND_PROCESS_NAME:
            self.value_edit.setPlaceholderText("Telegram.exe")
        elif kind == MATCH_KIND_PROCESS_PATH:
            self.value_edit.setPlaceholderText(r"C:\Program Files\Telegram Desktop\Telegram.exe")
        else:
            self.value_edit.setPlaceholderText(r"(?i).*\\Telegram\.exe$")
        self._apply_selected_process()

    def _apply_selected_process(self) -> None:
        process = self._selected_process()
        if not process:
            return
        value = self._value_for_process(process, self._match_kind())
        if value:
            self.value_edit.setText(value)
        self._suggest_name_if_empty(process)

    def _suggest_name_if_empty(self, process: ProcessOption | None = None) -> None:
        if self.name_edit.text().strip():
            return
        process = process or self._selected_process()
        if not process:
            return
        route = "VPN" if normalize_outbound(str(self.route_combo.currentData())) == ROUTE_OUTBOUND_PROXY else "direct"
        self.name_edit.setText(f"{process.name}: {route}")

    @staticmethod
    def _value_for_process(process: ProcessOption, match_kind: str) -> str:
        if match_kind == MATCH_KIND_PROCESS_NAME:
            return process.name
        if match_kind == MATCH_KIND_PROCESS_PATH:
            return process.path
        if process.path:
            return "(?i)" + re.escape(process.path.replace("/", "\\"))
        return rf"(?i)(^|.*[\\/]){re.escape(process.name)}$"

    def _build_rule_data(self, *, show_errors: bool) -> PerAppRuleData | None:
        match_kind = self._match_kind()
        raw_value = self.value_edit.text().strip()
        value = self._normalize_value(match_kind, raw_value, show_errors=show_errors)
        if not value:
            return None
        name = self.name_edit.text().strip() or f"Per-app: {value}"
        return PerAppRuleData(
            name=name,
            outbound=normalize_outbound(str(self.route_combo.currentData() or ROUTE_OUTBOUND_PROXY)),
            match_kind=match_kind,
            value=value,
        )

    def _normalize_value(self, match_kind: str, raw_value: str, *, show_errors: bool) -> str:
        if not raw_value:
            self._warn(show_errors, "Укажи имя процесса, путь или regex.")
            return ""
        if match_kind == MATCH_KIND_PROCESS_NAME:
            values = clean_process_names([raw_value])
        elif match_kind == MATCH_KIND_PROCESS_PATH:
            values = clean_process_paths([raw_value])
        else:
            try:
                re.compile(raw_value)
            except re.error as exc:
                self._warn(show_errors, f"Некорректный regex пути: {exc}")
                return ""
            values = clean_process_path_regexes([raw_value])
        if not values:
            self._warn(show_errors, "Значение стало пустым после нормализации.")
            return ""
        return values[0]

    def _warn(self, enabled: bool, message: str) -> None:
        if enabled:
            QMessageBox.warning(self, "Некорректное правило", message)

    def _accept_if_valid(self) -> None:
        data = self._build_rule_data(show_errors=True)
        if not data:
            return
        self._data = data
        self.accept()
