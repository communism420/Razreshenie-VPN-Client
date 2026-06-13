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

"""Переиспользуемые GUI-виджеты Razreshenie VPN."""

from __future__ import annotations

import json
import math
import time
from collections import deque

from PyQt6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import LineEdit, PlainTextEdit, PrimaryPushButton, PushButton, SettingCard, SpinBox


class TrafficGraphWidget(QWidget):
    """Живой график входящего/исходящего трафика, как компактные карточки zapret-kvn."""

    def __init__(self, parent: QWidget | None = None, max_points: int = 80) -> None:
        super().__init__(parent)
        self._down: deque[float] = deque(maxlen=max_points + 1)
        self._up: deque[float] = deque(maxlen=max_points + 1)
        self._max_points = max_points
        self._scroll_progress = 0.0
        self._display_scale = 100.0
        self._target_scale = 100.0
        self._peak_down = 0.0
        self._peak_up = 0.0
        self._current_down = 0.0
        self._current_up = 0.0
        self._animation_started = 0.0
        self._animation_duration = 0.92
        self._easing = QEasingCurve(QEasingCurve.Type.InOutCubic)
        self._animation_timer = QTimer(self)
        self._animation_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._animation_timer.setInterval(16)
        self._animation_timer.timeout.connect(self._animation_step)
        self.setMinimumHeight(166)

    def add_point(self, down_bps: float, up_bps: float) -> None:
        if self._animation_timer.isActive():
            self._finish_scroll()
        self._current_down = max(0.0, float(down_bps or 0.0))
        self._current_up = max(0.0, float(up_bps or 0.0))
        self._peak_down = max(self._peak_down, self._current_down)
        self._peak_up = max(self._peak_up, self._current_up)
        self._down.append(self._current_down)
        self._up.append(self._current_up)
        self._target_scale = self._calculate_scale(self._scroll_series(self._down), self._scroll_series(self._up))
        if self._target_scale > self._display_scale:
            self._display_scale = self._target_scale
        self._scroll_progress = 0.0
        self._animation_started = time.monotonic()
        if not self._animation_timer.isActive():
            self._animation_timer.start()
        self.update()

    def clear_data(self) -> None:
        self._down.clear()
        self._up.clear()
        self._scroll_progress = 0.0
        self._display_scale = 100.0
        self._target_scale = 100.0
        self._peak_down = 0.0
        self._peak_up = 0.0
        self._current_down = 0.0
        self._current_up = 0.0
        self._animation_timer.stop()
        self.update()

    @staticmethod
    def _calculate_scale(down_values: list[float], up_values: list[float]) -> float:
        raw_max = max(max(down_values + up_values, default=1.0), 100.0)
        return TrafficGraphWidget._nice_scale(raw_max * 1.18)

    @staticmethod
    def _nice_scale(value: float) -> float:
        if value <= 0:
            return 100.0
        exponent = math.floor(math.log10(value))
        fraction = value / 10**exponent
        if fraction <= 1:
            nice = 1
        elif fraction <= 2:
            nice = 2
        elif fraction <= 5:
            nice = 5
        else:
            nice = 10
        return float(nice * 10**exponent)

    def _scroll_series(self, values: deque[float]) -> list[float]:
        items = list(values)
        required = self._max_points + 1
        if len(items) >= required:
            return items[-required:]
        return [0.0] * (required - len(items)) + items

    def _stable_series(self, values: deque[float]) -> list[float]:
        items = list(values)
        if len(items) >= self._max_points:
            return items[-self._max_points :]
        return [0.0] * (self._max_points - len(items)) + items

    def _animation_step(self) -> None:
        if self._apply_animation_progress(time.monotonic()):
            self.update()
            return
        self._animation_timer.stop()
        self._finish_scroll(update=False)
        self.update()

    def _apply_animation_progress(self, now: float) -> bool:
        elapsed = max(0.0, now - self._animation_started)
        progress = min(1.0, elapsed / self._animation_duration) if self._animation_duration > 0 else 1.0
        self._scroll_progress = float(self._easing.valueForProgress(progress))
        if self._target_scale < self._display_scale:
            self._display_scale += (self._target_scale - self._display_scale) * 0.025
        return progress < 1.0

    def _finish_scroll(self, update: bool = True) -> None:
        self._animation_timer.stop()
        self._down = deque(list(self._down)[-self._max_points :], maxlen=self._max_points + 1)
        self._up = deque(list(self._up)[-self._max_points :], maxlen=self._max_points + 1)
        self._scroll_progress = 0.0
        self._target_scale = self._calculate_scale(self._stable_series(self._down), self._stable_series(self._up))
        if update:
            self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(8, 16, 24, 42))
        painter.drawRoundedRect(rect, 6, 6)

        pad_x, pad_top, pad_bottom = 14, 40, 24
        graph_x = rect.x() + pad_x
        graph_y = rect.y() + pad_top
        graph_w = max(1.0, rect.width() - pad_x * 2)
        graph_h = max(1.0, rect.height() - pad_top - pad_bottom)

        scale = max(self._display_scale, self._target_scale, 100.0)
        self._draw_header(painter, rect, scale)
        grid_pen = QPen(QColor(255, 255, 255, 22))
        grid_pen.setWidthF(0.5)
        painter.setPen(grid_pen)
        for index in range(4):
            y = graph_y + graph_h * index / 3
            painter.drawLine(QPointF(graph_x, y), QPointF(graph_x + graph_w, y))
            if index in (0, 3):
                label = self._format_speed(scale if index == 0 else 0.0)
                painter.setPen(QColor(210, 220, 230, 150))
                painter.drawText(QRectF(graph_x + 4, y - 16 if index == 0 else y - 2, 110, 18), Qt.AlignmentFlag.AlignLeft, label)
                painter.setPen(grid_pen)

        is_scrolling = self._animation_timer.isActive()
        down_values = self._scroll_series(self._down) if is_scrolling else self._stable_series(self._down)
        up_values = self._scroll_series(self._up) if is_scrolling else self._stable_series(self._up)
        painter.save()
        painter.setClipRect(QRectF(graph_x, graph_y, graph_w, graph_h))
        self._draw_series(
            painter,
            down_values,
            QColor(0, 180, 255),
            graph_x,
            graph_y,
            graph_w,
            graph_h,
            scale,
            self._scroll_progress if is_scrolling else 0.0,
        )
        self._draw_series(
            painter,
            up_values,
            QColor(0, 220, 120),
            graph_x,
            graph_y,
            graph_w,
            graph_h,
            scale,
            self._scroll_progress if is_scrolling else 0.0,
        )
        painter.restore()
        if not any(value > 0 for value in down_values + up_values):
            painter.setPen(QColor(210, 220, 230, 120))
            painter.drawText(QRectF(graph_x, graph_y, graph_w, graph_h), Qt.AlignmentFlag.AlignCenter, "Нет трафика")
        painter.end()

    def _draw_header(self, painter: QPainter, rect: QRectF, scale: float) -> None:
        painter.save()
        title_font = QFont(painter.font())
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QColor(240, 246, 255, 222))
        painter.drawText(QRectF(rect.x() + 14, rect.y() + 10, rect.width() * 0.42, 20), Qt.AlignmentFlag.AlignLeft, "Скорость")
        painter.setFont(QFont())
        down_color = QColor(0, 180, 255)
        up_color = QColor(0, 220, 120)
        legend_y = rect.y() + 12
        right_x = rect.right() - 14
        legend_text = (
            f"↓ {self._format_speed(self._current_down)}   "
            f"↑ {self._format_speed(self._current_up)}   "
            f"пик {self._format_speed(max(self._peak_down, self._peak_up, scale / 10))}"
        )
        painter.setPen(QColor(220, 230, 240, 190))
        painter.drawText(QRectF(rect.x() + 120, rect.y() + 10, max(80.0, rect.width() - 134), 20), Qt.AlignmentFlag.AlignRight, legend_text)
        self._draw_legend_dot(painter, right_x - 236, legend_y + 7, down_color)
        self._draw_legend_dot(painter, right_x - 124, legend_y + 7, up_color)
        painter.restore()

    @staticmethod
    def _draw_legend_dot(painter: QPainter, x: float, y: float, color: QColor) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(QPointF(x, y), 3.2, 3.2)

    @staticmethod
    def _format_speed(bytes_per_second: float) -> str:
        units = ("Б/с", "КБ/с", "МБ/с", "ГБ/с")
        value = float(max(0.0, bytes_per_second))
        unit_index = 0
        while value >= 1024 and unit_index < len(units) - 1:
            value /= 1024
            unit_index += 1
        return f"{value:.1f} {units[unit_index]}"

    def _draw_series(
        self,
        painter: QPainter,
        values: list[float],
        color: QColor,
        graph_x: float,
        graph_y: float,
        graph_w: float,
        graph_h: float,
        scale: float,
        scroll_progress: float,
    ) -> None:
        if len(values) < 2:
            return
        points: list[QPointF] = []
        step = graph_w / max(1, self._max_points - 1)
        for index, value in enumerate(values):
            x = graph_x + (index - scroll_progress) * step
            y = graph_y + graph_h - min(1.0, value / scale) * graph_h
            points.append(QPointF(x, y))

        path = QPainterPath(points[0])
        for index in range(1, len(points)):
            previous = points[index - 1]
            current = points[index]
            control_dx = (current.x() - previous.x()) * 0.55
            path.cubicTo(
                QPointF(previous.x() + control_dx, previous.y()),
                QPointF(current.x() - control_dx, current.y()),
                current,
            )

        fill_color = QColor(color)
        fill_color.setAlpha(54)
        transparent = QColor(color)
        transparent.setAlpha(0)
        gradient = QLinearGradient(QPointF(0, graph_y), QPointF(0, graph_y + graph_h))
        gradient.setColorAt(0.0, fill_color)
        gradient.setColorAt(1.0, transparent)
        fill_path = QPainterPath(path)
        fill_path.lineTo(points[-1].x(), graph_y + graph_h)
        fill_path.lineTo(points[0].x(), graph_y + graph_h)
        fill_path.closeSubpath()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(gradient))
        painter.drawPath(fill_path)

        glow = QColor(color)
        glow.setAlpha(70)
        glow_pen = QPen(glow)
        glow_pen.setWidthF(5.2)
        glow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        glow_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(glow_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        pen = QPen(color)
        pen.setWidthF(2.15)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.drawPath(path)


class _LineCard(SettingCard):
    def __init__(self, icon, title: str, content: str, parent: QWidget | None = None) -> None:
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setMinimumWidth(360)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _SpinCard(SettingCard):
    def __init__(
        self,
        icon,
        title: str,
        content: str,
        minimum: int,
        maximum: int,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(icon, title, content, parent)
        self.spin = SpinBox(self)
        self.spin.setRange(minimum, maximum)
        self.spin.setMinimumWidth(160)
        self.hBoxLayout.addWidget(self.spin, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class JsonEditorDialog(QDialog):
    def __init__(self, title: str, data: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 620)
        layout = QVBoxLayout(self)
        self.editor = PlainTextEdit(self)
        self.editor.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
        layout.addWidget(self.editor, 1)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.save_btn = PrimaryPushButton("Сохранить", self)
        buttons.addWidget(self.cancel_btn)
        buttons.addWidget(self.save_btn)
        layout.addLayout(buttons)
        self.cancel_btn.clicked.connect(self.reject)
        self.save_btn.clicked.connect(self.accept)

    def data(self) -> dict:
        return json.loads(self.editor.toPlainText())
