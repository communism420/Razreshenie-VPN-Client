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

"""Runtime state and usage accounting for the active connection."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import time

from core.smart_connect import SmartConnectManager
from models.connection import SMART_GROUP_MODE_LOAD_BALANCE, SmartGroup, normalize_smart_group_mode
from models.profile import utc_now_iso


StateSaver = Callable[[], None]


@dataclass(frozen=True, slots=True)
class ConnectionUsageRecord:
    profile_ids: tuple[str, ...]
    group_id: str | None
    connected_seconds: int
    download_bytes: int
    upload_bytes: int
    connected_at: str
    disconnected_at: str
    per_profile_download_bytes: int
    per_profile_upload_bytes: int


@dataclass(frozen=True, slots=True)
class _ActiveConnection:
    profile_ids: tuple[str, ...]
    group_id: str | None
    connected_at: str
    started_monotonic: float


class ConnectionRuntimeState:
    """Tracks one active runtime session and writes usage into quality stats."""

    def __init__(
        self,
        *,
        smart_connect: SmartConnectManager,
        smart_groups: Sequence[SmartGroup],
        monotonic_clock: Callable[[], float] = time.monotonic,
        iso_clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self.smart_connect = smart_connect
        self.smart_groups = smart_groups
        self._monotonic_clock = monotonic_clock
        self._iso_clock = iso_clock
        self._active: _ActiveConnection | None = None

    @property
    def active_group_id(self) -> str | None:
        return self._active.group_id if self._active else None

    @property
    def active_profile_ids(self) -> tuple[str, ...]:
        return self._active.profile_ids if self._active else ()

    def active_group(self) -> SmartGroup | None:
        group_id = self.active_group_id
        if not group_id:
            return None
        return next((group for group in self.smart_groups if group.id == group_id), None)

    def begin(self, *, profile_ids: Sequence[str], group_id: str | None = None) -> None:
        clean_profile_ids = tuple(str(profile_id).strip() for profile_id in profile_ids if str(profile_id).strip())
        if not clean_profile_ids:
            raise ValueError("Active connection runtime requires at least one profile id")
        self._active = _ActiveConnection(
            profile_ids=clean_profile_ids,
            group_id=str(group_id).strip() if group_id else None,
            connected_at=self._iso_clock(),
            started_monotonic=float(self._monotonic_clock()),
        )

    def clear(self) -> None:
        self._active = None

    def record_usage_and_clear(
        self,
        *,
        download_bytes: float,
        upload_bytes: float,
        save_quality_stats: StateSaver | None = None,
        save_smart_groups: StateSaver | None = None,
    ) -> ConnectionUsageRecord | None:
        active = self._active
        if not active:
            return None

        disconnected_at = self._iso_clock()
        connected_seconds = max(0, int(float(self._monotonic_clock()) - active.started_monotonic))
        total_download = max(0, int(download_bytes))
        total_upload = max(0, int(upload_bytes))
        group = self.active_group()

        if group:
            group.record_usage(
                connected_seconds=connected_seconds,
                download_bytes=total_download,
                upload_bytes=total_upload,
                connected_at=active.connected_at,
                disconnected_at=disconnected_at,
            )
            if normalize_smart_group_mode(group.mode) == SMART_GROUP_MODE_LOAD_BALANCE:
                per_profile_download = total_download // len(active.profile_ids)
                per_profile_upload = total_upload // len(active.profile_ids)
            else:
                per_profile_download = total_download
                per_profile_upload = total_upload
        else:
            per_profile_download = total_download
            per_profile_upload = total_upload

        for profile_id in active.profile_ids:
            self.smart_connect.record_usage(
                profile_id,
                connected_seconds=connected_seconds,
                download_bytes=per_profile_download,
                upload_bytes=per_profile_upload,
                connected_at=active.connected_at,
                disconnected_at=disconnected_at,
            )

        record = ConnectionUsageRecord(
            profile_ids=active.profile_ids,
            group_id=active.group_id,
            connected_seconds=connected_seconds,
            download_bytes=total_download,
            upload_bytes=total_upload,
            connected_at=active.connected_at,
            disconnected_at=disconnected_at,
            per_profile_download_bytes=per_profile_download,
            per_profile_upload_bytes=per_profile_upload,
        )
        self.clear()
        if save_quality_stats:
            save_quality_stats()
        if save_smart_groups:
            save_smart_groups()
        return record
