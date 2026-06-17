import unittest

from core.connection_runtime import ConnectionRuntimeState
from core.smart_connect import SmartConnectManager
from models.connection import SMART_GROUP_MODE_LOAD_BALANCE, SmartGroup


class FakeClock:
    def __init__(self) -> None:
        self.monotonic = 100.0
        self.iso_values = ["2026-01-01T00:00:00+00:00", "2026-01-01T00:00:12+00:00"]

    def monotonic_now(self) -> float:
        return self.monotonic

    def iso_now(self) -> str:
        return self.iso_values.pop(0)


def runtime(
    smart_connect: SmartConnectManager,
    groups: list[SmartGroup],
    clock: FakeClock,
) -> ConnectionRuntimeState:
    return ConnectionRuntimeState(
        smart_connect=smart_connect,
        smart_groups=groups,
        monotonic_clock=clock.monotonic_now,
        iso_clock=clock.iso_now,
    )


class ConnectionRuntimeStateTests(unittest.TestCase):
    def test_profile_usage_records_full_traffic_and_clears_state(self) -> None:
        clock = FakeClock()
        smart_connect = SmartConnectManager()
        state = runtime(smart_connect, [], clock)
        saved: list[str] = []

        state.begin(profile_ids=["server-a"])
        clock.monotonic = 112.8
        record = state.record_usage_and_clear(
            download_bytes=1200.9,
            upload_bytes=300.1,
            save_quality_stats=lambda: saved.append("stats"),
            save_smart_groups=lambda: saved.append("groups"),
        )

        stats = smart_connect.quality_stats["server-a"]
        self.assertIsNotNone(record)
        self.assertEqual(record.connected_seconds, 12)
        self.assertEqual(record.download_bytes, 1200)
        self.assertEqual(record.upload_bytes, 300)
        self.assertEqual(stats.connection_count, 1)
        self.assertEqual(stats.total_connected_seconds, 12)
        self.assertEqual(stats.total_download_bytes, 1200)
        self.assertEqual(stats.total_upload_bytes, 300)
        self.assertEqual(stats.last_connected_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(stats.last_disconnected_at, "2026-01-01T00:00:12+00:00")
        self.assertEqual(state.active_profile_ids, ())
        self.assertEqual(saved, ["stats", "groups"])

    def test_load_balance_usage_records_group_and_splits_profile_traffic(self) -> None:
        clock = FakeClock()
        smart_connect = SmartConnectManager()
        group = SmartGroup(
            id="group",
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["server-a", "server-b"],
        )
        state = runtime(smart_connect, [group], clock)

        state.begin(profile_ids=["server-a", "server-b"], group_id="group")
        clock.monotonic = 112.0
        record = state.record_usage_and_clear(download_bytes=101, upload_bytes=25)

        self.assertIsNotNone(record)
        self.assertEqual(record.per_profile_download_bytes, 50)
        self.assertEqual(record.per_profile_upload_bytes, 12)
        self.assertEqual(group.usage_connection_count, 1)
        self.assertEqual(group.usage_total_seconds, 12)
        self.assertEqual(group.usage_total_download_bytes, 101)
        self.assertEqual(group.usage_total_upload_bytes, 25)
        self.assertEqual(smart_connect.quality_stats["server-a"].total_download_bytes, 50)
        self.assertEqual(smart_connect.quality_stats["server-b"].total_download_bytes, 50)
        self.assertEqual(smart_connect.quality_stats["server-a"].total_upload_bytes, 12)
        self.assertEqual(smart_connect.quality_stats["server-b"].total_upload_bytes, 12)
        self.assertIsNone(state.active_group_id)

    def test_record_without_active_session_is_noop(self) -> None:
        clock = FakeClock()
        smart_connect = SmartConnectManager()
        state = runtime(smart_connect, [], clock)
        saved: list[str] = []

        record = state.record_usage_and_clear(
            download_bytes=100,
            upload_bytes=50,
            save_quality_stats=lambda: saved.append("stats"),
            save_smart_groups=lambda: saved.append("groups"),
        )

        self.assertIsNone(record)
        self.assertEqual(smart_connect.quality_stats, {})
        self.assertEqual(saved, [])


if __name__ == "__main__":
    unittest.main()
