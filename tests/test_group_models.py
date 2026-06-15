import unittest

from models.connection import (
    SMART_GROUP_MODE_FAILOVER,
    SMART_GROUP_MODE_LOAD_BALANCE,
    ServerQualityStats,
    SmartGroup,
)


class GroupModelTests(unittest.TestCase):
    def test_old_smart_group_defaults_to_failover_mode(self) -> None:
        group = SmartGroup.from_dict({"name": "legacy", "profile_ids": ["a", "b"]})

        self.assertEqual(group.mode, SMART_GROUP_MODE_FAILOVER)
        self.assertEqual(group.profile_ids, ["a", "b"])
        self.assertEqual(group.load_balance_tolerance_ms, 50)

    def test_group_usage_stats_are_serialized(self) -> None:
        group = SmartGroup(name="balanced", mode=SMART_GROUP_MODE_LOAD_BALANCE)

        group.record_usage(
            connected_seconds=12,
            download_bytes=100,
            upload_bytes=25,
            connected_at="2026-01-01T00:00:00+00:00",
            disconnected_at="2026-01-01T00:00:12+00:00",
        )
        restored = SmartGroup.from_dict(group.to_dict())

        self.assertEqual(restored.usage_connection_count, 1)
        self.assertEqual(restored.usage_total_seconds, 12)
        self.assertEqual(restored.usage_total_download_bytes, 100)
        self.assertEqual(restored.usage_total_upload_bytes, 25)

    def test_server_usage_stats_are_serialized(self) -> None:
        stats = ServerQualityStats(profile_id="server")

        stats.record_usage(
            connected_seconds=30,
            download_bytes=1024,
            upload_bytes=512,
            connected_at="2026-01-01T00:00:00+00:00",
            disconnected_at="2026-01-01T00:00:30+00:00",
        )
        restored = ServerQualityStats.from_dict(stats.to_dict())

        self.assertEqual(restored.connection_count, 1)
        self.assertEqual(restored.total_connected_seconds, 30)
        self.assertEqual(restored.total_download_bytes, 1024)
        self.assertEqual(restored.total_upload_bytes, 512)


if __name__ == "__main__":
    unittest.main()
