import unittest

from core.profile_state_service import ProfileStateService
from core.smart_connect import SmartConnectManager
from models.profile import VlessProfile


def profile(profile_id: str, *, name: str | None = None, latency_ms: int | None = None) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=name or profile_id,
        address=f"{profile_id}.example.com",
        latency_ms=latency_ms,
    )


class ProfileStateServiceTests(unittest.TestCase):
    def test_import_profiles_appends_and_selects_first_imported_profile(self) -> None:
        service = ProfileStateService(SmartConnectManager())
        existing = profile("existing")
        imported = [profile("new-a"), profile("new-b")]

        change = service.apply_import(
            profiles=[existing],
            imported_profiles=imported,
            active_profile_id="existing",
        )

        self.assertEqual([item.id for item in change.profiles], ["existing", "new-a", "new-b"])
        self.assertEqual(change.active_profile_id, "new-a")
        self.assertEqual(change.changed_profile_ids, ("new-a", "new-b"))
        self.assertEqual(change.imported_count, 2)

    def test_delete_active_profile_selects_next_or_none(self) -> None:
        service = ProfileStateService(SmartConnectManager())

        change = service.delete_profile(
            profiles=[profile("a"), profile("b")],
            profile_id="a",
            active_profile_id="a",
        )
        self.assertEqual([item.id for item in change.profiles], ["b"])
        self.assertEqual(change.active_profile_id, "b")

        empty = service.delete_profile(
            profiles=[profile("a")],
            profile_id="a",
            active_profile_id="a",
        )
        self.assertEqual(empty.profiles, [])
        self.assertIsNone(empty.active_profile_id)

    def test_replace_profile_preserves_position_and_repairs_active_id(self) -> None:
        service = ProfileStateService(SmartConnectManager(), timestamp_factory=lambda: "unused")
        original = [profile("a"), profile("b"), profile("c")]
        updated = profile("b-new", name="B new")
        updated.created_at = "2026-01-01T00:00:00+00:00"

        change = service.replace_profile(
            profiles=original,
            profile_id="b",
            updated_profile=updated,
            active_profile_id="b",
        )

        self.assertEqual([item.id for item in change.profiles], ["a", "b-new", "c"])
        self.assertEqual(change.active_profile_id, "b-new")
        self.assertEqual(change.profiles[1].name, "B new")
        self.assertNotEqual(change.profiles[1].updated_at, "2026-01-01T00:00:00+00:00")

    def test_latency_batch_updates_profiles_and_quality_stats(self) -> None:
        smart_connect = SmartConnectManager()
        service = ProfileStateService(smart_connect, timestamp_factory=lambda: "2026-01-01T00:00:00+00:00")
        profiles = [profile("a"), profile("b")]

        result = service.apply_latency_batch(profiles, [("a", 42), ("missing", 10), ("b", None)])

        self.assertEqual(result.changed_profile_ids, ("a", "b"))
        self.assertEqual(profiles[0].latency_ms, 42)
        self.assertEqual(profiles[0].latency_checked_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(profiles[1].latency_ms, None)
        self.assertEqual(smart_connect.quality_stats["a"].last_latency_ms, 42)
        self.assertEqual(smart_connect.quality_stats["a"].success_count, 1)
        self.assertEqual(smart_connect.quality_stats["b"].failure_count, 1)

    def test_sort_by_latency_orders_known_latency_before_unknown_then_name(self) -> None:
        service = ProfileStateService(SmartConnectManager())
        profiles = [
            profile("unknown", name="Unknown", latency_ms=None),
            profile("slow", name="Slow", latency_ms=200),
            profile("fast-b", name="Beta", latency_ms=20),
            profile("fast-a", name="Alpha", latency_ms=20),
        ]

        change = service.sort_by_latency(profiles, active_profile_id="slow")

        self.assertEqual([item.id for item in change.profiles], ["fast-a", "fast-b", "slow", "unknown"])
        self.assertEqual(change.active_profile_id, "slow")


if __name__ == "__main__":
    unittest.main()
