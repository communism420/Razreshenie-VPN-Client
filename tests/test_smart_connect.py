import unittest

from core.smart_connect import SMART_CONNECT_FAILURE_COOLDOWN_MINUTES, SmartConnectManager
from models.connection import (
    QUALITY_EVENT_FAILURE,
    QUALITY_EVENT_SUCCESS,
    SMART_STRATEGY_FAILOVER_ORDER,
    ServerQualityStats,
    SmartGroup,
)
from models.profile import VlessProfile


def profile(
    profile_id: str,
    *,
    name: str | None = None,
    address: str | None = None,
    port: int = 443,
    subscription_id: str = "sub",
    group: str = "group",
    latency_ms: int | None = None,
) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=name or profile_id,
        address=address if address is not None else f"{profile_id}.example.com",
        port=port,
        subscription_id=subscription_id,
        group=group,
        latency_ms=latency_ms,
    )


class SmartConnectManagerTests(unittest.TestCase):
    def test_candidate_profiles_drop_invalid_profiles(self) -> None:
        manager = SmartConnectManager()
        profiles = [
            profile("valid", latency_ms=80),
            profile("empty-host", address="", latency_ms=10),
            profile("bad-port", port=0, latency_ms=10),
        ]

        candidates = manager.candidate_profiles(profiles[0], profiles)

        self.assertEqual([item.id for item in candidates], ["valid"])

    def test_cooldown_penalty_keeps_recently_failed_fast_server_behind(self) -> None:
        profiles = [
            profile("stable", latency_ms=120),
            profile("fast-but-failed", latency_ms=20),
        ]
        stats = ServerQualityStats(
            profile_id="fast-but-failed",
            latency_ewma_ms=20,
            failure_count=2,
            consecutive_failures=2,
            cooldown_until="2999-01-01T00:00:00+00:00",
        )
        manager = SmartConnectManager({"fast-but-failed": stats})

        decision = manager.choose_best(profiles[0], profiles)

        self.assertIsNotNone(decision.selected)
        self.assertEqual(decision.selected.id, "stable")

    def test_ordered_failover_rotates_after_current_profile_and_skips_failed(self) -> None:
        profiles = [profile("a"), profile("b"), profile("c")]
        manager = SmartConnectManager(
            smart_groups=[
                SmartGroup(
                    name="ordered",
                    strategy=SMART_STRATEGY_FAILOVER_ORDER,
                    profile_ids=["a", "b", "c"],
                )
            ]
        )

        decision = manager.choose_failover_next(
            profiles[0],
            profiles,
            current_profile=profiles[1],
            failed_ids={"a", "b"},
        )

        self.assertIsNotNone(decision.selected)
        self.assertEqual(decision.selected.id, "c")
        self.assertEqual([candidate.profile.id for candidate in decision.candidates], ["c"])

    def test_failure_cooldown_and_success_recovery(self) -> None:
        manager = SmartConnectManager()

        manager.record_failure("server-a", checked_at="2026-01-01T00:00:00+00:00", message="first")
        stats = manager.record_failure("server-a", checked_at="2026-01-01T00:01:00+00:00", message="second")

        self.assertEqual(stats.failure_count, 2)
        self.assertEqual(stats.consecutive_failures, 2)
        self.assertIsNotNone(stats.cooldown_until)
        self.assertEqual(stats.last_event.event, QUALITY_EVENT_FAILURE)
        self.assertEqual(SMART_CONNECT_FAILURE_COOLDOWN_MINUTES, 10)

        recovered = manager.record_success("server-a", checked_at="2026-01-01T00:02:00+00:00")

        self.assertEqual(recovered.consecutive_failures, 0)
        self.assertIsNone(recovered.cooldown_until)
        self.assertEqual(recovered.last_event.event, QUALITY_EVENT_SUCCESS)

    def test_prune_missing_profiles_removes_stats_and_group_members(self) -> None:
        manager = SmartConnectManager(
            quality_stats={
                "keep": ServerQualityStats(profile_id="keep"),
                "drop": ServerQualityStats(profile_id="drop"),
            },
            smart_groups=[SmartGroup(name="group", profile_ids=["keep", "drop"])],
        )

        manager.prune_missing_profiles(["keep"])

        self.assertEqual(list(manager.quality_stats), ["keep"])
        self.assertEqual(manager.smart_groups[0].profile_ids, ["keep"])


if __name__ == "__main__":
    unittest.main()
