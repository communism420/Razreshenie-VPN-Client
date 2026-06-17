import unittest

from core.subscription_state_service import SubscriptionStateService
from core.subscription_types import SubscriptionFetchResult
from models.profile import Subscription, VlessProfile


def subscription(subscription_id: str, *, name: str | None = None) -> Subscription:
    return Subscription(id=subscription_id, name=name or subscription_id, url=f"https://example.com/{subscription_id}")


def profile(
    profile_id: str,
    *,
    name: str,
    subscription_id: str,
    address: str = "server.example.com",
    latency_ms: int | None = None,
) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=name,
        protocol="vless",
        address=address,
        port=443,
        uuid=f"00000000-0000-4000-8000-{abs(hash(profile_id)) % 10**12:012d}",
        subscription_id=subscription_id,
        latency_ms=latency_ms,
        latency_checked_at="2026-01-01T00:00:00+00:00" if latency_ms is not None else None,
    )


class SubscriptionStateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SubscriptionStateService()

    def test_update_preserves_existing_profile_identity_latency_and_active_profile(self) -> None:
        sub = subscription("sub")
        old_active = profile("old-active", name="Server A", subscription_id="sub", latency_ms=42)
        old_active.created_at = "2026-01-01T00:00:00+00:00"
        manual = VlessProfile(id="manual", name="Manual", address="manual.example.com")
        incoming = profile("new-active", name="Server A", subscription_id="sub")
        incoming.uuid = old_active.uuid

        change = self.service.apply_update(
            subscriptions=[sub],
            profiles=[manual, old_active],
            active_profile_id="old-active",
            subscription=sub,
            incoming_profiles=[incoming],
        )

        self.assertEqual(change.active_profile_id, "old-active")
        self.assertEqual([item.id for item in change.profiles], ["manual", "old-active"])
        restored = change.profiles[1]
        self.assertEqual(restored.created_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(restored.latency_ms, 42)
        self.assertEqual(restored.latency_checked_at, "2026-01-01T00:00:00+00:00")
        self.assertEqual(change.profile_counts, {"sub": 1})
        self.assertEqual(change.subscriptions[0].profile_count, 1)

    def test_batch_update_applies_success_and_records_formatted_error(self) -> None:
        sub_ok = subscription("ok", name="OK")
        sub_fail = subscription("fail", name="Fail")
        incoming = profile("incoming", name="Server", subscription_id="ok")

        change = self.service.apply_batch_results(
            subscriptions=[sub_ok, sub_fail],
            profiles=[],
            active_profile_id=None,
            results=[
                SubscriptionFetchResult(subscription=sub_ok, profiles=[incoming]),
                SubscriptionFetchResult(subscription=sub_fail, error="timeout"),
            ],
            error_formatter=lambda error: f"formatted: {error}",
        )

        self.assertEqual(change.updated, 1)
        self.assertEqual(change.failed, ("Fail",))
        self.assertEqual(change.active_profile_id, "incoming")
        self.assertEqual(change.profile_counts, {"ok": 1})
        failed = self.service.subscription_by_id(change.subscriptions, "fail")
        self.assertIsNotNone(failed)
        self.assertEqual(failed.last_error, "formatted: timeout")

    def test_delete_subscription_removes_only_its_profiles_and_repairs_active_profile(self) -> None:
        sub_a = subscription("a")
        sub_b = subscription("b")
        profile_a = profile("a-1", name="A", subscription_id="a")
        profile_b = profile("b-1", name="B", subscription_id="b")

        change = self.service.delete_subscription(
            subscriptions=[sub_a, sub_b],
            profiles=[profile_a, profile_b],
            active_profile_id="a-1",
            subscription_id="a",
        )

        self.assertEqual([item.id for item in change.subscriptions], ["b"])
        self.assertEqual([item.id for item in change.profiles], ["b-1"])
        self.assertEqual(change.active_profile_id, "b-1")
        self.assertEqual(change.profile_counts, {"b": 1})

    def test_sync_profile_counts_reports_changes(self) -> None:
        sub_a = subscription("a")
        sub_b = subscription("b")
        sub_a.profile_count = 99
        sub_b.profile_count = 0

        result = self.service.sync_profile_counts(
            [sub_a, sub_b],
            [
                profile("a-1", name="A1", subscription_id="a"),
                profile("a-2", name="A2", subscription_id="a"),
            ],
        )

        self.assertTrue(result.changed)
        self.assertEqual(result.counts, {"a": 2})
        self.assertEqual(sub_a.profile_count, 2)
        self.assertEqual(sub_b.profile_count, 0)


if __name__ == "__main__":
    unittest.main()
