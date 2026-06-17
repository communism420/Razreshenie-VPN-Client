import unittest

from core.subscription_manager import SubscriptionManager
from models.profile import Subscription, VlessProfile


def profile(profile_id: str, subscription_id: str) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        address=f"{profile_id}.example.com",
        port=443,
        subscription_id=subscription_id,
    )


class FakeFetcher:
    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls: list[str] = []

    def fetch(self, subscription: Subscription):
        self.calls.append(subscription.id)
        response = self.responses[subscription.id]
        if isinstance(response, Exception):
            raise response
        return response


class SubscriptionManagerTests(unittest.TestCase):
    def test_fetch_many_collects_successes_errors_and_progress(self) -> None:
        ok = Subscription(id="ok", name="OK", url="https://ok.example/sub")
        bad = Subscription(id="bad", name="Bad", url="https://bad.example/sub")
        updated = Subscription(id="ok", name="OK", url=ok.url, profile_count=1)
        fetcher = FakeFetcher(
            {
                "ok": ([profile("server-a", "ok")], updated),
                "bad": RuntimeError("network down"),
            }
        )
        manager = SubscriptionManager(fetcher=fetcher)
        progress = []

        results = manager.fetch_many([ok, bad], max_workers=1, progress_callback=progress.append)
        by_id = {result.subscription.id: result for result in results}

        self.assertEqual(fetcher.calls, ["ok", "bad"])
        self.assertEqual(len(results), 2)
        self.assertTrue(by_id["ok"].success)
        self.assertEqual(by_id["ok"].profiles[0].subscription_id, "ok")
        self.assertEqual(by_id["ok"].subscription.profile_count, 1)
        self.assertFalse(by_id["bad"].success)
        self.assertEqual(by_id["bad"].error, "network down")
        self.assertEqual(bad.last_error, "network down")
        self.assertEqual([event.current for event in progress], [1, 2])
        self.assertEqual(progress[-1].updated, 1)
        self.assertEqual(progress[-1].errors, 1)

    def test_fetch_many_empty_batch_does_not_call_progress(self) -> None:
        manager = SubscriptionManager(fetcher=FakeFetcher({}))
        progress = []

        self.assertEqual(manager.fetch_many([], progress_callback=progress.append), [])
        self.assertEqual(progress, [])

    def test_manager_parse_methods_delegate_to_importer(self) -> None:
        manager = SubscriptionManager(fetcher=FakeFetcher({}))
        profiles = manager.parse_text(
            "vless://00000000-0000-4000-8000-000000000000@example.com:443#Demo",
            "sub",
        )

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].subscription_id, "sub")
        self.assertEqual(
            SubscriptionManager.profile_key(profiles[0]),
            "vless|demo|example.com|443|00000000-0000-4000-8000-000000000000|",
        )


if __name__ == "__main__":
    unittest.main()
