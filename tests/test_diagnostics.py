import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.diagnostics import build_diagnostics_archive, collect_stability_summary
from models.connection import SMART_GROUP_MODE_LOAD_BALANCE, ServerQualityStats, SmartGroup
from models.profile import VlessProfile
from models.rules import RouteRuleSetResource, RoutingRuleSet, SplitRules
from models.settings import AppSettings


class DiagnosticsTests(unittest.TestCase):
    def test_collect_stability_summary_uses_aggregates_only(self) -> None:
        summary = collect_stability_summary(
            settings=AppSettings(mode="tun", self_healing_enabled=True),
            profiles=[
                VlessProfile(id="a", protocol="vless", address="secret-a.example", uuid="secret-uuid"),
                VlessProfile(id="b", protocol="trojan", address="secret-b.example", params={"password": "secret"}),
            ],
            subscriptions=[],
            split_rules=SplitRules(
                enabled=True,
                rule_sets=[RoutingRuleSet(enabled=True, domains=["bank.example"], priority=100)],
                rule_set_resources=[RouteRuleSetResource(enabled=True, type="remote", format="binary", url="https://rules.example/a.srs")],
            ),
            quality_stats={"a": ServerQualityStats(profile_id="a", failure_count=1, consecutive_failures=1)},
            smart_groups=[
                SmartGroup(
                    name="balanced",
                    mode=SMART_GROUP_MODE_LOAD_BALANCE,
                    profile_ids=["a", "b"],
                )
            ],
            log_lines=["timeout while connecting to secret-a.example"],
        )

        self.assertEqual(summary["counts"]["profiles_total"], 2)
        self.assertEqual(summary["counts"]["profiles_by_protocol"]["vless"], 1)
        self.assertEqual(summary["counts"]["smart_groups_by_mode"][SMART_GROUP_MODE_LOAD_BALANCE], 1)
        self.assertEqual(summary["routing"]["rule_sets_enabled"], 1)
        self.assertEqual(summary["routing"]["rule_set_resources_enabled"], 1)
        self.assertEqual(summary["quality"]["profiles_with_consecutive_failures"], 1)
        self.assertEqual(summary["logs"]["session_buffer_error_lines"], 1)

        payload = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("secret-a.example", payload)
        self.assertNotIn("bank.example", payload)
        self.assertNotIn("secret-uuid", payload)

    def test_diagnostics_archive_includes_stability_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = build_diagnostics_archive(
                Path(tmp) / "diagnostics.zip",
                settings=AppSettings(),
                profiles=[VlessProfile(id="a", protocol="vless", address="secret.example")],
                subscriptions=[],
                split_rules=SplitRules(),
                quality_stats={},
                smart_groups=[],
                log_lines=["server=secret.example failed"],
            )

            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                summary = json.loads(archive.read("state/stability-summary.redacted.json").decode("utf-8"))
                payload = "\n".join(
                    archive.read(name).decode("utf-8", errors="replace")
                    for name in names
                    if name.endswith((".json", ".txt", ".log"))
                )

        self.assertIn("state/stability-summary.redacted.json", names)
        self.assertEqual(summary["counts"]["profiles_total"], 1)
        self.assertNotIn("secret.example", payload)


if __name__ == "__main__":
    unittest.main()
