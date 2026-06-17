import logging
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from core.connection_service import ConnectionService, ConnectionStartResult
from core.connectivity import ConnectivityCheckResult, ConnectivityProbeResult
from core.resilience_service import (
    HEALTH_STATUS_RECOVER,
    RECOVERY_ACTION_FAILOVER,
    RECOVERY_ACTION_RESTART_GROUP,
    ResilienceService,
)
from core.smart_connect import SmartConnectManager
from models.connection import SMART_GROUP_MODE_FAILOVER, SMART_GROUP_MODE_LOAD_BALANCE, SmartGroup
from models.profile import VlessProfile
from models.rules import SplitRules
from models.settings import AppSettings


@dataclass(slots=True)
class FakeScanResult:
    results: dict[str, int | None]


class FakeLatencyScanner:
    def __init__(self, results: dict[str, int | None] | None = None, *, fail: bool = False) -> None:
        self.results = dict(results or {})
        self.fail = fail
        self.calls: list[list[str]] = []

    def scan_profiles_sync(self, profiles, *, settings):
        self.calls.append([profile.id for profile in profiles])
        if self.fail:
            raise RuntimeError("scan failed")
        return FakeScanResult(self.results)


class FakeSingBox:
    def __init__(self, *, fail_start: bool = False, fail_start_ids: set[str] | None = None) -> None:
        self.fail_start = fail_start
        self.fail_start_ids = set(fail_start_ids or set())
        self.start_calls: list[str] = []
        self.start_group_calls: list[tuple[str, list[str]]] = []
        self.stop_calls = 0

    def start(self, profile, settings, split_rules) -> None:
        self.start_calls.append(profile.id)
        if self.fail_start or profile.id in self.fail_start_ids:
            raise RuntimeError("start failed")

    def start_group(self, group, profiles_by_id, settings, split_rules) -> None:
        self.start_group_calls.append((group.id, list(profiles_by_id)))
        if self.fail_start:
            raise RuntimeError("group start failed")

    def stop(self) -> None:
        self.stop_calls += 1

    def ensure_binary(self) -> Path:
        return Path("C:/Razreshenie/sing-box.exe")


def profile(profile_id: str, latency_ms: int | None = None) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        address=f"{profile_id}.example.com",
        port=443,
        subscription_id="sub",
        group="group",
        latency_ms=latency_ms,
    )


def test_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return logger


def connection_service(
    singbox: FakeSingBox | None = None,
    smart_connect: SmartConnectManager | None = None,
    scanner: FakeLatencyScanner | None = None,
) -> ConnectionService:
    return ConnectionService(
        singbox=singbox or FakeSingBox(),
        smart_connect=smart_connect or SmartConnectManager(),
        latency_scanner=scanner or FakeLatencyScanner(),
        logger=test_logger("tests.connection"),
        scan_limit=4,
    )


class ConnectionServiceTests(unittest.TestCase):
    def test_start_profile_core_rolls_back_core_when_proxy_guard_fails(self) -> None:
        singbox = FakeSingBox()
        service = connection_service(singbox=singbox)
        settings = AppSettings(mode="proxy", enable_system_proxy_guard=True)

        with patch("core.connection_service.windows.set_system_proxy", side_effect=[RuntimeError("proxy failed"), None]) as proxy:
            with self.assertRaisesRegex(RuntimeError, "proxy failed"):
                service.start_profile_core(profile("a"), settings=settings, split_rules=SplitRules())

        self.assertEqual(singbox.start_calls, ["a"])
        self.assertEqual(singbox.stop_calls, 1)
        self.assertEqual(proxy.call_count, 2)

    def test_start_direct_records_failure_and_saves_stats(self) -> None:
        smart_connect = SmartConnectManager()
        service = connection_service(singbox=FakeSingBox(fail_start=True), smart_connect=smart_connect)
        saved = []

        with self.assertRaisesRegex(RuntimeError, "start failed"):
            service.start_direct(
                profile("a"),
                settings=AppSettings(),
                split_rules=SplitRules(),
                save_quality_stats=lambda: saved.append("saved"),
            )

        self.assertEqual(saved, ["saved"])
        self.assertEqual(smart_connect.quality_stats["a"].failure_count, 1)

    def test_smart_select_records_scan_results_and_uses_best_candidate(self) -> None:
        profiles = [profile("a", 200), profile("b", 300)]
        scanner = FakeLatencyScanner({"a": 180, "b": 40})
        service = connection_service(scanner=scanner)
        saved_profiles = []
        saved_stats = []
        recorded = {}

        selected = service.select_smart_profile(
            profiles[0],
            profiles=profiles,
            settings=AppSettings(),
            record_latency=lambda profile_id, latency_ms, checked_at: recorded.update({profile_id: latency_ms}),
            save_profiles=lambda: saved_profiles.append("profiles"),
            save_quality_stats=lambda: saved_stats.append("stats"),
        )

        self.assertEqual(selected.id, "b")
        self.assertEqual(scanner.calls, [["a", "b"]])
        self.assertEqual(recorded, {"a": 180, "b": 40})
        self.assertEqual(saved_profiles, ["profiles"])
        self.assertEqual(saved_stats, ["stats"])

    def test_start_load_balance_group_records_member_successes(self) -> None:
        profiles = [profile("a"), profile("b")]
        group = SmartGroup(
            id="group",
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["a", "b"],
        )
        singbox = FakeSingBox()
        smart_connect = SmartConnectManager()
        service = connection_service(singbox=singbox, smart_connect=smart_connect)
        saved_stats = []

        result = service.start_group(
            group,
            profiles=profiles,
            settings=AppSettings(),
            split_rules=SplitRules(),
            record_latency=lambda *_args: None,
            save_profiles=lambda: None,
            save_quality_stats=lambda: saved_stats.append("stats"),
        )

        self.assertEqual(singbox.start_group_calls, [("group", ["a", "b"])])
        self.assertEqual(result.group_id, "group")
        self.assertEqual(result.profile_ids, ("a", "b"))
        self.assertEqual(smart_connect.quality_stats["a"].success_count, 1)
        self.assertEqual(smart_connect.quality_stats["b"].success_count, 1)
        self.assertEqual(saved_stats, ["stats"])

    def test_connection_start_result_classifies_failover_and_advanced_group(self) -> None:
        selected = profile("a")

        direct = ConnectionStartResult(anchor_profile=selected, selected_profile=selected)
        failover_group = ConnectionStartResult(
            anchor_profile=selected,
            selected_profile=selected,
            group_id="failover",
            group_mode=SMART_GROUP_MODE_FAILOVER,
        )
        advanced_group = ConnectionStartResult(
            anchor_profile=selected,
            selected_profile=selected,
            group_id="advanced",
            group_mode=SMART_GROUP_MODE_LOAD_BALANCE,
        )

        self.assertTrue(direct.starts_failover_session)
        self.assertTrue(failover_group.starts_failover_session)
        self.assertFalse(failover_group.is_advanced_group)
        self.assertFalse(advanced_group.starts_failover_session)
        self.assertTrue(advanced_group.is_advanced_group)


class ResilienceServiceTests(unittest.TestCase):
    def test_health_failure_reaches_threshold_and_plans_failover(self) -> None:
        primary = profile("a", 80)
        backup = profile("b", 120)
        service = connection_service()
        resilience = ResilienceService(connection_service=service, logger=test_logger("tests.resilience"), scan_limit=4)
        resilience.begin_failover_session(primary)
        saved = []

        outcome = resilience.handle_health_check_result(
            primary,
            ConnectivityCheckResult(False, [ConnectivityProbeResult("https://check.example", False, error="timeout")]),
            running=True,
            closing=False,
            settings=AppSettings(background_health_check_failure_threshold=1),
            record_latency=lambda profile_id, latency_ms, checked_at: None,
            save_profiles=lambda: None,
            save_quality_stats=lambda: saved.append("stats"),
        )
        plan = resilience.plan_health_recovery(
            primary,
            outcome.reason,
            settings=AppSettings(),
            profiles=[primary, backup],
            profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
            busy=False,
            closing=False,
        )

        self.assertEqual(outcome.status, HEALTH_STATUS_RECOVER)
        self.assertEqual(outcome.failure_count, 1)
        self.assertEqual(saved, ["stats"])
        self.assertEqual(plan.action, RECOVERY_ACTION_FAILOVER)

    def test_self_healing_attempt_limit_enters_cooldown(self) -> None:
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )
        settings = AppSettings.from_dict({"self_healing_max_attempts": 1, "self_healing_cooldown_seconds": 30})

        first = resilience.register_self_healing_attempt(settings, "core stopped")
        second = resilience.register_self_healing_attempt(settings, "core stopped again")

        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertIn("лимит", second.message)

    def test_connection_start_applies_failover_session_policy(self) -> None:
        primary = profile("a")
        backup = profile("b")
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )

        resilience.apply_connection_start(ConnectionStartResult(anchor_profile=primary, selected_profile=primary))
        self.assertEqual(resilience.failover_anchor_profile_id, "a")

        resilience.apply_connection_start(
            ConnectionStartResult(
                anchor_profile=primary,
                selected_profile=backup,
                group_id="failover",
                group_mode=SMART_GROUP_MODE_FAILOVER,
            )
        )
        self.assertEqual(resilience.failover_anchor_profile_id, "a")

        resilience.apply_connection_start(
            ConnectionStartResult(
                anchor_profile=primary,
                selected_profile=backup,
                group_id="advanced",
                group_mode=SMART_GROUP_MODE_LOAD_BALANCE,
            )
        )
        self.assertIsNone(resilience.failover_anchor_profile_id)

    def test_run_failover_attempt_skips_failed_candidates_and_records_success(self) -> None:
        primary = profile("a", 80)
        first_backup = profile("b", 40)
        second_backup = profile("c", 60)
        singbox = FakeSingBox(fail_start_ids={"b"})
        smart_connect = SmartConnectManager()
        service = connection_service(
            singbox=singbox,
            smart_connect=smart_connect,
            scanner=FakeLatencyScanner({"b": 40, "c": 60}),
        )
        resilience = ResilienceService(connection_service=service, logger=test_logger("tests.resilience"), scan_limit=4)
        saved_stats = []
        saved_profiles = []
        recorded_latency = {}

        started = resilience.begin_failover_after_drop(
            primary,
            busy=False,
            closing=False,
            save_quality_stats=lambda: saved_stats.append("stats"),
        )
        self.assertFalse(started)
        resilience.begin_failover_session(primary)
        self.assertTrue(
            resilience.begin_failover_after_drop(
                primary,
                busy=False,
                closing=False,
                save_quality_stats=lambda: saved_stats.append("stats"),
            )
        )

        def record_latency(profile_id: str, latency_ms: int | None, checked_at: str) -> None:
            recorded_latency[profile_id] = latency_ms
            smart_connect.record_latency(profile_id, latency_ms, checked_at=checked_at)

        result = resilience.run_failover_attempt(
            primary,
            profiles=[primary, first_backup, second_backup],
            settings=AppSettings(),
            split_rules=SplitRules(),
            profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
            record_latency=record_latency,
            save_profiles=lambda: saved_profiles.append("profiles"),
            save_quality_stats=lambda: saved_stats.append("stats"),
        )

        self.assertIsNotNone(result.profile)
        self.assertEqual(result.profile.id, "c")
        self.assertEqual(singbox.start_calls, ["b", "c"])
        self.assertEqual(recorded_latency, {"b": 40, "c": 60})
        self.assertEqual(saved_profiles, ["profiles"])
        self.assertIn("a", resilience.failover_failed_ids)
        self.assertIn("b", resilience.failover_failed_ids)
        self.assertEqual(smart_connect.quality_stats["b"].failure_count, 1)
        self.assertEqual(smart_connect.quality_stats["c"].success_count, 2)
        self.assertEqual(len(saved_stats), 4)

    def test_advanced_group_health_recovery_restarts_group(self) -> None:
        primary = profile("a", 80)
        backup = profile("b", 120)
        group = SmartGroup(
            id="advanced",
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["a", "b"],
        )
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )

        plan = resilience.plan_health_recovery(
            primary,
            "timeout",
            settings=AppSettings(),
            profiles=[primary, backup],
            profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
            busy=False,
            closing=False,
            active_group=group,
        )

        self.assertEqual(plan.action, RECOVERY_ACTION_RESTART_GROUP)
        self.assertEqual(plan.group_id, "advanced")

    def test_advanced_group_health_recovery_is_throttled(self) -> None:
        primary = profile("a", 80)
        backup = profile("b", 120)
        group = SmartGroup(
            id="advanced",
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["a", "b"],
        )
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )
        settings = AppSettings.from_dict({"self_healing_cooldown_seconds": 30})

        with patch("core.resilience_service.time.time", side_effect=[1000, 1002, 1005]):
            first = resilience.plan_health_recovery(
                primary,
                "timeout",
                settings=settings,
                profiles=[primary, backup],
                profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
                busy=False,
                closing=False,
                active_group=group,
            )
            second = resilience.plan_health_recovery(
                primary,
                "timeout again",
                settings=settings,
                profiles=[primary, backup],
                profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
                busy=False,
                closing=False,
                active_group=group,
            )

        self.assertEqual(first.action, RECOVERY_ACTION_RESTART_GROUP)
        self.assertEqual(second.action, "none")
        self.assertIn("паузе", second.reason)

    def test_advanced_group_recovery_cooldown_survives_restart_until_health_ok(self) -> None:
        primary = profile("a", 80)
        backup = profile("b", 120)
        group = SmartGroup(
            id="advanced",
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["a", "b"],
        )
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )
        settings = AppSettings.from_dict({"self_healing_cooldown_seconds": 30})

        with patch("core.resilience_service.time.time", side_effect=[1000, 1002, 1005]):
            resilience.plan_health_recovery(
                primary,
                "timeout",
                settings=settings,
                profiles=[primary, backup],
                profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
                busy=False,
                closing=False,
                active_group=group,
            )
            resilience.on_connected()
            second = resilience.plan_health_recovery(
                primary,
                "timeout again",
                settings=settings,
                profiles=[primary, backup],
                profile_lookup=lambda profile_id: primary if profile_id == primary.id else None,
                busy=False,
                closing=False,
                active_group=group,
            )

        self.assertEqual(second.action, "none")

    def test_manual_disconnect_does_not_report_core_stop(self) -> None:
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )

        resilience.on_connected()
        self.assertTrue(resilience.should_report_core_stop(closing=False))

        resilience.mark_manual_disconnect_requested()
        self.assertFalse(resilience.should_report_core_stop(closing=False))

        resilience.mark_core_stopped()
        self.assertFalse(resilience.last_connection_running)

    def test_health_reconnect_restarts_current_profile_and_records_success(self) -> None:
        active = profile("a")
        singbox = FakeSingBox()
        smart_connect = SmartConnectManager()
        resilience = ResilienceService(
            connection_service=connection_service(singbox=singbox, smart_connect=smart_connect),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )
        saved = []

        result = resilience.run_health_reconnect(
            active,
            settings=AppSettings(),
            split_rules=SplitRules(),
            save_quality_stats=lambda: saved.append("stats"),
        )

        self.assertIsNotNone(result.profile)
        self.assertEqual(result.profile.id, "a")
        self.assertEqual(singbox.stop_calls, 1)
        self.assertEqual(singbox.start_calls, ["a"])
        self.assertEqual(smart_connect.quality_stats["a"].success_count, 1)
        self.assertEqual(saved, ["stats"])

    def test_self_healing_cooldown_allows_new_attempt_after_pause(self) -> None:
        resilience = ResilienceService(
            connection_service=connection_service(),
            logger=test_logger("tests.resilience"),
            scan_limit=4,
        )
        settings = AppSettings.from_dict({"self_healing_max_attempts": 1, "self_healing_cooldown_seconds": 30})

        with patch("core.resilience_service.time.time", side_effect=[1000, 1001, 1035]):
            first = resilience.register_self_healing_attempt(settings, "first")
            limited = resilience.register_self_healing_attempt(settings, "second")
            after_cooldown = resilience.register_self_healing_attempt(settings, "third")

        self.assertTrue(first.allowed)
        self.assertFalse(limited.allowed)
        self.assertTrue(after_cooldown.allowed)
        self.assertEqual(resilience.self_healing_attempts, 1)


if __name__ == "__main__":
    unittest.main()
