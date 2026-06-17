import unittest

from core.smart_connect import SmartConnectManager
from core.smart_group_service import SmartGroupEdit, SmartGroupService, SmartGroupServiceError
from models.connection import (
    SMART_GROUP_MODE_FAILOVER,
    SMART_GROUP_MODE_LOAD_BALANCE,
    SMART_GROUP_MODE_MULTI_HOP,
    SMART_STRATEGY_FAILOVER_ORDER,
    SMART_STRATEGY_SMART,
    SmartGroup,
)
from models.profile import Subscription, VlessProfile
from models.settings import AppSettings


def profile(
    profile_id: str,
    *,
    subscription_id: str | None = "sub",
    group: str | None = "ru",
    address: str | None = None,
) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        address=address if address is not None else f"{profile_id}.example.com",
        subscription_id=subscription_id,
        group=group,
    )


class SmartGroupServiceTests(unittest.TestCase):
    def test_create_failover_group_requires_multiple_members(self) -> None:
        service = SmartGroupService(SmartConnectManager())

        with self.assertRaisesRegex(SmartGroupServiceError, "минимум два сервера"):
            service.create_failover_group(
                profile_id="a",
                profiles=[profile("a")],
                subscriptions=[Subscription(id="sub", name="Provider")],
            )

    def test_create_failover_group_uses_subscription_and_source_group_name(self) -> None:
        manager = SmartConnectManager()
        service = SmartGroupService(manager)
        profiles = [profile("a"), profile("b")]

        result = service.create_failover_group(
            profile_id="a",
            profiles=profiles,
            subscriptions=[Subscription(id="sub", name="Provider")],
        )

        self.assertEqual(result.group.name, "Provider / ru")
        self.assertEqual(result.group.strategy, SMART_STRATEGY_FAILOVER_ORDER)
        self.assertEqual(result.group.profile_ids, ["a", "b"])
        self.assertEqual([item.id for item in result.members], ["a", "b"])
        self.assertIn("серверов: 2", result.status_message)
        self.assertEqual(manager.smart_groups, [result.group])

    def test_apply_edit_normalizes_and_cleans_group_fields(self) -> None:
        service = SmartGroupService(SmartConnectManager())
        group = SmartGroup(id="group", name="Old", profile_ids=["old"])

        result = service.apply_edit(
            group,
            SmartGroupEdit(
                name="  New  ",
                enabled=False,
                mode="lb",
                strategy="unknown",
                profile_ids=["a", "", "a", "b"],
                load_balance_interval="",
                load_balance_tolerance_ms=-5,
            ),
        )

        self.assertIs(result.group, group)
        self.assertEqual(group.name, "New")
        self.assertFalse(group.enabled)
        self.assertEqual(group.mode, SMART_GROUP_MODE_LOAD_BALANCE)
        self.assertEqual(group.strategy, SMART_STRATEGY_SMART)
        self.assertEqual(group.profile_ids, ["a", "b"])
        self.assertEqual(group.load_balance_interval, "5m")
        self.assertEqual(group.load_balance_tolerance_ms, 0)
        self.assertEqual(result.status_message, "Группа сохранена: New")

    def test_apply_edit_rejects_advanced_group_with_too_few_members(self) -> None:
        service = SmartGroupService(SmartConnectManager())

        with self.assertRaisesRegex(SmartGroupServiceError, "недостаточно серверов"):
            service.apply_edit(
                SmartGroup(),
                SmartGroupEdit(
                    name="Chain",
                    enabled=True,
                    mode=SMART_GROUP_MODE_MULTI_HOP,
                    strategy=SMART_STRATEGY_SMART,
                    profile_ids=["a"],
                    load_balance_interval="5m",
                    load_balance_tolerance_ms=50,
                ),
            )

    def test_plan_start_blocks_disabled_busy_and_admin_requirements(self) -> None:
        disabled = SmartGroup(id="disabled", enabled=False)
        failover = SmartGroup(id="failover", mode=SMART_GROUP_MODE_FAILOVER)
        manager = SmartConnectManager(smart_groups=[disabled, failover])
        service = SmartGroupService(manager)

        blocked_disabled = service.plan_start(
            group_id="disabled",
            settings=AppSettings(),
            is_admin=True,
            busy=False,
        )
        self.assertFalse(blocked_disabled.allowed)
        self.assertEqual(blocked_disabled.status_message, "Группа отключена")

        admin_required = service.plan_start(
            group_id="failover",
            settings=AppSettings(mode="tun"),
            is_admin=False,
            busy=False,
        )
        self.assertFalse(admin_required.allowed)
        self.assertTrue(admin_required.admin_required)
        self.assertIn("TUN-режиме", admin_required.admin_reason)

        busy = service.plan_start(
            group_id="failover",
            settings=AppSettings(),
            is_admin=True,
            busy=True,
        )
        self.assertFalse(busy.allowed)
        self.assertEqual(busy.status_level, "info")
        self.assertEqual(busy.status_message, "Операция подключения уже выполняется")

    def test_plan_start_returns_mode_specific_busy_text(self) -> None:
        failover = SmartGroup(id="failover", mode=SMART_GROUP_MODE_FAILOVER)
        chain = SmartGroup(id="chain", mode=SMART_GROUP_MODE_MULTI_HOP)
        balance = SmartGroup(id="balance", mode=SMART_GROUP_MODE_LOAD_BALANCE)
        service = SmartGroupService(SmartConnectManager(smart_groups=[failover, chain, balance]))

        self.assertEqual(
            service.plan_start(group_id="failover", settings=AppSettings(), is_admin=True, busy=False).busy_text,
            "Подключение группы…",
        )
        self.assertEqual(
            service.plan_start(group_id="chain", settings=AppSettings(), is_admin=True, busy=False).busy_text,
            "Multi-hop…",
        )
        self.assertEqual(
            service.plan_start(group_id="balance", settings=AppSettings(), is_admin=True, busy=False).busy_text,
            "Load Balance…",
        )


if __name__ == "__main__":
    unittest.main()
