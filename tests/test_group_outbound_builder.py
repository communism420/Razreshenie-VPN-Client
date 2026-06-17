import unittest

from core.config_builder import SingBoxConfigBuilder
from core.group_outbound_builder import GroupOutboundBuildError, GroupOutboundBuilder
from models.connection import (
    SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT,
    SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS,
    SMART_GROUP_MODE_LOAD_BALANCE,
    SMART_GROUP_MODE_MULTI_HOP,
    SmartGroup,
)
from models.profile import VlessProfile
from models.rules import SplitRules
from models.settings import AppSettings


def profile(profile_id: str, *, uuid: str | None = None) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        protocol="vless",
        address=f"{profile_id}.example.com",
        port=443,
        uuid=f"00000000-0000-4000-8000-00000000000{profile_id[-1]}" if uuid is None else uuid,
    )


class GroupOutboundBuilderTests(unittest.TestCase):
    def test_multi_hop_builds_detour_chain_with_proxy_exit(self) -> None:
        profiles = [profile("hop1"), profile("hop2"), profile("hop3")]
        by_id = {item.id: item for item in profiles}
        group = SmartGroup(
            name="chain",
            mode=SMART_GROUP_MODE_MULTI_HOP,
            profile_ids=["hop1", "hop2", "hop3"],
        )

        result = GroupOutboundBuilder().build(group, by_id)

        self.assertEqual([item["tag"] for item in result.outbounds], ["hop-1", "hop-2", "proxy"])
        self.assertNotIn("detour", result.outbounds[0])
        self.assertEqual(result.outbounds[1]["detour"], "hop-1")
        self.assertEqual(result.outbounds[2]["detour"], "hop-2")
        self.assertEqual(result.exit_profile.id, "hop3")

    def test_load_balance_builds_urltest_proxy_group(self) -> None:
        profiles = [profile("lb1"), profile("lb2")]
        by_id = {item.id: item for item in profiles}
        group = SmartGroup(
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["lb1", "lb2"],
            load_balance_interval="2m",
            load_balance_tolerance_ms=75,
        )

        result = GroupOutboundBuilder().build(group, by_id)
        proxy = result.outbounds[-1]

        self.assertEqual([item["tag"] for item in result.outbounds], ["lb-1", "lb-2", "proxy"])
        self.assertEqual(proxy["type"], "urltest")
        self.assertEqual(proxy["outbounds"], ["lb-1", "lb-2"])
        self.assertEqual(proxy["interval"], "2m")
        self.assertEqual(proxy["tolerance"], 75)

    def test_load_balance_falls_back_from_corrupted_interval_and_tolerance(self) -> None:
        profiles = [profile("lb1"), profile("lb2")]
        group = SmartGroup(
            name="balanced",
            mode=SMART_GROUP_MODE_LOAD_BALANCE,
            profile_ids=["lb1", "lb2"],
            load_balance_interval="never",
            load_balance_tolerance_ms="bad",  # type: ignore[arg-type]
        )

        result = GroupOutboundBuilder().build(group, {item.id: item for item in profiles})
        proxy = result.outbounds[-1]

        self.assertEqual(proxy["interval"], SMART_GROUP_LOAD_BALANCE_INTERVAL_DEFAULT)
        self.assertEqual(proxy["tolerance"], SMART_GROUP_LOAD_BALANCE_TOLERANCE_DEFAULT_MS)

    def test_advanced_group_rejects_missing_members(self) -> None:
        group = SmartGroup(
            name="chain",
            mode=SMART_GROUP_MODE_MULTI_HOP,
            profile_ids=["hop1", "missing-hop"],
        )

        with self.assertRaisesRegex(GroupOutboundBuildError, "недоступные серверы"):
            GroupOutboundBuilder().build(group, {"hop1": profile("hop1")})

    def test_group_member_error_includes_role_context(self) -> None:
        broken = profile("hop1", uuid="")
        group = SmartGroup(
            name="chain",
            mode=SMART_GROUP_MODE_MULTI_HOP,
            profile_ids=["hop1", "hop2"],
        )

        with self.assertRaisesRegex(GroupOutboundBuildError, "Multi-hop hop 1"):
            GroupOutboundBuilder().build(group, {"hop1": broken, "hop2": profile("hop2")})

    def test_config_builder_group_keeps_route_proxy_tag(self) -> None:
        profiles = [profile("a"), profile("b")]
        group = SmartGroup(name="chain", mode=SMART_GROUP_MODE_MULTI_HOP, profile_ids=["a", "b"])

        config = SingBoxConfigBuilder().build_group(
            group,
            {item.id: item for item in profiles},
            AppSettings(mode="proxy"),
            SplitRules(),
            None,
        )

        tags = [item["tag"] for item in config["outbounds"]]
        self.assertIn("proxy", tags)
        self.assertIn("direct", tags)
        self.assertEqual(config["route"]["final"], "proxy")


if __name__ == "__main__":
    unittest.main()
