import unittest

from core.config_builder import ConfigBuildError, SingBoxConfigBuilder
from models.connection import SMART_GROUP_MODE_LOAD_BALANCE, SMART_GROUP_MODE_MULTI_HOP, SmartGroup
from models.profile import VlessProfile
from models.rules import ROUTE_OUTBOUND_DIRECT, ROUTE_OUTBOUND_PROXY, RouteRuleSetResource, RoutingRuleSet, SplitRules
from models.settings import AppSettings


def profile(profile_id: str = "server") -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        protocol="vless",
        address=f"{profile_id}.example.com",
        port=443,
        uuid=f"00000000-0000-4000-8000-{int(profile_id[-1]) if profile_id[-1].isdigit() else 1:012d}",
        params={"security": "tls", "sni": f"{profile_id}.example.com"},
    )


class ConfigBuilderIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = SingBoxConfigBuilder()
        self.profile = profile("server1")

    def test_proxy_and_tun_modes_emit_expected_inbounds_and_route_final(self) -> None:
        proxy_config = self.builder.build(self.profile, AppSettings(mode="proxy"), SplitRules(), log_path=None)
        tun_config = self.builder.build(self.profile, AppSettings(mode="tun"), SplitRules(), log_path=None)

        self.assertEqual(proxy_config["inbounds"][0]["type"], "mixed")
        self.assertEqual(tun_config["inbounds"][0]["type"], "tun")
        self.assertEqual(proxy_config["route"]["final"], "proxy")
        self.assertEqual(tun_config["route"]["final"], "proxy")
        self.assertEqual(proxy_config["outbounds"][0]["tag"], "proxy")
        self.assertEqual(proxy_config["outbounds"][1]["tag"], "direct")

    def test_tun_ipv6_dns_strategy_and_kill_switch_are_reflected_in_config(self) -> None:
        settings = AppSettings(
            mode="tun",
            enable_ipv6=True,
            dns_strategy="prefer_ipv6",
            tun_ipv6_address="fdfe:dcba:9876::1/126",
            kill_switch=True,
        )

        config = self.builder.build(self.profile, settings, SplitRules(), log_path=None)

        self.assertEqual(config["dns"]["strategy"], "prefer_ipv6")
        self.assertEqual(config["inbounds"][0]["address"], ["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
        self.assertTrue(config["inbounds"][0]["strict_route"])
        fakeip = next(server for server in config["dns"]["servers"] if server["tag"] == "fakeip")
        self.assertEqual(fakeip["inet6_range"], "fc00::/18")

    def test_complex_split_rules_emit_route_selectors_and_srs_resources(self) -> None:
        rules = SplitRules(
            enabled=True,
            default_outbound=ROUTE_OUTBOUND_PROXY,
            rule_set_resources=[
                RouteRuleSetResource(name="local", type="local", tag="local-ru", path="rules/ru.srs"),
                RouteRuleSetResource(
                    name="remote",
                    type="remote",
                    tag="remote-ads",
                    url="https://example.com/ads.srs",
                    update_interval="12h",
                ),
            ],
            rule_sets=[
                RoutingRuleSet(
                    name="direct mix",
                    outbound=ROUTE_OUTBOUND_DIRECT,
                    domains=["example.ru"],
                    domain_suffix=["ru"],
                    geosite=["category-ru"],
                    geoip=["ru"],
                    process_name=["browser.exe"],
                    rule_set_tags=["local-ru"],
                ),
                RoutingRuleSet(
                    name="proxy ads",
                    outbound=ROUTE_OUTBOUND_PROXY,
                    domain_keyword=["ads"],
                    rule_set_tags=["remote-ads"],
                    rule_set_ip_cidr_match_source=True,
                ),
            ],
        )

        config = self.builder.build(self.profile, AppSettings(mode="proxy"), rules, log_path=None)
        route = config["route"]

        self.assertEqual(route["final"], ROUTE_OUTBOUND_PROXY)
        self.assertEqual(route["rule_set"][0]["path"], "rules/ru.srs")
        self.assertEqual(route["rule_set"][1]["url"], "https://example.com/ads.srs")
        direct_rule = next(rule for rule in route["rules"] if rule.get("domain") == ["example.ru"])
        self.assertEqual(direct_rule["outbound"], ROUTE_OUTBOUND_DIRECT)
        self.assertEqual(direct_rule["rule_set"], ["local-ru"])
        self.assertEqual(direct_rule["process_name"], ["browser.exe"])
        proxy_rule = next(rule for rule in route["rules"] if rule.get("domain_keyword") == ["ads"])
        self.assertTrue(proxy_rule["rule_set_ip_cidr_match_source"])

    def test_multi_hop_group_and_load_balance_group_configs(self) -> None:
        profiles = {item.id: item for item in [profile("hop1"), profile("hop2"), profile("hop3")]}

        chain_config = self.builder.build_group(
            SmartGroup(name="chain", mode=SMART_GROUP_MODE_MULTI_HOP, profile_ids=["hop1", "hop2", "hop3"]),
            profiles,
            AppSettings(mode="proxy"),
            SplitRules(),
            log_path=None,
        )
        balance_config = self.builder.build_group(
            SmartGroup(name="balance", mode=SMART_GROUP_MODE_LOAD_BALANCE, profile_ids=["hop1", "hop2"]),
            profiles,
            AppSettings(mode="proxy"),
            SplitRules(),
            log_path=None,
        )

        self.assertEqual([item["tag"] for item in chain_config["outbounds"][:3]], ["hop-1", "hop-2", "proxy"])
        self.assertEqual(chain_config["outbounds"][1]["detour"], "hop-1")
        self.assertEqual(chain_config["outbounds"][2]["detour"], "hop-2")
        lb_proxy = next(item for item in balance_config["outbounds"] if item["tag"] == "proxy")
        self.assertEqual(lb_proxy["type"], "urltest")
        self.assertEqual(lb_proxy["outbounds"], ["lb-1", "lb-2"])

    def test_invalid_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigBuildError, "Неизвестный режим"):
            self.builder.build(self.profile, AppSettings(mode="bad"), SplitRules(), log_path=None)


if __name__ == "__main__":
    unittest.main()
