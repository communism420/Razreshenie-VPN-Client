import unittest

from core.config_errors import ConfigBuildError
from core.route_builder import RouteBuilder
from models.rules import ROUTE_OUTBOUND_DIRECT, RouteRuleSetResource, RoutingRuleSet, SplitRules


class RouteBuilderTests(unittest.TestCase):
    def test_duplicate_rule_set_resource_tags_are_rejected(self) -> None:
        rules = SplitRules(
            enabled=True,
            rule_set_resources=[
                RouteRuleSetResource(name="first", type="remote", tag="ru-sites", url="https://example.com/1.srs"),
                RouteRuleSetResource(name="second", type="remote", tag="ru-sites", url="https://example.com/2.srs"),
            ],
            rule_sets=[RoutingRuleSet(name="direct", outbound=ROUTE_OUTBOUND_DIRECT, rule_set_tags=["ru-sites"])],
        )

        with self.assertRaisesRegex(ConfigBuildError, "используется повторно"):
            RouteBuilder().build(rules)

    def test_missing_rule_set_reference_is_rejected(self) -> None:
        rules = SplitRules(
            enabled=True,
            rule_sets=[RoutingRuleSet(name="missing", outbound=ROUTE_OUTBOUND_DIRECT, rule_set_tags=["missing-tag"])],
        )

        with self.assertRaisesRegex(ConfigBuildError, "неизвестный route.rule_set"):
            RouteBuilder().build(rules)

    def test_remote_and_local_srs_resources_are_emitted(self) -> None:
        rules = SplitRules(
            enabled=True,
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
                RoutingRuleSet(name="local direct", outbound=ROUTE_OUTBOUND_DIRECT, rule_set_tags=["local-ru"]),
                RoutingRuleSet(name="remote direct", outbound=ROUTE_OUTBOUND_DIRECT, rule_set_tags=["remote-ads"]),
            ],
        )

        route = RouteBuilder().build(rules)

        self.assertEqual(route["rule_set"][0], {"type": "local", "tag": "local-ru", "format": "binary", "path": "rules/ru.srs"})
        self.assertEqual(route["rule_set"][1]["type"], "remote")
        self.assertEqual(route["rule_set"][1]["url"], "https://example.com/ads.srs")
        self.assertEqual(route["rule_set"][1]["update_interval"], "12h")
        self.assertTrue(any(rule.get("rule_set") == ["local-ru"] for rule in route["rules"]))
        self.assertTrue(any(rule.get("rule_set") == ["remote-ads"] for rule in route["rules"]))

    def test_complex_selector_with_inline_srs_and_process_rules_is_emitted(self) -> None:
        rules = SplitRules(
            enabled=True,
            rule_set_resources=[
                RouteRuleSetResource(
                    name="inline",
                    type="inline",
                    tag="inline-ru",
                    rules=[{"domain_suffix": ["ru"]}],
                ),
            ],
            rule_sets=[
                RoutingRuleSet(
                    name="complex",
                    outbound=ROUTE_OUTBOUND_DIRECT,
                    priority=10,
                    domains=["EXAMPLE.com", "https://api.example.com/path"],
                    domain_suffix=[".ru"],
                    domain_keyword=["cdn", "cdn"],
                    domain_regex=[r".*\\.internal$"],
                    geosite=["category-ads-all"],
                    geoip=["private"],
                    ip_cidr=["10.0.0.0/8"],
                    process_name=[r"C:\Tools\App.exe --flag", "browser.exe"],
                    process_path=[r"C:\Program Files\App\app.exe --flag"],
                    process_path_regex=[r".*\\app\\.exe$"],
                    rule_set_tags=["inline-ru"],
                    rule_set_ip_cidr_match_source=True,
                )
            ],
        )

        route = RouteBuilder().build(rules)
        selector = next(rule for rule in route["rules"] if rule.get("rule_set") == ["inline-ru"])

        self.assertEqual(route["rule_set"][0], {"type": "inline", "tag": "inline-ru", "rules": [{"domain_suffix": ["ru"]}]})
        self.assertEqual(selector["domain"], ["api.example.com", "example.com"])
        self.assertEqual(selector["domain_suffix"], ["example.com", "ru"])
        self.assertEqual(selector["domain_keyword"], ["cdn"])
        self.assertEqual(selector["domain_regex"], [r".*\\.internal$"])
        self.assertEqual(selector["geosite"], ["category-ads-all"])
        self.assertEqual(selector["geoip"], ["private"])
        self.assertEqual(selector["ip_cidr"], ["10.0.0.0/8"])
        self.assertEqual(selector["process_name"], ["App.exe", "browser.exe"])
        self.assertEqual(selector["process_path"], [r"C:\Program Files\App\app.exe"])
        self.assertEqual(selector["process_path_regex"], [r".*\\app\\.exe$"])
        self.assertTrue(selector["rule_set_ip_cidr_match_source"])

    def test_inline_srs_resource_without_rules_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigBuildError, "пуст"):
            RouteBuilder()._build_route_rule_set(
                RouteRuleSetResource(name="empty inline", type="inline", tag="empty", rules=[])
            )


if __name__ == "__main__":
    unittest.main()
