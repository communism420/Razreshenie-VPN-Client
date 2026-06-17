import unittest

from core.routing_service import (
    LIVE_ACTIVITY_RULE_SOURCE_TYPE,
    MATCH_KIND_PROCESS_NAME,
    RoutingService,
)
from core.rules_manager import RulesImportResult
from models.rules import (
    ROUTE_OUTBOUND_DIRECT,
    ROUTE_OUTBOUND_PROXY,
    RouteRuleSetResource,
    RoutingRuleSet,
    SplitRules,
)


class RoutingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RoutingService()

    def test_import_result_adds_priorities_and_deduplicates_resources(self) -> None:
        rules = SplitRules(
            enabled=True,
            rule_sets=[RoutingRuleSet(id="existing", name="existing", priority=1000)],
            rule_set_resources=[
                RouteRuleSetResource(name="old", type="remote", tag="ru", url="https://old.example/ru.srs")
            ],
        )
        imported_rule = RoutingRuleSet(id="imported", name="imported", domains=["example.com"])
        result = RulesImportResult(
            rule_sets=[imported_rule],
            rule_set_resources=[
                RouteRuleSetResource(name="new", type="remote", tag="ru", url="https://new.example/ru.srs"),
                RouteRuleSetResource(name="ads", type="remote", tag="ads", url="https://new.example/ads.srs"),
            ],
        )

        mutation = self.service.add_import_result(rules, result)

        self.assertTrue(mutation.changed)
        self.assertTrue(mutation.restart_required)
        self.assertEqual(mutation.selected_rule_id, "imported")
        self.assertEqual(imported_rule.priority, 1010)
        self.assertEqual([resource.tag for resource in rules.rule_set_resources], ["ru", "ads"])
        self.assertEqual(rules.rule_set_resources[0].url, "https://new.example/ru.srs")
        self.assertTrue(rules.enabled)

    def test_per_app_upsert_updates_existing_rule_without_duplicate(self) -> None:
        rules = SplitRules()

        created = self.service.upsert_per_app_rule(
            rules,
            name="Chrome",
            outbound=ROUTE_OUTBOUND_DIRECT,
            match_kind=MATCH_KIND_PROCESS_NAME,
            value="chrome.exe",
        )
        updated = self.service.upsert_per_app_rule(
            rules,
            name="Chrome VPN",
            outbound=ROUTE_OUTBOUND_PROXY,
            match_kind=MATCH_KIND_PROCESS_NAME,
            value="chrome.exe",
        )

        self.assertTrue(created.changed)
        self.assertTrue(updated.changed)
        self.assertEqual(len(rules.rule_sets), 1)
        rule = rules.rule_sets[0]
        self.assertEqual(rule.name, "Chrome VPN")
        self.assertEqual(rule.outbound, ROUTE_OUTBOUND_PROXY)
        self.assertEqual(rule.process_name, ["chrome.exe"])
        self.assertEqual(created.selected_rule_id, updated.selected_rule_id)

    def test_move_rule_set_orders_and_renumbers_priorities(self) -> None:
        rules = SplitRules(
            rule_sets=[
                RoutingRuleSet(id="a", name="A", priority=10),
                RoutingRuleSet(id="b", name="B", priority=20),
                RoutingRuleSet(id="c", name="C", priority=30),
            ]
        )

        mutation = self.service.move_rule_set(rules, "b", -1)

        self.assertTrue(mutation.changed)
        self.assertEqual([rule.id for rule in rules.rule_sets], ["b", "a", "c"])
        self.assertEqual([rule.priority for rule in rules.rule_sets], [10, 20, 30])
        self.assertEqual(mutation.selected_rule_id, "b")

    def test_delete_rule_set_prunes_unused_resources(self) -> None:
        rules = SplitRules(
            enabled=True,
            rule_set_resources=[
                RouteRuleSetResource(name="ru", type="remote", tag="ru", url="https://example.com/ru.srs"),
                RouteRuleSetResource(name="ads", type="remote", tag="ads", url="https://example.com/ads.srs"),
            ],
            rule_sets=[
                RoutingRuleSet(id="ru-rule", name="RU", rule_set_tags=["ru"]),
                RoutingRuleSet(id="ads-rule", name="Ads", rule_set_tags=["ads"]),
            ],
        )

        mutation = self.service.delete_rule_set(rules, "ads-rule")

        self.assertTrue(mutation.changed)
        self.assertEqual([rule.id for rule in rules.rule_sets], ["ru-rule"])
        self.assertEqual([resource.tag for resource in rules.rule_set_resources], ["ru"])
        self.assertTrue(rules.enabled)

    def test_clear_rule_sets_resets_split_rules_and_resources(self) -> None:
        rules = SplitRules(
            enabled=True,
            default_outbound=ROUTE_OUTBOUND_DIRECT,
            rule_set_resources=[
                RouteRuleSetResource(name="ru", type="remote", tag="ru", url="https://example.com/ru.srs")
            ],
            rule_sets=[RoutingRuleSet(id="ru-rule", name="RU", rule_set_tags=["ru"])],
        )

        mutation = self.service.clear_rule_sets(rules)
        second = self.service.clear_rule_sets(rules)

        self.assertTrue(mutation.changed)
        self.assertTrue(mutation.restart_required)
        self.assertFalse(second.changed)
        self.assertFalse(rules.enabled)
        self.assertEqual(rules.default_outbound, ROUTE_OUTBOUND_PROXY)
        self.assertEqual(rules.rule_sets, [])
        self.assertEqual(rules.rule_set_resources, [])

    def test_live_activity_adds_direct_suffix_and_proxy_domain(self) -> None:
        rules = SplitRules()

        direct = self.service.add_activity_rule(
            rules,
            domain="https://sub.example.com/path",
            match_kind="domain_suffix",
            outbound=ROUTE_OUTBOUND_DIRECT,
        )
        duplicate = self.service.add_activity_rule(
            rules,
            domain="sub.example.com",
            match_kind="domain_suffix",
            outbound=ROUTE_OUTBOUND_DIRECT,
        )
        proxy = self.service.add_activity_rule(
            rules,
            domain="api.test.org",
            match_kind="domain",
            outbound=ROUTE_OUTBOUND_PROXY,
        )

        self.assertTrue(direct.changed)
        self.assertFalse(duplicate.changed)
        self.assertEqual(duplicate.status_level, "info")
        self.assertTrue(proxy.changed)
        direct_rule = next(rule for rule in rules.rule_sets if rule.outbound == ROUTE_OUTBOUND_DIRECT)
        proxy_rule = next(rule for rule in rules.rule_sets if rule.outbound == ROUTE_OUTBOUND_PROXY)
        self.assertEqual(direct_rule.source_type, LIVE_ACTIVITY_RULE_SOURCE_TYPE)
        self.assertEqual(direct_rule.domain_suffix, ["example.com"])
        self.assertEqual(proxy_rule.domains, ["api.test.org"])
        self.assertTrue(rules.enabled)


if __name__ == "__main__":
    unittest.main()
