import base64
import json
import tempfile
import unittest
from pathlib import Path

from core.subscription_importer import SubscriptionImporter
from core.subscription_types import ImportProgress, SubscriptionError


UUID_A = "00000000-0000-4000-8000-000000000001"
UUID_B = "00000000-0000-4000-8000-000000000002"


def vless_link(uuid: str = UUID_A, name: str = "Server") -> str:
    return f"vless://{uuid}@example.com:443?security=tls&sni=example.com#{name}"


class SubscriptionImporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.importer = SubscriptionImporter()

    def test_parse_text_extracts_mixed_uri_lines_and_suffixes_duplicate_names(self) -> None:
        profiles = self.importer.parse_text(
            "\n".join(
                [
                    vless_link(UUID_A, "Same"),
                    f"trojan://secret@example.org:443?security=tls#Same",
                    "ss://aes-128-gcm:secret@example.net:8388#Other",
                ]
            ),
            subscription_id="sub",
        )

        self.assertEqual([item.protocol for item in profiles], ["vless", "trojan", "shadowsocks"])
        self.assertEqual([item.name for item in profiles], ["Same", "Same-1", "Other"])
        self.assertTrue(all(item.subscription_id == "sub" for item in profiles))

    def test_parse_text_decodes_base64_subscription_payload(self) -> None:
        payload = "\n".join([vless_link(UUID_A, "A"), vless_link(UUID_B, "B")])
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")

        profiles = self.importer.parse_text(encoded, subscription_id="base64-sub")

        self.assertEqual([item.name for item in profiles], ["A", "B"])
        self.assertEqual([item.uuid for item in profiles], [UUID_A, UUID_B])

    def test_parse_clash_yaml_applies_group_metadata_and_skips_service_groups(self) -> None:
        payload = """
proxies:
  - name: RU VLESS
    type: vless
    server: ru.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    servername: front.example.com
  - name: RU Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: secret
proxy-groups:
  - name: Auto RU
    type: url-test
    proxies:
      - RU VLESS
      - RU Trojan
"""

        profiles = self.importer.parse_text(payload, subscription_id="clash")

        self.assertEqual([item.name for item in profiles], ["RU VLESS", "RU Trojan"])
        self.assertEqual([item.group for item in profiles], ["Auto RU", "Auto RU"])
        self.assertEqual(profiles[0].tags, ["Auto RU", "RU VLESS"])
        self.assertEqual(profiles[0].params["security"], "tls")
        self.assertEqual(profiles[0].params["sni"], "front.example.com")

    def test_parse_sing_box_json_ignores_selector_and_urltest_outbounds(self) -> None:
        payload = {
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["node-1"]},
                {"type": "urltest", "tag": "auto", "outbounds": ["node-1"]},
                {
                    "type": "vless",
                    "tag": "node-1",
                    "server": "node.example.com",
                    "server_port": 443,
                    "uuid": UUID_A,
                    "tls": {"enabled": True, "server_name": "front.example.com"},
                },
            ]
        }

        profiles = self.importer.parse_text(json.dumps(payload), subscription_id="singbox")

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].name, "node-1")
        self.assertEqual(profiles[0].protocol, "vless")
        self.assertEqual(profiles[0].params["sni"], "front.example.com")

    def test_parse_many_keeps_successes_and_reports_progress_for_partial_failures(self) -> None:
        events: list[ImportProgress] = []

        profiles = self.importer.parse_many(
            [
                ("bad", "not a server"),
                ("good", vless_link(UUID_A, "Good")),
            ],
            subscription_id="many",
            progress_callback=events.append,
        )

        self.assertEqual([item.name for item in profiles], ["Good"])
        self.assertEqual([(event.current, event.total, event.imported, event.errors) for event in events], [(1, 2, 0, 1), (2, 2, 1, 1)])

    def test_parse_many_raises_when_all_sources_fail(self) -> None:
        with self.assertRaisesRegex(SubscriptionError, "Не удалось импортировать серверы"):
            self.importer.parse_many([("bad", "not a server")])

    def test_parse_files_reads_multiple_files_and_reports_file_errors(self) -> None:
        events: list[ImportProgress] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good.txt"
            missing = root / "missing.txt"
            good.write_text(vless_link(UUID_A, "File"), encoding="utf-8")

            profiles = self.importer.parse_files([missing, good], progress_callback=events.append)

        self.assertEqual([item.name for item in profiles], ["File"])
        self.assertEqual(events[-1].total, 2)
        self.assertEqual(events[-1].imported, 1)
        self.assertEqual(events[-1].errors, 1)


if __name__ == "__main__":
    unittest.main()
