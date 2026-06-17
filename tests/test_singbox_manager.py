import json
import logging
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.singbox_manager import SingBoxManager
from models.connection import SMART_GROUP_MODE_MULTI_HOP, SmartGroup
from models.profile import VlessProfile
from models.rules import SplitRules
from models.settings import AppSettings


def profile(profile_id: str, *, number: int = 1) -> VlessProfile:
    return VlessProfile(
        id=profile_id,
        name=profile_id,
        protocol="vless",
        address=f"{profile_id}.example.com",
        port=443,
        uuid=f"00000000-0000-4000-8000-{number:012d}",
    )


def settings(**overrides: object) -> AppSettings:
    data = AppSettings(mode="proxy").to_dict()
    data.update(overrides)
    return AppSettings.from_dict(data)


class SingBoxManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SingBoxManager(logging.getLogger("tests.singbox_manager"))
        self.split_rules = SplitRules()
        self.profile = profile("server-a", number=1)

    def test_profile_fingerprint_changes_when_ipv6_is_toggled(self) -> None:
        base = settings(enable_ipv6=True)
        changed = settings(enable_ipv6=False)

        self.assertNotEqual(
            self.manager._connection_fingerprint(self.profile, base, self.split_rules),
            self.manager._connection_fingerprint(self.profile, changed, self.split_rules),
        )

    def test_profile_fingerprint_changes_when_tun_ipv6_address_changes(self) -> None:
        base = settings(tun_ipv6_address="fdfe:dcba:9876::1/126")
        changed = settings(tun_ipv6_address="fdfe:dcba:9876::5/126")

        self.assertNotEqual(
            self.manager._connection_fingerprint(self.profile, base, self.split_rules),
            self.manager._connection_fingerprint(self.profile, changed, self.split_rules),
        )

    def test_profile_fingerprint_changes_when_dns_strategy_changes(self) -> None:
        base = settings(dns_strategy="prefer_ipv4")
        changed = settings(dns_strategy="prefer_ipv6")

        self.assertNotEqual(
            self.manager._connection_fingerprint(self.profile, base, self.split_rules),
            self.manager._connection_fingerprint(self.profile, changed, self.split_rules),
        )

    def test_group_fingerprint_includes_ipv6_and_dns_runtime_settings(self) -> None:
        profiles_by_id = {
            "server-a": profile("server-a", number=1),
            "server-b": profile("server-b", number=2),
        }
        group = SmartGroup(
            id="group-1",
            name="chain",
            mode=SMART_GROUP_MODE_MULTI_HOP,
            profile_ids=["server-a", "server-b"],
        )
        base = settings(enable_ipv6=True, tun_ipv6_address="fdfe:dcba:9876::1/126", dns_strategy="prefer_ipv4")
        changed = settings(enable_ipv6=True, tun_ipv6_address="fdfe:dcba:9876::5/126", dns_strategy="prefer_ipv6")

        self.assertNotEqual(
            self.manager._group_connection_fingerprint(group, profiles_by_id, base, self.split_rules),
            self.manager._group_connection_fingerprint(group, profiles_by_id, changed, self.split_rules),
        )

    def test_profile_config_check_uses_temporary_file_without_replacing_runtime_config(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            runtime_path = Path(tmp_dir) / "sing-box-runtime.json"
            runtime_content = '{"runtime": true}\n'
            runtime_path.write_text(runtime_content, encoding="utf-8")
            self.manager.config_path = runtime_path
            checked_paths: list[Path] = []

            def fake_check_config(config_path: Path | None = None) -> tuple[bool, str]:
                self.assertIsNotNone(config_path)
                target = Path(config_path or runtime_path)
                checked_paths.append(target)
                payload = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(payload["outbounds"][0]["tag"], "proxy")
                return True, "config OK"

            self.manager.check_config = fake_check_config  # type: ignore[method-assign]

            ok, output = self.manager.check_profile_config(self.profile, settings(), self.split_rules)

            self.assertTrue(ok)
            self.assertEqual(output, "config OK")
            self.assertEqual(runtime_path.read_text(encoding="utf-8"), runtime_content)
            self.assertEqual(len(checked_paths), 1)
            self.assertNotEqual(checked_paths[0], runtime_path)
            self.assertEqual(checked_paths[0].name, "sing-box-check.json")
            self.assertFalse(checked_paths[0].exists())


if __name__ == "__main__":
    unittest.main()
