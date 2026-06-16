import os
import tempfile
import unittest
from pathlib import Path

from core.app_updater import AppUpdateError, prepare_in_place_update
from models.settings import APP_UPDATE_MODE_DOWNLOAD_ONLY, APP_UPDATE_MODE_REPLACE_CURRENT, AppSettings


class AppUpdaterTests(unittest.TestCase):
    def test_app_update_mode_is_normalized(self) -> None:
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "replace"}).app_update_mode, APP_UPDATE_MODE_REPLACE_CURRENT)
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "manual"}).app_update_mode, APP_UPDATE_MODE_DOWNLOAD_ONLY)
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "bad"}).app_update_mode, APP_UPDATE_MODE_DOWNLOAD_ONLY)

    def test_prepare_in_place_update_writes_batch_for_current_exe_folder(self) -> None:
        if os.name != "nt":
            self.skipTest("in-place EXE update script is Windows-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "Razreshenie VPN Client 3.1.0.exe"
            update = root / "downloads" / "Razreshenie VPN Client 3.2.1.exe"
            current.write_bytes(b"old")
            update.parent.mkdir()
            update.write_bytes(b"new")

            plan = prepare_in_place_update(
                update,
                current_executable=current,
                updates_dir=root / "updates",
                require_frozen=False,
            )

            self.assertEqual(plan.current_executable, current)
            self.assertEqual(plan.install_path, root / "Razreshenie VPN Client 3.2.1.exe")
            self.assertTrue(plan.script_path.exists())
            script = plan.script_path.read_text(encoding="utf-8")
            self.assertIn(str(current), script)
            self.assertIn(str(plan.install_path), script)
            self.assertIn("del /f /q \"%OLD%\"", script)

    def test_prepare_in_place_update_rejects_non_exe_asset(self) -> None:
        if os.name != "nt":
            self.skipTest("in-place EXE update script is Windows-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "app.exe"
            update = root / "app.zip"
            current.write_bytes(b"old")
            update.write_bytes(b"new")

            with self.assertRaises(AppUpdateError):
                prepare_in_place_update(update, current_executable=current, require_frozen=False)


if __name__ == "__main__":
    unittest.main()
