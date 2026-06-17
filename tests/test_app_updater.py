import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.app_updater import (
    AppReleaseAsset,
    AppUpdateInfo,
    AppUpdateError,
    PreparedInPlaceUpdate,
    app_release_api_url,
    download_update_asset,
    is_newer_version,
    launch_in_place_update,
    prepare_in_place_update,
    select_checksum_asset,
    select_windows_asset,
    update_info_from_release,
)
from models.settings import APP_UPDATE_MODE_DOWNLOAD_ONLY, APP_UPDATE_MODE_REPLACE_CURRENT, AppSettings


def asset(name: str, url: str | None = None, *, size: int = 123) -> dict[str, object]:
    download_url = url if url is not None else f"https://downloads.example/{name}"
    return {
        "name": name,
        "browser_download_url": download_url,
        "html_url": f"https://github.com/example/repo/releases/download/v4.0.0/{name}",
        "size": size,
    }


class FakeDownloadResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        return False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        yield from self.chunks


class AppUpdaterTests(unittest.TestCase):
    def test_app_update_mode_is_normalized(self) -> None:
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "replace"}).app_update_mode, APP_UPDATE_MODE_REPLACE_CURRENT)
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "manual"}).app_update_mode, APP_UPDATE_MODE_DOWNLOAD_ONLY)
        self.assertEqual(AppSettings.from_dict({"app_update_mode": "bad"}).app_update_mode, APP_UPDATE_MODE_DOWNLOAD_ONLY)

    def test_release_api_url_accepts_github_repo_and_rejects_other_hosts(self) -> None:
        self.assertEqual(
            app_release_api_url("https://github.com/owner/repo"),
            "https://api.github.com/repos/owner/repo/releases/latest",
        )
        self.assertEqual(
            app_release_api_url("https://www.github.com/owner/repo/tree/main"),
            "https://api.github.com/repos/owner/repo/releases/latest",
        )
        with self.assertRaises(AppUpdateError):
            app_release_api_url("https://gitlab.com/owner/repo")

    def test_is_newer_version_handles_prefixes_prereleases_and_build_metadata(self) -> None:
        self.assertTrue(is_newer_version("v4.0.0", "4.0.0-rc1"))
        self.assertTrue(is_newer_version("4.0.1+build.5", "4.0.0"))
        self.assertFalse(is_newer_version("4.0.0-rc1", "4.0.0"))
        self.assertFalse(is_newer_version("4.0.0", "4.0.0+local"))

    def test_select_windows_asset_prefers_installer_and_skips_non_update_files(self) -> None:
        selected = select_windows_asset(
            [
                asset("source-code.zip"),
                asset("RazreshenieVPN-linux-x64.deb"),
                asset("RazreshenieVPN-win-arm64.exe"),
                asset("RazreshenieVPN-win-x64.zip"),
                asset("RazreshenieVPN-Setup-Windows-x64.exe"),
                asset("RazreshenieVPN-Setup-Windows-x64.exe.sha256"),
            ]
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected.name, "RazreshenieVPN-Setup-Windows-x64.exe")

    def test_update_info_from_release_selects_asset_checksum_and_version_status(self) -> None:
        release = {
            "tag_name": "v4.0.0",
            "name": "Razreshenie VPN Client 4.0.0",
            "html_url": "https://github.com/example/repo/releases/tag/v4.0.0",
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                asset("RazreshenieVPN-Setup-Windows-x64.exe", size=42),
                asset("RazreshenieVPN-Setup-Windows-x64.exe.sha256"),
            ],
        }

        info = update_info_from_release(release, current_version="3.3.1")

        self.assertTrue(info.update_available)
        self.assertEqual(info.latest_version, "4.0.0")
        self.assertEqual(info.release_name, "Razreshenie VPN Client 4.0.0")
        self.assertEqual(info.asset_name, "RazreshenieVPN-Setup-Windows-x64.exe")
        self.assertIsNotNone(info.checksum_asset)
        self.assertEqual(info.checksum_asset.name, "RazreshenieVPN-Setup-Windows-x64.exe.sha256")

    def test_select_checksum_asset_uses_matching_target_before_fallback(self) -> None:
        selected = select_checksum_asset(
            [
                asset("generic-checksums.txt"),
                asset("RazreshenieVPN-Setup-Windows-x64.exe.sha256"),
            ],
            "RazreshenieVPN-Setup-Windows-x64.exe",
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected.name, "RazreshenieVPN-Setup-Windows-x64.exe.sha256")

    def test_download_update_asset_rejects_empty_file(self) -> None:
        info = AppUpdateInfo(
            current_version="3.3.1",
            latest_version="4.0.0",
            update_available=True,
            release_url="https://github.com/example/repo/releases/tag/v4.0.0",
            asset=AppReleaseAsset("RazreshenieVPN-Setup-Windows-x64.exe", "https://downloads.example/app.exe"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch("core.app_updater.requests.get", return_value=FakeDownloadResponse([b""])):
                with self.assertRaisesRegex(AppUpdateError, "пустой"):
                    download_update_asset(info, target_dir=Path(tmp), verify_checksum=False)

            self.assertFalse((Path(tmp) / "RazreshenieVPN-Setup-Windows-x64.exe.part").exists())

    def test_prepare_in_place_update_writes_batch_for_current_exe_folder(self) -> None:
        if os.name != "nt":
            self.skipTest("in-place EXE update script is Windows-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "Razreshenie VPN Client 3.3.0.exe"
            update = root / "downloads" / "Razreshenie VPN Client 3.3.1.exe"
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
            self.assertEqual(plan.install_path, current)
            self.assertGreater(plan.process_id, 0)
            self.assertTrue(plan.script_path.exists())
            script = plan.script_path.read_text(encoding="utf-8")
            self.assertIn(str(current), script)
            self.assertIn(str(update), script)
            self.assertIn("tasklist /FI \"PID eq %PID%\"", script)
            self.assertIn("taskkill /PID %PID% /T /F", script)
            self.assertIn("move /y \"%OLD%\" \"%BACKUP%\"", script)
            self.assertIn("copy /y \"%NEW%\" \"%OLD%\"", script)
            self.assertIn("move /y \"%BACKUP%\" \"%OLD%\"", script)

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

    def test_prepare_in_place_update_rejects_empty_exe_asset(self) -> None:
        if os.name != "nt":
            self.skipTest("in-place EXE update script is Windows-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "app.exe"
            update = root / "app-update.exe"
            current.write_bytes(b"old")
            update.write_bytes(b"")

            with self.assertRaisesRegex(AppUpdateError, "пустой"):
                prepare_in_place_update(update, current_executable=current, require_frozen=False)

    def test_launch_in_place_update_rejects_missing_script(self) -> None:
        plan = PreparedInPlaceUpdate(
            downloaded_path=Path("app-update.exe"),
            script_path=Path("missing-apply-update.bat"),
            current_executable=Path("app.exe"),
            install_path=Path("app.exe"),
            process_id=123,
        )

        with self.assertRaisesRegex(AppUpdateError, "Скрипт"):
            launch_in_place_update(plan)


if __name__ == "__main__":
    unittest.main()
