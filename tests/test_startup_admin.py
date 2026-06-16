import unittest
from unittest.mock import patch

import main
from models.settings import AppSettings


class StartupAdminTests(unittest.TestCase):
    def test_startup_admin_setting_relaunches_when_enabled(self) -> None:
        with patch("utils.windows.is_windows", return_value=True), patch(
            "utils.windows.is_admin",
            return_value=False,
        ), patch("core.app_state.load_settings", return_value=AppSettings(always_run_as_admin=True)), patch(
            "utils.windows.relaunch_as_admin",
            return_value=True,
        ) as relaunch:
            self.assertTrue(main.maybe_relaunch_as_admin_for_startup())

        relaunch.assert_called_once_with()

    def test_startup_admin_setting_does_not_relaunch_when_disabled(self) -> None:
        with patch("utils.windows.is_windows", return_value=True), patch(
            "utils.windows.is_admin",
            return_value=False,
        ), patch("core.app_state.load_settings", return_value=AppSettings(always_run_as_admin=False)), patch(
            "utils.windows.relaunch_as_admin",
        ) as relaunch:
            self.assertFalse(main.maybe_relaunch_as_admin_for_startup())

        relaunch.assert_not_called()

    def test_startup_admin_setting_does_not_relaunch_when_already_admin(self) -> None:
        with patch("utils.windows.is_windows", return_value=True), patch(
            "utils.windows.is_admin",
            return_value=True,
        ), patch("core.app_state.load_settings") as load_settings, patch("utils.windows.relaunch_as_admin") as relaunch:
            self.assertFalse(main.maybe_relaunch_as_admin_for_startup())

        load_settings.assert_not_called()
        relaunch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
