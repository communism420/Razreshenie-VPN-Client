import unittest

from core.app_updater import AppUpdateError
from core.error_messages import format_user_error


class ErrorMessagesTests(unittest.TestCase):
    def test_reality_error_gets_actionable_category(self) -> None:
        message = format_user_error(ValueError("VLESS Reality: некорректный pbk/publicKey"))

        self.assertEqual(message.category, "reality")
        self.assertIn("Reality", message.display_text)
        self.assertIn("pbk/publicKey", message.display_text)

    def test_group_error_gets_actionable_category(self) -> None:
        message = format_user_error(ValueError("Multi-hop hop 2 'server': VLESS требует UUID"))

        self.assertEqual(message.category, "group")
        self.assertIn("группу серверов", message.display_text)

    def test_update_error_gets_actionable_category(self) -> None:
        message = format_user_error(AppUpdateError("Скачанный файл обновления пустой"))

        self.assertEqual(message.category, "update")
        self.assertIn("обновить приложение", message.display_text)

    def test_subscription_context_keeps_subscription_priority(self) -> None:
        message = format_user_error("ошибка обновления", context="Подписка")

        self.assertEqual(message.category, "subscription")


if __name__ == "__main__":
    unittest.main()
