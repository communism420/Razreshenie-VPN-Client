import unittest

from models.rules import (
    clean_process_names,
    clean_process_paths,
    looks_like_process_executable_path,
)


class ProcessRuleTests(unittest.TestCase):
    def test_full_executable_path_is_detected_without_requiring_existing_file(self) -> None:
        value = r"C:\Program Files\Example App\Example.exe"

        self.assertTrue(looks_like_process_executable_path(value))
        self.assertEqual(clean_process_paths([value]), [value])

    def test_quoted_executable_path_with_arguments_is_detected_and_trimmed(self) -> None:
        value = r'"C:\Program Files\Example App\Example.exe" --flag'

        self.assertTrue(looks_like_process_executable_path(value))
        self.assertEqual(clean_process_paths([value]), [r"C:\Program Files\Example App\Example.exe"])

    def test_plain_process_name_is_not_treated_as_full_path(self) -> None:
        self.assertFalse(looks_like_process_executable_path("Telegram.exe"))
        self.assertEqual(clean_process_names([r"C:\Program Files\Telegram Desktop\Telegram.exe"]), ["Telegram.exe"])


if __name__ == "__main__":
    unittest.main()
