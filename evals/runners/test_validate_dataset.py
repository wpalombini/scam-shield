import json
import tempfile
import unittest
from pathlib import Path

from validate_dataset import load_dataset, validate_record


def record(**overrides):
    base = {
        "id": "test-001",
        "text": "Example message",
        "label": "scam",
        "category": "hi_mum",
        "channel": "sms",
        "language": "en-AU",
        "source": "synthetic",
        "licence": "project-original",
        "hard_negative": False,
    }
    return {**base, **overrides}


class ValidateRecordTests(unittest.TestCase):
    def test_accepts_valid_record(self):
        self.assertEqual(validate_record(record()), [])

    def test_rejects_category_from_other_label(self):
        self.assertTrue(validate_record(record(category="bank_notice")))

    def test_rejects_unknown_label(self):
        self.assertTrue(validate_record(record(label="safe")))

    def test_requires_source_url_for_non_synthetic(self):
        self.assertTrue(validate_record(record(source="public_alert")))

    def test_hard_negative_must_be_legit(self):
        self.assertTrue(validate_record(record(hard_negative=True)))

    def test_requires_licence(self):
        self.assertTrue(validate_record(record(licence="")))

    def test_reports_non_string_values_without_crashing(self):
        for field in ("label", "category", "channel", "source"):
            with self.subTest(field=field):
                self.assertTrue(validate_record(record(**{field: ["scam"]})))

    def test_rejects_non_object(self):
        self.assertTrue(validate_record(["not", "an", "object"]))


class LoadDatasetTests(unittest.TestCase):
    def load(self, content):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "data.jsonl").write_text(content, encoding="utf-8")
            return load_dataset(directory)

    def test_reports_duplicate_ids(self):
        line = json.dumps(record())
        _, errors = self.load(f"{line}\n{line}\n")
        self.assertTrue(any("duplicate id" in error for error in errors))

    def test_reports_invalid_json_with_location(self):
        _, errors = self.load("{oops\n")
        self.assertIn("data.jsonl:1", errors[0])


if __name__ == "__main__":
    unittest.main()
