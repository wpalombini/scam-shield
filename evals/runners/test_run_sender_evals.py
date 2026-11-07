import json
import unittest
from pathlib import Path

from run_sender_evals import CASES_FILE, build_sender_report
from scam_shield.checker import CHANNELS, NO_RED_FLAGS, RED_FLAGS, CheckResult


def result(status):
    return CheckResult(status, "", cost_usd=0.01)


class SenderReportTests(unittest.TestCase):
    def setUp(self):
        self.cases = [
            {"id": "p1-plausible", "group": "pair", "pair": "p1", "text": "SECRET", "expected": NO_RED_FLAGS},
            {"id": "p1-suspicious", "group": "pair", "pair": "p1", "text": "SECRET", "expected": RED_FLAGS},
            {"id": "s1", "group": "spoof", "text": "SECRET", "expected": RED_FLAGS},
        ]
        self.report = build_sender_report(
            self.cases,
            {"p1-plausible": result(NO_RED_FLAGS), "p1-suspicious": result(RED_FLAGS), "s1": result(NO_RED_FLAGS)},
            {"p1-plausible": result(NO_RED_FLAGS), "s1": result(RED_FLAGS)},
            "fake/model",
        )

    def test_scores(self):
        scores = self.report["with_sender"]
        self.assertEqual(scores["suspicious_flagged"], 1)
        self.assertEqual(scores["plausible_flagged"], 0)
        self.assertEqual(scores["pairs_both_correct"], 1)
        self.assertEqual(scores["spoofs_flagged"], 0)
        self.assertEqual(scores["wrong"], ["s1"])
        self.assertEqual(self.report["text_only"]["spoofs_flagged"], 1)

    def test_report_never_contains_message_text(self):
        self.assertNotIn("SECRET", json.dumps(self.report))


class SenderCasesTests(unittest.TestCase):
    def test_cases_are_valid(self):
        cases = [json.loads(line) for line in Path(CASES_FILE).read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        for case in cases:
            self.assertIn(case["channel"], CHANNELS)
            self.assertIn(case["expected"], (RED_FLAGS, NO_RED_FLAGS))
        for pair in {case["pair"] for case in cases if case["group"] == "pair"}:
            sides = [case for case in cases if case.get("pair") == pair]
            self.assertEqual(len(sides), 2)
            self.assertEqual(sides[0]["text"], sides[1]["text"])
            self.assertNotEqual(sides[0]["expected"], sides[1]["expected"])


if __name__ == "__main__":
    unittest.main()
