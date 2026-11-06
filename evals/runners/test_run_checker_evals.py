import json
import unittest

from run_checker_evals import build_report
from scam_shield.checker import CHECK_FAILED, NO_RED_FLAGS, RED_FLAGS, CheckResult


def record(record_id, label, source="synthetic", hard_negative=False):
    return {
        "id": record_id,
        "text": f"SECRET TEXT {record_id}",
        "label": label,
        "category": "hi_mum" if label == "scam" else "family",
        "source": source,
        "hard_negative": hard_negative,
    }


def result(status, cost=0.01, latency=100, error=""):
    return CheckResult(status, "", cost_usd=cost, latency_ms=latency, error=error)


class BuildReportTests(unittest.TestCase):
    def setUp(self):
        self.pairs = [
            (record("s1", "scam", "public_alert"), result(RED_FLAGS)),
            (record("s2", "scam"), result(NO_RED_FLAGS)),
            (record("s3", "scam"), result(CHECK_FAILED, cost=0, latency=5, error="network")),
            (record("l1", "legit", hard_negative=True), result(RED_FLAGS)),
            (record("l2", "legit"), result(NO_RED_FLAGS, latency=900)),
        ]
        self.redteam = [
            ({"id": "i1", "expected": RED_FLAGS}, result(RED_FLAGS)),
            ({"id": "i2", "expected": RED_FLAGS}, result(NO_RED_FLAGS)),
        ]
        self.report = build_report(self.pairs, self.redteam, "fake/model")

    def test_failed_checks_are_counted_separately(self):
        overall = self.report["overall"]
        self.assertEqual(overall["failed_checks"], 1)
        self.assertEqual(overall["recall"], 0.5)
        self.assertEqual(overall["missed_scams"], ["s2"])

    def test_false_alarms_and_hard_negatives(self):
        self.assertEqual(self.report["overall"]["false_positive_rate"], 0.5)
        self.assertEqual(self.report["overall"]["false_alarms"], ["l1"])
        self.assertEqual(self.report["hard_negatives"]["false_positive_rate"], 1.0)

    def test_real_and_synthetic_are_separate(self):
        self.assertEqual(self.report["real"]["recall"], 1.0)
        self.assertEqual(self.report["synthetic"]["recall"], 0.0)

    def test_no_scams_gives_no_recall_rather_than_a_crash(self):
        self.assertIsNone(build_report([], [], "fake/model")["overall"]["recall"])

    def test_red_team_failures_are_listed(self):
        self.assertEqual(self.report["red_team"]["passed"], 1)
        self.assertEqual(self.report["red_team"]["failed"], ["i2"])

    def test_cost_and_latency(self):
        self.assertEqual(self.report["cost_usd_total"], 0.06)
        self.assertEqual(self.report["latency_ms_p95"], 900)
        self.assertEqual(self.report["errors"], ["network"])

    def test_report_never_contains_message_text(self):
        self.assertNotIn("SECRET TEXT", json.dumps(self.report))


if __name__ == "__main__":
    unittest.main()
