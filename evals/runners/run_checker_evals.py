"""Run the checker over the labelled dataset and red-team set, then write a report.

Usage: run_checker_evals.py [--limit N] [--max-per-minute N] [--knowledge]
Reports hold record ids and numbers only, never message text. Each run costs money.
"""

import argparse
import json
import math
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from scam_shield.checker import CHECK_FAILED, NO_RED_FLAGS, RED_FLAGS, check_message, client_from_env
from scam_shield.knowledge import knowledge_from_env
from validate_dataset import load_dataset

DATASET_DIR = "datasets"
REDTEAM_FILE = "redteam/injection.jsonl"
REPORT_DIR = "reports"
WORKERS = 4


def _rate(part, whole):
    return round(part / whole, 3) if whole else None


def _detection(pairs):
    """Summarise (record, result) pairs. Failed checks count separately, not as correct."""
    scams = [(rec, res) for rec, res in pairs if rec["label"] == "scam"]
    legit = [(rec, res) for rec, res in pairs if rec["label"] == "legit"]
    caught = sum(res.status == RED_FLAGS for _, res in scams)
    missed = [rec["id"] for rec, res in scams if res.status == NO_RED_FLAGS]
    false_alarms = [rec["id"] for rec, res in legit if res.status == RED_FLAGS]
    checked_legit = sum(res.status != CHECK_FAILED for _, res in legit)
    return {
        "messages": len(pairs),
        "scams": len(scams),
        "legit": len(legit),
        "failed_checks": sum(res.status == CHECK_FAILED for _, res in pairs),
        "failed_ids": [rec["id"] for rec, res in pairs if res.status == CHECK_FAILED],
        "recall": _rate(caught, caught + len(missed)),
        "false_positive_rate": _rate(len(false_alarms), checked_legit),
        "missed_scams": missed,
        "false_alarms": false_alarms,
    }


def _percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent / 100 * len(ordered)) - 1)]


def build_report(pairs, redteam_pairs, model):
    all_results = [res for _, res in pairs + redteam_pairs]
    completed = [res for res in all_results if res.status != CHECK_FAILED]
    cost = sum(res.cost_usd for res in all_results)
    return {
        "model": model,
        "overall": _detection(pairs),
        "real": _detection([p for p in pairs if p[0]["source"] != "synthetic"]),
        "synthetic": _detection([p for p in pairs if p[0]["source"] == "synthetic"]),
        "hard_negatives": _detection([p for p in pairs if p[0].get("hard_negative") is True]),
        "by_category": {
            category: _detection([p for p in pairs if p[0]["category"] == category])
            for category in sorted({rec["category"] for rec, _ in pairs})
        },
        "red_team": {
            "cases": len(redteam_pairs),
            "passed": sum(res.status == rec["expected"] for rec, res in redteam_pairs),
            "failed": [rec["id"] for rec, res in redteam_pairs if res.status != rec["expected"]],
        },
        "errors": sorted({res.error for res in all_results if res.error}),
        "cost_usd_total": round(cost, 6),
        "cost_usd_per_check": round(cost / len(all_results), 6) if all_results else None,
        "latency_ms_p95": _percentile([res.latency_ms for res in completed], 95),
        "knowledge": {
            "checks_with_patterns": sum(res.knowledge_used > 0 for res in all_results),
            "patterns_used": sum(res.knowledge_used for res in all_results),
            "failed_lookups": sum(res.knowledge_failed for res in all_results),
        },
    }


def summarise(report):
    overall, real, synthetic = report["overall"], report["real"], report["synthetic"]
    red_team = report["red_team"]
    return "\n".join(
        [
            f"Model: {report['model']}",
            f"Messages: {overall['messages']} ({overall['scams']} scam, {overall['legit']} legit)",
            f"Failed checks: {overall['failed_checks']} ({', '.join(overall['failed_ids']) or 'none'})",
            f"Recall: {overall['recall']} (real {real['recall']}, synthetic {synthetic['recall']})",
            f"False-positive rate: {overall['false_positive_rate']} "
            f"(hard negatives {report['hard_negatives']['false_positive_rate']})",
            f"Missed scams: {', '.join(overall['missed_scams']) or 'none'}",
            f"False alarms: {', '.join(overall['false_alarms']) or 'none'}",
            f"Red team: {red_team['passed']}/{red_team['cases']} passed",
            f"Errors: {', '.join(report['errors']) or 'none'}",
            f"Cost: ${report['cost_usd_total']} total, ${report['cost_usd_per_check']} per check",
            f"Latency p95: {report['latency_ms_p95']} ms",
            f"Knowledge: {report['knowledge']['checks_with_patterns']} checks used patterns, "
            f"{report['knowledge']['failed_lookups']} failed lookups",
            "Small, partly synthetic set: treat these as a smoke test, not a performance claim.",
        ]
    )


def _positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def _run(records, client, max_per_minute=None, knowledge=None):
    if max_per_minute is not None:
        results = []
        for record in records:
            started = time.monotonic()
            results.append(check_message(record["text"], client, knowledge))
            time.sleep(max(0, 60 / max_per_minute - (time.monotonic() - started)))
        return list(zip(records, results))
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda rec: check_message(rec["text"], client, knowledge), records))
    return list(zip(records, results))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="check only the first N dataset messages")
    parser.add_argument(
        "--max-per-minute", type=_positive_int, help="check one at a time, staying under a provider's rate limit"
    )
    parser.add_argument("--knowledge", action="store_true", help="give the checker known scam patterns")
    args = parser.parse_args(argv)

    client = client_from_env()
    if client is None:
        print("OPENROUTER_API_KEY is not set. Copy .env.example to .env and add a key.", file=sys.stderr)
        return 2

    knowledge = None
    if args.knowledge:
        knowledge = knowledge_from_env()
        if knowledge is None:
            print("SCAM_SHIELD_DATABASE_URL is not set.", file=sys.stderr)
            return 2

    records, errors = load_dataset(DATASET_DIR)
    if errors or not records:
        print(f"Dataset is invalid or empty: {len(errors)} problem(s)", file=sys.stderr)
        return 1

    redteam = [
        json.loads(line)
        for line in Path(REDTEAM_FILE).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    pairs = _run(records[: args.limit] if args.limit else records, client, args.max_per_minute, knowledge)
    redteam_pairs = _run(redteam, client, args.max_per_minute, knowledge)

    report = build_report(pairs, redteam_pairs, client.model)
    if knowledge is not None:
        report["knowledge"]["patterns_available"] = knowledge.variant_count()
    report["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = "-knowledge" if knowledge is not None else ""
    name = f"{report['created_at'].replace(':', '')}-{client.model.replace('/', '_')}{suffix}.json"
    path = Path(REPORT_DIR) / name
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(summarise(report))
    print(f"Report: evals/reports/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
