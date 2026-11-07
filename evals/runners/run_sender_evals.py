"""Score how sender details change results: run_sender_evals.py [--knowledge]

Each pair has the same text from a plausible and a suspicious sender. Spoof cases are
clear scams from senders that look right, which a sender must never clear. Reports hold
ids and numbers only. Each run costs money.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from run_checker_evals import REPORT_DIR
from scam_shield.checker import CHECK_FAILED, RED_FLAGS, check_message, client_from_env
from scam_shield.knowledge import knowledge_from_env

CASES_FILE = "sender/pairs.jsonl"


def build_sender_report(cases, with_sender, text_only, model):
    """Summarise results, given dictionaries of case id to CheckResult."""
    by_group = lambda group: [case for case in cases if case["group"] == group]
    wrong = [case["id"] for case in cases if with_sender[case["id"]].status != case["expected"]]
    pairs = by_group("pair")
    plausible = [case for case in pairs if case["expected"] != RED_FLAGS]
    suspicious = [case for case in pairs if case["expected"] == RED_FLAGS]
    flagged = lambda items, results: sum(results[case["id"]].status == RED_FLAGS for case in items)
    results = list(with_sender.values()) + list(text_only.values())
    return {
        "model": model,
        "with_sender": {
            "suspicious_flagged": flagged(suspicious, with_sender),
            "suspicious_total": len(suspicious),
            "plausible_flagged": flagged(plausible, with_sender),
            "plausible_total": len(plausible),
            "pairs_both_correct": sum(
                f"{pair['pair']}-plausible" not in wrong and f"{pair['pair']}-suspicious" not in wrong
                for pair in plausible
            ),
            "spoofs_flagged": flagged(by_group("spoof"), with_sender),
            "spoofs_total": len(by_group("spoof")),
            "injections_flagged": flagged(by_group("injection"), with_sender),
            "injections_total": len(by_group("injection")),
            "wrong": wrong,
        },
        "text_only": {
            "pair_texts_flagged": flagged(plausible, text_only),
            "pair_texts_total": len(plausible),
            "spoofs_flagged": flagged(by_group("spoof"), text_only),
        },
        "failed_checks": sum(result.status == CHECK_FAILED for result in results),
        "errors": sorted({result.error for result in results if result.error}),
        "cost_usd_total": round(sum(result.cost_usd for result in results), 6),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge", action="store_true", help="give the checker known scam patterns")
    args = parser.parse_args(argv)

    client = client_from_env()
    if client is None:
        print("OPENROUTER_API_KEY is not set.", file=sys.stderr)
        return 2
    knowledge = knowledge_from_env() if args.knowledge else None
    if args.knowledge and knowledge is None:
        print("SCAM_SHIELD_DATABASE_URL is not set.", file=sys.stderr)
        return 2

    cases = [json.loads(line) for line in Path(CASES_FILE).read_text(encoding="utf-8").splitlines() if line.strip()]
    with_sender, text_only = {}, {}
    for case in cases:
        with_sender[case["id"]] = check_message(case["text"], client, knowledge, case["channel"], case["sender"])
        # The two sides of a pair share their text, so text alone needs one check per pair.
        if case["group"] != "pair" or case["expected"] != RED_FLAGS:
            text_only[case["id"]] = check_message(case["text"], client, knowledge)

    report = build_sender_report(cases, with_sender, text_only, client.model)
    report["knowledge"] = knowledge is not None
    report["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = "-knowledge" if knowledge is not None else ""
    name = f"{report['created_at'].replace(':', '')}-{client.model.replace('/', '_')}-sender{suffix}.json"
    (Path(REPORT_DIR) / name).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("with_sender", "text_only", "failed_checks", "errors", "cost_usd_total")}, indent=2))
    print(f"Report: evals/reports/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
