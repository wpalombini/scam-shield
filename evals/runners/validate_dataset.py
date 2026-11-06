"""Validate the labelled eval dataset and report progress towards the Phase 0 target.

Usage: validate_dataset.py <directory containing .jsonl files>
Exits 1 if any record is invalid or no records are found.
"""

import json
import sys
from collections import Counter
from pathlib import Path

TARGET_MESSAGES = 200

CATEGORIES = {
    "scam": {
        "bank_impersonation",
        "delivery_toll",
        "fake_notification",
        "government_impersonation",
        "hi_mum",
        "investment",
        "job",
        "remote_access",
        "romance",
        "other_scam",
    },
    "legit": {
        "appointment",
        "bank_notice",
        "delivery_notice",
        "family",
        "government_notice",
        "marketing",
        "other_legit",
    },
}
CHANNELS = {"sms", "email", "call_description", "voicemail_transcript", "social"}
SOURCES = {"synthetic", "public_alert", "public_dataset"}
REQUIRED_TEXT_FIELDS = ("id", "text", "category", "language", "licence")


def is_one_of(value, allowed):
    """Membership check that treats JSON lists and objects as invalid, not as a crash."""
    return isinstance(value, str) and value in allowed


def validate_record(record):
    """Return a list of problems with one dataset record."""
    if not isinstance(record, dict):
        return ["record is not a JSON object"]

    errors = []
    for field in REQUIRED_TEXT_FIELDS:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be a non-empty string")

    label = record.get("label")
    if not is_one_of(label, CATEGORIES):
        errors.append(f"label must be one of {sorted(CATEGORIES)}")
    elif not is_one_of(record.get("category"), CATEGORIES[label]):
        errors.append(f"category must be one of {sorted(CATEGORIES[label])}")

    if not is_one_of(record.get("channel"), CHANNELS):
        errors.append(f"channel must be one of {sorted(CHANNELS)}")

    source = record.get("source")
    if not is_one_of(source, SOURCES):
        errors.append(f"source must be one of {sorted(SOURCES)}")
    elif source != "synthetic" and not record.get("source_url"):
        errors.append("source_url is required for non-synthetic records")

    hard_negative = record.get("hard_negative")
    if not isinstance(hard_negative, bool):
        errors.append("hard_negative must be true or false")
    elif hard_negative and label != "legit":
        errors.append("hard_negative can only be true for legit records")

    return errors


def load_dataset(directory):
    """Return (records, errors) for every .jsonl file in a directory."""
    records, errors, seen_ids = [], [], set()

    for path in sorted(Path(directory).glob("*.jsonl")):
        with path.open(encoding="utf-8") as lines:
            for number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                where = f"{path.name}:{number}"
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    errors.append(f"{where}: invalid JSON ({error.msg})")
                    continue

                errors.extend(f"{where}: {e}" for e in validate_record(record))

                if isinstance(record, dict):
                    record_id = record.get("id")
                    if isinstance(record_id, str):
                        if record_id in seen_ids:
                            errors.append(f"{where}: duplicate id {record_id}")
                        seen_ids.add(record_id)
                    records.append(record)

    return records, errors


def summarise(records):
    """Return a printable progress summary."""
    lines = [f"Messages: {len(records)}/{TARGET_MESSAGES}"]
    for field in ("label", "category", "channel", "source", "language"):
        counts = Counter(str(record.get(field)) for record in records)
        joined = ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
        lines.append(f"  {field}: {joined}")
    hard_negatives = sum(record.get("hard_negative") is True for record in records)
    lines.append(f"  hard_negative: {hard_negatives}")
    return "\n".join(lines)


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    records, errors = load_dataset(argv[1])
    if not records and not errors:
        errors.append(f"no records found in {argv[1]}")

    if errors:
        print(f"INVALID: {len(errors)} problem(s)", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    print("VALID")
    print(summarise(records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
