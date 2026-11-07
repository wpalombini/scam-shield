"""Check one message: python -m scam_shield "message text" (or pipe it in)."""

import os
import sys

from scam_shield.checker import check_message, client_from_env
from scam_shield.knowledge import knowledge_from_env


def main(argv):
    text = " ".join(argv[1:]) if len(argv) > 1 else sys.stdin.read()
    client = client_from_env()
    if client is None:
        print("OPENROUTER_API_KEY is not set. Copy .env.example to .env and add a key.", file=sys.stderr)
        return 2

    knowledge = knowledge_from_env() if os.environ.get("SCAM_SHIELD_KNOWLEDGE") == "on" else None
    result = check_message(text, client, knowledge)
    print(result.text)
    for reason in result.reasons:
        print(f"- {reason}")
    if result.error:
        print(f"Error code: {result.error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
