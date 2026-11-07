"""Read known scam patterns from the private knowledge base.

The set is small, so every check gets all of it and the model decides what applies.
Keyword matching was tried first and couldn't tell related patterns from unrelated
ones. A pattern is reference material for the model and never decides a result.
"""

import os
import threading
import time

# A safety limit on prompt size and cost. Patterns beyond it need a real lookup.
MAX_PATTERNS = 50
CACHE_SECONDS = 300

_PATTERNS_SQL = """
    SELECT v.title, v.scam_type, v.summary, v.warning_signs
    FROM scam_variants v
    JOIN source_documents d ON d.id = v.document_id
    WHERE NOT d.eval_holdout
    ORDER BY v.first_seen DESC NULLS LAST, v.id
    LIMIT %(limit)s
"""


class KnowledgeBase:
    def __init__(self, database_url):
        self.database_url = database_url
        self._lock = threading.Lock()
        self._cached = None
        self._cached_at = 0.0

    def _connect(self):
        import psycopg

        return psycopg.connect(self.database_url, connect_timeout=5, options="-c statement_timeout=3000")

    def lookup(self, text):
        """Return the newest patterns as dictionaries. The message text isn't used or stored."""
        with self._lock:
            if self._cached is None or time.monotonic() - self._cached_at > CACHE_SECONDS:
                with self._connect() as connection:
                    rows = connection.execute(_PATTERNS_SQL, {"limit": MAX_PATTERNS}).fetchall()
                self._cached = [
                    {"title": title, "scam_type": scam_type, "summary": summary, "warning_signs": signs.splitlines()}
                    for title, scam_type, summary, signs in rows
                ]
                self._cached_at = time.monotonic()
            return self._cached

    def variant_count(self):
        with self._connect() as connection:
            return connection.execute("SELECT count(*) FROM scam_variants").fetchone()[0]


def knowledge_from_env():
    """Return a KnowledgeBase if a database is configured, otherwise None."""
    database_url = os.environ.get("SCAM_SHIELD_DATABASE_URL", "").strip()
    return KnowledgeBase(database_url) if database_url else None
