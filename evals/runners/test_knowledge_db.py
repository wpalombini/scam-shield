"""Database tests. They need SCAM_SHIELD_TEST_DATABASE_URL, a database they can wipe."""

import json
import os
import unittest

from scam_shield.ingest import Document, apply_holdout, extract_pending, prepare_database, prune_ato, store_documents
from scam_shield.knowledge import KnowledgeBase

TEST_URL = os.environ.get("SCAM_SHIELD_TEST_DATABASE_URL")
HELD_OUT = "https://www.scamwatch.gov.au/held-out"
OPEN = "https://www.scamwatch.gov.au/open"


def document(url, content="Alert text", source="scamwatch"):
    return Document(source, url, "Title", None, content)


def output(title):
    return json.dumps(
        {"variants": [{"title": title, "scam_type": "job", "summary": "Summary", "warning_signs": ["Sign"]}]}
    )


class FakeClient:
    def __init__(self, content):
        self.content = content
        self.calls = 0

    def complete(self, messages, response_format=None, max_tokens=None):
        self.calls += 1
        if isinstance(self.content, Exception):
            raise self.content
        return self.content, 0.001


@unittest.skipUnless(TEST_URL, "SCAM_SHIELD_TEST_DATABASE_URL is not set")
class IngestDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.knowledge = KnowledgeBase(TEST_URL)
        self.connection = self.knowledge._connect()
        self.addCleanup(self.connection.close)
        self.connection.execute("DROP TABLE IF EXISTS scam_variants, source_documents, sources CASCADE")
        prepare_database(self.connection)
        self.connection.commit()

    def titles(self):
        return [p["title"] for p in KnowledgeBase(TEST_URL).lookup("anything")]

    def ingest(self, documents, content, holdout=()):
        store_documents(self.connection, documents)
        apply_holdout(self.connection, holdout)
        self.connection.commit()
        client = FakeClient(content)
        result = extract_pending(self.connection, client)
        self.connection.commit()
        return result, client

    def test_held_out_alerts_are_never_extracted_or_returned(self):
        (added, _), client = self.ingest([document(HELD_OUT), document(OPEN)], output("Open"), [HELD_OUT])
        self.assertEqual(added, 1)
        self.assertEqual(client.calls, 1)
        self.assertEqual(self.titles(), ["Open"])

    def test_alert_held_out_after_leaving_the_feed_loses_its_patterns(self):
        self.ingest([document(OPEN)], output("Open"))
        self.assertEqual(self.titles(), ["Open"])
        self.ingest([], output("Unused"), [OPEN])
        self.assertEqual(self.titles(), [])

    def test_alert_released_from_holdout_is_extracted_again(self):
        self.ingest([document(OPEN)], output("Open"), [OPEN])
        self.assertEqual(self.titles(), [])
        self.ingest([], output("Open"))
        self.assertEqual(self.titles(), ["Open"])

    def test_unchanged_documents_are_not_extracted_again(self):
        self.ingest([document(OPEN)], output("Open"))
        _, client = self.ingest([document(OPEN)], output("New"))
        self.assertEqual(client.calls, 0)
        self.assertEqual(self.titles(), ["Open"])

    def test_changed_document_replaces_its_patterns(self):
        self.ingest([document(OPEN)], output("Old"))
        self.ingest([document(OPEN, "New text")], output("New"))
        self.assertEqual(self.titles(), ["New"])

    def test_failed_extraction_keeps_patterns_and_retries(self):
        self.ingest([document(OPEN)], output("Old"))
        (_, failures), _ = self.ingest([document(OPEN, "New text")], ValueError("bad"))
        self.assertEqual(failures, 1)
        self.assertEqual(self.titles(), ["Old"])
        self.ingest([], output("New"))
        self.assertEqual(self.titles(), ["New"])

    def test_empty_extraction_of_a_changed_page_keeps_patterns(self):
        self.ingest([document(OPEN)], output("Old"))
        (_, failures), _ = self.ingest([document(OPEN, "Maintenance page")], json.dumps({"variants": []}))
        self.assertEqual(failures, 1)
        self.assertEqual(self.titles(), ["Old"])

    def test_earlier_extractions_survive_a_crash_later_in_the_run(self):
        store_documents(self.connection, [document(OPEN), document(HELD_OUT)])
        self.connection.commit()

        class CrashOnSecond(FakeClient):
            def complete(self, messages, response_format=None, max_tokens=None):
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError("crash")
                return self.content, 0.001

        with self.assertRaises(RuntimeError):
            extract_pending(self.connection, CrashOnSecond(output("First")))
        self.connection.rollback()
        self.assertEqual(self.titles(), ["First"])

    def test_nul_characters_from_the_model_can_be_stored(self):
        (added, failures), _ = self.ingest([document(OPEN)], output("Bad\u0000title"))
        self.assertEqual((added, failures), (1, 0))

    def test_withdrawn_ato_alerts_are_removed_unless_the_page_looks_broken(self):
        urls = [f"https://www.ato.gov.au/{i}" for i in range(4)]
        self.ingest([document(url, source="ato") for url in urls], output("Alert"))
        self.assertEqual(prune_ato(self.connection, urls[:3]), 0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM source_documents").fetchone()[0], 3)
        self.assertEqual(prune_ato(self.connection, urls[:1]), 1)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM source_documents").fetchone()[0], 3)


if __name__ == "__main__":
    unittest.main()
