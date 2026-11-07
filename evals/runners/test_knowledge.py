import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from run_checker_evals import _run_poisoned_patterns
from scam_shield.checker import NO_RED_FLAGS, RED_FLAGS, SYSTEM_PROMPT, check_message
from scam_shield.ingest import (
    MAX_SUMMARY_CHARS,
    MAX_TITLE_CHARS,
    MAX_VARIANTS_PER_DOCUMENT,
    MAX_WARNING_SIGNS,
    _CheckedRedirects,
    eval_source_urls,
    fetch,
    html_to_text,
    normalise_url,
    parse_ato_alerts,
    parse_scamwatch_feed,
    parse_variants,
)
from scam_shield.knowledge import CACHE_SECONDS, KnowledgeBase

PATTERN = {
    "title": "Fake toll notice",
    "scam_type": "delivery_toll",
    "summary": "Demands a small unpaid toll.",
    "warning_signs": ["Small fee"],
}


class FakeClient:
    model = "fake/model"

    def __init__(self, status=NO_RED_FLAGS):
        self.status = status
        self.messages = None

    def complete(self, messages):
        self.messages = messages
        return json.dumps({"status": self.status, "reasons": []}), 0.001


class FakeKnowledge:
    def __init__(self, patterns=(), error=None):
        self.patterns = list(patterns)
        self.error = error

    def lookup(self, text):
        if self.error:
            raise self.error
        return self.patterns


class FlakyKnowledgeBase(KnowledgeBase):
    def __init__(self):
        super().__init__("unused")
        self.connects = 0
        self.down = False

    def _connect(self):
        self.connects += 1
        if self.down:
            raise OSError("down")
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchall.return_value = [("T", "job", "S", "a\nb")]
        return connection


class LookupCacheTests(unittest.TestCase):
    def test_patterns_are_cached(self):
        knowledge = FlakyKnowledgeBase()
        self.assertEqual(knowledge.lookup("a"), knowledge.lookup("b"))
        self.assertEqual(knowledge.connects, 1)
        self.assertEqual(knowledge.lookup("a")[0]["warning_signs"], ["a", "b"])

    def test_outage_serves_stale_patterns_and_backs_off(self):
        knowledge = FlakyKnowledgeBase()
        first = knowledge.lookup("a")
        knowledge._cached_at -= CACHE_SECONDS + 1
        knowledge.down = True
        self.assertEqual(knowledge.lookup("a"), first)
        self.assertEqual(knowledge.lookup("a"), first)
        self.assertEqual(knowledge.connects, 2)

    def test_outage_with_nothing_cached_fails_and_backs_off(self):
        knowledge = FlakyKnowledgeBase()
        knowledge.down = True
        for _ in range(2):
            with self.assertRaises(OSError):
                knowledge.lookup("a")
        self.assertEqual(knowledge.connects, 1)


class PoisonedPatternTests(unittest.TestCase):
    def test_case_fails_if_the_pattern_never_reached_the_model(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.jsonl"
            path.write_text(json.dumps({"id": "pp", "text": "Pay", "expected": RED_FLAGS, "pattern": PATTERN}))
            with mock.patch("run_checker_evals.POISONED_PATTERNS_FILE", str(path)):
                down = _run_poisoned_patterns(FakeClient(RED_FLAGS), FakeKnowledge(error=OSError("down")))
                working = _run_poisoned_patterns(FakeClient(RED_FLAGS), FakeKnowledge())
        self.assertEqual(down["failed"], ["pp"])
        self.assertEqual(working["passed"], 1)
        self.assertEqual(working["cost_usd"], 0.001)


class CheckWithKnowledgeTests(unittest.TestCase):
    def test_patterns_go_in_the_user_turn_as_data(self):
        client = FakeClient()
        result = check_message("Pay the toll", client, FakeKnowledge([PATTERN]))
        self.assertEqual(json.loads(client.messages[1]["content"])["known_scam_patterns"], [PATTERN])
        self.assertEqual(result.knowledge_used, 1)

    def test_no_knowledge_keeps_the_original_request(self):
        client = FakeClient()
        result = check_message("Pay the toll", client)
        self.assertEqual(json.loads(client.messages[1]["content"]), {"message": "Pay the toll"})
        self.assertEqual(client.messages[0]["content"], SYSTEM_PROMPT)
        self.assertEqual(result.knowledge_used, 0)

    def test_no_matching_pattern_keeps_the_original_request(self):
        client = FakeClient()
        check_message("Pay the toll", client, FakeKnowledge())
        self.assertEqual(json.loads(client.messages[1]["content"]), {"message": "Pay the toll"})
        self.assertEqual(client.messages[0]["content"], SYSTEM_PROMPT)

    def test_lookup_failure_still_checks_and_is_recorded(self):
        client = FakeClient(RED_FLAGS)
        result = check_message("Pay the toll", client, FakeKnowledge(error=OSError("down")))
        self.assertEqual(result.status, RED_FLAGS)
        self.assertTrue(result.knowledge_failed)


class ParsingTests(unittest.TestCase):
    def test_html_to_text_keeps_only_main_content(self):
        page = "<nav>Menu</nav><main><script>bad()</script><h1>Alert</h1><p>Fish &amp; chips</p></main><footer>F</footer>"
        self.assertEqual(html_to_text(page), "Alert Fish & chips")

    def test_scamwatch_feed(self):
        feed = """<rss><channel><title>Feed</title><item><title> Scam alert </title>
        <link>https://www.scamwatch.gov.au/a</link><pubDate>Mon, 02 Nov 2026 23:00:00 +0000</pubDate></item>
        <item><title>No link</title></item></channel></rss>"""
        items = parse_scamwatch_feed(feed)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][0], "Scam alert")
        self.assertEqual(items[0][2].isoformat(), "2026-11-02")

    def test_ato_page_uses_the_alert_text_not_the_list_of_alerts(self):
        body = "This scam email claims to be from the ATO and asks you to sign in through a link to a fake page."
        page = (
            "<main>Scam alerts July 2026 – ATO appointment email scam February 2026 – Crypto email scam "
            f"July 2026 – ATO appointment email scam We have reports. {body} "
            f"February 2026 – Crypto email scam The email asks for crypto details. {body}</main>"
        )
        documents = parse_ato_alerts(page)
        self.assertEqual([d.title for d in documents], ["July 2026: ATO appointment email scam", "February 2026: Crypto email scam"])
        self.assertIn("We have reports", documents[0].content)
        self.assertNotIn("Crypto email scam", documents[0].content)
        self.assertEqual(documents[0].published_on.isoformat(), "2026-07-01")
        self.assertIn("#July2026ATOappointmentemailscam", documents[0].url)

    def test_variants_are_validated(self):
        content = json.dumps(
            {
                "variants": [
                    {"title": " Toll ", "scam_type": "delivery_toll", "summary": "S", "warning_signs": ["a\nb", " "]},
                    {"title": "Bad", "scam_type": "made_up", "summary": "S", "warning_signs": []},
                ]
            }
        )
        self.assertEqual(parse_variants(content), [("Toll", "delivery_toll", "S", "a b")])

    def test_unusable_variants_raise(self):
        with self.assertRaises(ValueError):
            parse_variants("not json")
        with self.assertRaises(ValueError):
            parse_variants('{"variants": "none"}')


class HoldoutTests(unittest.TestCase):
    def test_eval_alerts_are_held_out(self):
        self.assertIn(
            "https://www.scamwatch.gov.au/about-us/news-and-alerts/scam-alert-food-delivery-scams",
            eval_source_urls("datasets"),
        )

    def test_missing_dataset_refuses_instead_of_holding_out_nothing(self):
        with self.assertRaises(ValueError):
            eval_source_urls("no-such-directory")

    def test_url_differences_can_not_defeat_the_holdout(self):
        self.assertEqual(normalise_url("HTTPS://WWW.Scamwatch.gov.au/a/"), "https://www.scamwatch.gov.au/a")


class FetcherTests(unittest.TestCase):
    def test_only_https_source_sites_are_allowed(self):
        for url in (
            "file:///proc/self/environ",
            "http://www.ato.gov.au/a",
            "https://bad.example/a",
            "https://www.ato.gov.au.bad.example/a",
            "http://db:5432/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch(url)

    def test_redirects_off_site_are_refused(self):
        with self.assertRaises(ValueError):
            _CheckedRedirects().redirect_request(None, None, 302, "", {}, "https://bad.example/a")

    def test_pages_without_main_content_are_rejected(self):
        with self.assertRaises(ValueError):
            html_to_text("<html>Service unavailable</html>", require_main=True)


class VariantLimitTests(unittest.TestCase):
    def test_fields_are_capped_and_contact_details_removed(self):
        variant = {
            "title": "T" * 500,
            "scam_type": "job",
            "summary": "Call 0491 570 156 or visit https://bad.example " + "s" * 2000,
            "warning_signs": ["sign"] * 20,
        }
        rows = parse_variants(json.dumps({"variants": [variant] * 20}))
        self.assertEqual(len(rows), MAX_VARIANTS_PER_DOCUMENT)
        title, _, summary, signs = rows[0]
        self.assertEqual(len(title), MAX_TITLE_CHARS)
        self.assertLessEqual(len(summary), MAX_SUMMARY_CHARS)
        self.assertNotIn("0491", summary)
        self.assertNotIn("bad.example", summary)
        self.assertEqual(len(signs.splitlines()), MAX_WARNING_SIGNS)


class FailedCheckFieldsTests(unittest.TestCase):
    def test_failed_checks_keep_the_knowledge_fields(self):
        class BadClient:
            model = "fake"

            def complete(self, messages):
                return "not json", 0.001

        result = check_message("Hello", BadClient(), FakeKnowledge([PATTERN]))
        self.assertEqual(result.status, "check_failed")
        self.assertEqual(result.knowledge_used, 1)


if __name__ == "__main__":
    unittest.main()
