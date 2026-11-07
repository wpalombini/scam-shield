import json
import unittest

from scam_shield.checker import NO_RED_FLAGS, RED_FLAGS, SYSTEM_PROMPT, check_message
from scam_shield.ingest import (
    Document,
    eval_source_urls,
    html_to_text,
    parse_ato_alerts,
    parse_scamwatch_feed,
    parse_variants,
)

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
        urls = eval_source_urls("datasets")
        self.assertIn(
            "https://www.scamwatch.gov.au/about-us/news-and-alerts/scam-alert-food-delivery-scams", urls
        )
        self.assertEqual(len(urls), 4)

    def test_document_fields(self):
        self.assertEqual(Document("a", "u", "t", None, "c").source_id, "a")


if __name__ == "__main__":
    unittest.main()
