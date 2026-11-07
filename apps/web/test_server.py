import contextlib
import http.client
import io
import json
import threading
import unittest

from scam_shield.checker import CHECK_FAILED, MAX_MESSAGE_CHARS, NO_RED_FLAGS, RED_FLAGS, RESULT_TEXT, ModelError
from server import MAX_BODY_BYTES, make_server


class FakeClient:
    model = "fake/model"

    def __init__(self, content=None, error=None):
        self.content = content
        self.error = error
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        if self.error:
            raise self.error
        return self.content, 0.001


def output(status, reasons=()):
    return json.dumps({"status": status, "reasons": list(reasons)})


class ServerTestCase(unittest.TestCase):
    def start(self, client):
        self.client = client
        self.server = make_server(client, port=0)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.logs = io.StringIO()
        redirect = contextlib.redirect_stderr(self.logs)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        self.addCleanup(connection.close)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response, response.read()

    def check(self, message, headers=None):
        all_headers = {"Content-Type": "application/json", **(headers or {})}
        response, body = self.request("POST", "/api/check", json.dumps({"message": message}), all_headers)
        return response.status, json.loads(body)


class StaticFileTests(ServerTestCase):
    def setUp(self):
        self.start(FakeClient(output(NO_RED_FLAGS)))

    def test_serves_the_page_with_security_headers(self):
        response, body = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Is this a scam?", body)
        self.assertIn("script-src 'self'", response.getheader("Content-Security-Policy"))
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")

    def test_only_listed_files_are_served(self):
        for path in ("/server.py", "/static/../server.py", "/.env", "/../.env"):
            with self.subTest(path=path):
                response, _ = self.request("GET", path)
                self.assertEqual(response.status, 404)

    def test_text_box_does_not_silently_cut_long_pastes(self):
        _, body = self.request("GET", "/")
        self.assertNotIn(b"maxlength", body)

    def test_page_never_says_safe(self):
        for path in ("/", "/app.js"):
            _, body = self.request("GET", path)
            self.assertNotIn(b"safe", body.lower())


class CheckTests(ServerTestCase):
    def test_returns_fixed_wording_and_reasons(self):
        self.start(FakeClient(output(RED_FLAGS, ["Creates urgency"])))
        status, body = self.check("Pay now")
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"status": RED_FLAGS, "text": RESULT_TEXT[RED_FLAGS], "reasons": ["Creates urgency"]}
        )

    def test_model_failure_is_never_no_red_flags(self):
        self.start(FakeClient(error=ModelError("network")))
        status, body = self.check("Pay now")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], CHECK_FAILED)
        self.assertEqual(body["text"], RESULT_TEXT[CHECK_FAILED])

    def test_unexpected_error_gives_the_check_failed_wording(self):
        self.start(FakeClient(error=RuntimeError("SECRET")))
        status, body = self.check("Pay now")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], CHECK_FAILED)
        self.assertIn("error=RuntimeError", self.logs.getvalue())
        self.assertNotIn("SECRET", self.logs.getvalue())

    def test_response_has_no_internal_details(self):
        self.start(FakeClient(output(NO_RED_FLAGS)))
        _, body = self.check("Hello")
        self.assertEqual(set(body), {"status", "text", "reasons"})

    def test_missing_api_key_is_a_clear_error(self):
        self.start(None)
        status, body = self.check("Hello")
        self.assertEqual(status, 503)
        self.assertNotIn("status", body)

    def test_sender_details_reach_the_model_as_data(self):
        self.start(FakeClient(output(RED_FLAGS)))
        captured = []
        original = self.client.complete
        self.client.complete = lambda messages: captured.append(messages) or original(messages)
        response, _ = self.request(
            "POST",
            "/api/check",
            json.dumps({"message": "Pay", "channel": "sms", "sender": "0491 570 156"}),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(
            json.loads(captured[0][1]["content"]), {"message": "Pay", "received_via": "sms", "sender": "0491 570 156"}
        )

    def test_blank_sender_fields_keep_the_plain_request(self):
        self.start(FakeClient(output(NO_RED_FLAGS)))
        response, _ = self.request(
            "POST", "/api/check", json.dumps({"message": "Hi", "channel": "", "sender": ""}), {"Content-Type": "application/json"}
        )
        self.assertEqual(response.status, 200)

    def test_invalid_sender_fields_are_refused(self):
        self.start(FakeClient(output(RED_FLAGS)))
        for extra in ({"channel": "pigeon"}, {"channel": 5}, {"sender": "x" * 255}, {"sender": ["0491"]}):
            with self.subTest(extra=extra):
                response, _ = self.request(
                    "POST", "/api/check", json.dumps({"message": "Hi", **extra}), {"Content-Type": "application/json"}
                )
                self.assertEqual(response.status, 400)
        self.assertEqual(self.client.calls, 0)

    def test_message_text_is_never_logged(self):
        self.start(FakeClient(output(RED_FLAGS, ["Creates urgency"])))
        self.check("SECRET MESSAGE TEXT")
        self.request(
            "POST", "/api/check", json.dumps({"message": "Hi", "sender": "SECRET-SENDER"}), {"Content-Type": "application/json"}
        )
        self.request("GET", "/?q=SECRET-IN-URL")
        self.request("POST", "/SECRET-PATH", b"{}", {"Content-Type": "application/json"})
        self.request("POST", "/api/check", b"SECRET not json", {"Content-Type": "application/json"})
        self.request("POST", "/api/check", b"[" * 60000, {"Content-Type": "application/json"})
        logs = self.logs.getvalue()
        self.assertIn("status=red_flags", logs)
        self.assertNotIn("SECRET", logs)
        self.assertNotIn("urgency", logs)


class RejectedRequestTests(ServerTestCase):
    def setUp(self):
        self.start(FakeClient(output(RED_FLAGS)))

    def assert_rejected(self, status, expected):
        self.assertEqual(status, expected)
        self.assertEqual(self.client.calls, 0)

    def test_invalid_messages(self):
        for message in ("", "   ", 123, None, ["list"], "x" * (MAX_MESSAGE_CHARS + 1)):
            with self.subTest(message=str(message)[:20]):
                status, _ = self.check(message)
                self.assertIn(status, (400, 413))
                self.assertEqual(self.client.calls, 0)

    def test_invalid_json(self):
        for body in (b"not json", b"[]", b"\xff", b"[" * 60000, b"[" + b"1" * 5000 + b"]"):
            with self.subTest(body=body):
                response, _ = self.request("POST", "/api/check", body, {"Content-Type": "application/json"})
                self.assert_rejected(response.status, 400)
        self.assertNotIn("Traceback", self.logs.getvalue())

    def test_wrong_content_type(self):
        response, _ = self.request(
            "POST", "/api/check", json.dumps({"message": "Hi"}), {"Content-Type": "text/plain"}
        )
        self.assert_rejected(response.status, 415)

    def test_other_origins_are_refused(self):
        for origin in (
            "https://bad.example",
            "null",
            "localhost",
            "http://localhost:9999",
            "https://localhost:8080",
            "ftp://localhost:8080",
            "http://bad.example@localhost:8080",
        ):
            with self.subTest(origin=origin):
                status, _ = self.check("Hi", {"Origin": origin, "Host": "localhost:8080"})
                self.assert_rejected(status, 403)

    def test_other_hosts_are_refused(self):
        for host in (
            "bad.example",
            "bad.example@localhost",
            "localhost/.bad.example",
            "localhost:bad",
            "localhost.bad.example",
            "[::1]",
            "[",
        ):
            with self.subTest(host=host):
                status, _ = self.check("Hi", {"Host": host})
                self.assert_rejected(status, 403)
        response, _ = self.request("GET", "/", headers={"Host": "bad.example"})
        self.assertEqual(response.status, 403)

    def test_missing_host_is_refused(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        self.addCleanup(connection.close)
        connection.putrequest("GET", "/", skip_host=True)
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 403)

    def test_own_origin_is_allowed(self):
        status, _ = self.check("Hi", {"Origin": "http://localhost:8080", "Host": "localhost:8080"})
        self.assertEqual(status, 200)

    def test_oversized_body_is_refused_without_reading_it(self):
        response, _ = self.request(
            "POST",
            "/api/check",
            b"x" * 10,
            {"Content-Type": "application/json", "Content-Length": str(MAX_BODY_BYTES + 1)},
        )
        self.assert_rejected(response.status, 413)

    def test_unknown_post_path(self):
        response, _ = self.request("POST", "/api/other", b"{}", {"Content-Type": "application/json"})
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
