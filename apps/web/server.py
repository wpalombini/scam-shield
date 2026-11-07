"""Local web page for checking a message: python server.py [--host HOST] [--port PORT]

Listens on this machine only by default. Message text is never logged or stored.
"""

import argparse
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from scam_shield.checker import (
    CHANNELS,
    CHECK_FAILED,
    MAX_MESSAGE_CHARS,
    MAX_SENDER_CHARS,
    RESULT_TEXT,
    check_message,
    client_from_env,
)
from scam_shield.knowledge import knowledge_from_env

STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
ALLOWED_HOST = re.compile(r"(localhost|127\.0\.0\.1)(:[0-9]{1,5})?")
MAX_BODY_BYTES = 64 * 1024
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ScamShield"
    sys_version = ""
    timeout = 30

    def log_message(self, format, *args):
        """Turn off default request logging. _log records only what is safe to keep."""

    def _log(self, status, detail=""):
        route = self.path if self.path in STATIC_FILES or self.path == "/api/check" else "other"
        print(f"{self.command} {route} {status} {detail}".rstrip(), file=sys.stderr)

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, payload, detail=""):
        self._log(status, detail)
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _host_allowed(self):
        """Reject other hostnames, so a malicious website can't reach this server by DNS rebinding."""
        return ALLOWED_HOST.fullmatch(self.headers.get("Host", "")) is not None

    def do_GET(self):
        if not self._host_allowed():
            return self._send_json(403, {"error": "This page only works from this computer."})
        entry = STATIC_FILES.get(urlsplit(self.path).path)
        if entry is None:
            return self._send_json(404, {"error": "Not found."})
        name, content_type = entry
        self._log(200)
        self._send(200, (STATIC_DIR / name).read_bytes(), content_type)

    def do_POST(self):
        if not self._host_allowed():
            return self._send_json(403, {"error": "This page only works from this computer."})
        if urlsplit(self.path).path != "/api/check":
            return self._send_json(404, {"error": "Not found."})
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://{self.headers.get('Host')}":
            return self._send_json(403, {"error": "This page only works from this computer."})
        if self.headers.get_content_type() != "application/json":
            return self._send_json(415, {"error": "Send the message as JSON."})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send_json(411, {"error": "The request is missing its length."})
        if length < 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            return self._send_json(413, {"error": "That message is too long."})

        try:
            request = json.loads(self.rfile.read(length))
            message, channel, sender = request.get("message"), request.get("channel"), request.get("sender")
        except (ValueError, RecursionError, AttributeError):
            return self._send_json(400, {"error": "The request couldn't be read."})
        if not isinstance(message, str) or not message.strip():
            return self._send_json(400, {"error": "Paste a message to check."})
        if len(message) > MAX_MESSAGE_CHARS:
            return self._send_json(
                413,
                {"error": "That message is too long to check. Please paste a shorter part, including any links or phone numbers."},
            )
        channel = None if channel == "" else channel
        sender = None if sender == "" else sender
        if channel is not None and (not isinstance(channel, str) or channel not in CHANNELS):
            return self._send_json(400, {"error": "Choose how the message arrived from the list."})
        if sender is not None and (not isinstance(sender, str) or len(sender) > MAX_SENDER_CHARS):
            return self._send_json(400, {"error": "That sender is too long. Enter just the name, phone number or email address."})
        sender = sender.strip() or None if sender is not None else None
        client = self.server.client
        if client is None:
            return self._send_json(503, {"error": "The checker isn't set up yet. Add an API key to .env."})

        try:
            result = check_message(message, client, self.server.knowledge, channel, sender)
        except Exception as error:
            # A bug must still give the "couldn't check" wording. Only the type is logged.
            return self._send_json(
                200,
                {"status": CHECK_FAILED, "text": RESULT_TEXT[CHECK_FAILED], "reasons": []},
                f"status={CHECK_FAILED} error={type(error).__name__}",
            )
        self._send_json(
            200,
            {"status": result.status, "text": result.text, "reasons": result.reasons},
            f"status={result.status} error={result.error or 'none'} "
            f"latency_ms={result.latency_ms} cost_usd={result.cost_usd} patterns={result.knowledge_used} "
            f"lookup_failed={result.knowledge_failed} sender_given={sender is not None}",
        )


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Log only the error type. A full traceback could carry message text."""
        print(f"Request failed: {sys.exc_info()[0].__name__}", file=sys.stderr)


def make_server(client, host="127.0.0.1", port=8080, knowledge=None):
    server = Server((host, port), Handler)
    server.client = client
    server.knowledge = knowledge
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    client = client_from_env()
    if client is None:
        print("OPENROUTER_API_KEY is not set, so checks will be refused.", file=sys.stderr)
    knowledge = knowledge_from_env() if os.environ.get("SCAM_SHIELD_KNOWLEDGE") == "on" else None
    server = make_server(client, args.host, args.port, knowledge)
    print(f"Listening on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
