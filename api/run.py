"""Vercel Python Function adapter for the QDS dashboard API."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import json
import pathlib
import os
import tempfile
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scenario_runner import run_scenario  # noqa: E402
from core.state_store import SQLiteStateStore  # noqa: E402

# Configure a durable path in the hosting environment when available. Vercel's
# default /tmp filesystem is intentionally ephemeral; use an external database
# adapter or mounted volume for replay protection across cold starts.
_default_state_db = str(pathlib.Path(tempfile.gettempdir()) / "qds_state.sqlite3")
STATE_STORE = SQLiteStateStore(os.environ.get("QDS_STATE_DB") or _default_state_db)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Vercel may use the configured Python entrypoint as the root handler.
        # Serve the static dashboard here as well as from dashboard.html so
        # GET / never falls through to BaseHTTPRequestHandler's 501 response.
        if self.path in ("/", "/index.html", "/dashboard.html"):
            page = (ROOT / "dashboard.html").read_bytes()
            self._send(200, page, "text/html; charset=utf-8")
        else:
            self._send(404, b"Not found", "text/plain")

    def do_OPTIONS(self):
        self._send(204, b"", "application/json")

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(size))
            result = run_scenario(state_store=STATE_STORE, **data)
            self._send(200, json.dumps(result).encode("utf-8"), "application/json")
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self._send(400, json.dumps({"error": str(error)}).encode("utf-8"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
