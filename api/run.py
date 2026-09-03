"""Vercel Python Function adapter for the QDS dashboard API."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import json
import pathlib
import os
import tempfile
import sys
import csv
import hmac
import io
from urllib.parse import parse_qs, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scenario_runner import run_scenario  # noqa: E402
from core.state_store import SQLiteStateStore  # noqa: E402

# Configure a durable path in the hosting environment when available. Vercel's
# default /tmp filesystem is intentionally ephemeral; use an external database
# adapter or mounted volume for replay protection across cold starts.
_default_state_db = str(pathlib.Path(tempfile.gettempdir()) / "qds_state.sqlite3")
_audit_key = os.environ.get("QDS_AUDIT_KEY")
STATE_STORE = SQLiteStateStore(
    os.environ.get("QDS_STATE_DB") or _default_state_db,
    audit_key=_audit_key.encode("utf-8") if _audit_key else None,
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _csv_report(events: list[dict]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["event_id", "timestamp", "attack", "decision", "reason", "mismatch_rate", "session_id", "signature_id", "payload_digest"])
    for event in events:
        writer.writerow([event.get(key, "") for key in ("event_id", "timestamp", "attack", "accepted", "reason", "mismatch_rate", "session_id", "signature_id", "payload_digest")])
    return output.getvalue().encode("utf-8")


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Vercel may use the configured Python entrypoint as the root handler.
        # Serve the static dashboard here as well as from dashboard.html so
        # GET / never falls through to BaseHTTPRequestHandler's 501 response.
        path, _, query = self.path.partition("?")
        params = parse_qs(query)
        # Vercel rewrites the public SOC endpoints to this one Python Function.
        resource = params.get("resource", [None])[0]
        if path == "/api/run" and resource:
            path = {
                "health": "/api/health", "audit": "/api/audit",
                "analytics": "/api/analytics", "report": "/api/reports/export",
            }.get(resource, path)
        if path in ("/", "/index.html", "/dashboard.html"):
            page = (ROOT / "dashboard.html").read_bytes()
            self._send(200, page, "text/html; charset=utf-8")
        elif path in ("/api/health", "/health"):
            self._send(200, _json_bytes({
                "status": "ok", "service": "QDS hardened-scenario API",
                "state_store": "persistent" if os.environ.get("QDS_STATE_DB") else "ephemeral-default",
                "audit": {**STATE_STORE.audit_summary(), **STATE_STORE.verify_audit_chain()},
                "admin_reset_enabled": bool(os.environ.get("QDS_ADMIN_TOKEN")),
            }), "application/json")
        elif path in ("/api/audit", "/audit"):
            try:
                limit = int(params.get("limit", ["50"])[0])
            except ValueError:
                self._send(400, _json_bytes({"error": "limit must be an integer"}), "application/json")
                return
            self._send(200, _json_bytes({"events": STATE_STORE.list_audit_events(limit),
                                         "integrity": STATE_STORE.verify_audit_chain()}), "application/json")
        elif path in ("/api/analytics", "/analytics"):
            self._send(200, _json_bytes(STATE_STORE.audit_summary()), "application/json")
        elif path in ("/api/reports/export", "/reports/export"):
            events = STATE_STORE.list_audit_events(200)
            if params.get("format", ["json"])[0].lower() == "csv":
                self._send(200, _csv_report(events), "text/csv; charset=utf-8")
            else:
                self._send(200, _json_bytes({"report_type": "QDS security audit report",
                                              "summary": STATE_STORE.audit_summary(),
                                              "integrity": STATE_STORE.verify_audit_chain(), "events": events}), "application/json")
        else:
            self._send(404, b"Not found", "text/plain")

    def do_OPTIONS(self):
        self._send(204, b"", "application/json")

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            resource = parse_qs(urlsplit(self.path).query).get("resource", [None])[0]
            if path == "/api/run" and resource == "admin-reset":
                path = "/api/admin/reset"
            if path in ("/api/admin/reset", "/admin/reset"):
                token = os.environ.get("QDS_ADMIN_TOKEN")
                supplied = self.headers.get("X-QDS-Admin-Token", "")
                if not token or not hmac.compare_digest(supplied, token):
                    self._send(403, _json_bytes({"error": "admin reset is disabled or unauthorized"}), "application/json")
                    return
                STATE_STORE.reset_audit_events()
                self._send(200, _json_bytes({"status": "audit events reset"}), "application/json")
                return
            if path not in ("/api/run", "/run", "/"):
                self._send(404, _json_bytes({"error": "Not found"}), "application/json")
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 65536:
                raise ValueError("request body must be between 1 and 65536 bytes")
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("request body must be a JSON object")
            result = run_scenario(state_store=STATE_STORE, audit_store=STATE_STORE, **data)
            self._send(200, json.dumps(result).encode("utf-8"), "application/json")
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self._send(400, json.dumps({"error": str(error)}).encode("utf-8"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        # The dashboard is served from this origin.  Cross-origin access is
        # opt-in and never uses a wildcard for a security-sensitive API.
        allowed_origin = os.environ.get("QDS_ALLOWED_ORIGIN")
        origin = self.headers.get("Origin")
        if allowed_origin and origin == allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
