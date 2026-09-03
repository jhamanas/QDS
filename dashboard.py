"""Launch the local dashboard: ``python dashboard.py``."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import webbrowser
from pathlib import Path

from core.state_store import SQLiteStateStore
from scenario_runner import run_scenario

ROOT = Path(__file__).resolve().parent
STORE = SQLiteStateStore(ROOT / "results" / "qds_dashboard.sqlite3")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send(200, (ROOT / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self.send(404, b"Not found", "text/plain")

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 65536:
                raise ValueError("request body must be between 1 and 65536 bytes")
            payload = json.loads(self.rfile.read(size))
            result = run_scenario(state_store=STORE, audit_store=STORE, **payload)
            self.send(200, json.dumps(result).encode(), "application/json")
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send(400, json.dumps({"error": str(error)}).encode(), "application/json")

    def send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    url = f"http://127.0.0.1:{args.port}"
    print(f"QDS dashboard: {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
