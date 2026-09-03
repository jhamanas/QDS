"""Small durable replay/authorization store used by the verifier.

The protocol remains usable without a database (the verifier falls back to
process-local sets), but deployments can inject this store so replay state is
not lost whenever a worker is restarted.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from typing import Any


class SQLiteStateStore:
    """Atomic one-time-use state backed by SQLite."""

    def __init__(self, path: str | Path, audit_key: bytes | None = None):
        self.path = Path(path)
        # A configured key upgrades the audit chain from tamper-evident to an
        # HMAC-authenticated chain.  Do not put a production key in source.
        self._audit_key = audit_key
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialise(self) -> None:
        db = self._connect()
        try:
            db.execute("CREATE TABLE IF NOT EXISTS consumed_signatures (id TEXT PRIMARY KEY, consumed_at REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS consumed_authorizations (id TEXT PRIMARY KEY, consumed_at REAL NOT NULL)")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )""")
            db.commit()
        finally:
            db.close()

    @property
    def audit_integrity_mode(self) -> str:
        return "hmac-sha256" if self._audit_key else "sha256-chain"

    def record_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append a canonical, hash-chained audit event atomically.

        The caller must supply a redacted event: payload content and secret key
        material are deliberately never stored here.
        """
        item = dict(event)
        item.setdefault("event_id", uuid.uuid4().hex)
        item.setdefault("timestamp", time.time())
        encoded = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT event_hash FROM audit_events ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
            previous_hash = row[0] if row else "GENESIS"
            material = f"{previous_hash}:{encoded}".encode("utf-8")
            digest = (hmac.new(self._audit_key, material, hashlib.sha256).hexdigest()
                      if self._audit_key else hashlib.sha256(material).hexdigest())
            db.execute(
                "INSERT INTO audit_events(event_id, created_at, event_json, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?)",
                (item["event_id"], float(item["timestamp"]), encoded, previous_hash, digest),
            )
            db.commit()
            return {**item, "previous_hash": previous_hash, "event_hash": digest}
        finally:
            db.close()

    def list_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT event_json, previous_hash, event_hash FROM audit_events ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [{**json.loads(row[0]), "previous_hash": row[1], "event_hash": row[2]} for row in rows]
        finally:
            db.close()

    def audit_summary(self) -> dict[str, Any]:
        db = self._connect()
        try:
            rows = db.execute("SELECT event_json FROM audit_events ORDER BY created_at ASC, rowid ASC").fetchall()
        finally:
            db.close()
        events = [json.loads(row[0]) for row in rows]
        accepted = sum(1 for event in events if event.get("accepted"))
        rejected = len(events) - accepted
        attacks = sum(1 for event in events if event.get("attack") != "honest")
        rates = [event["mismatch_rate"] for event in events if isinstance(event.get("mismatch_rate"), (int, float))]
        return {
            "total_events": len(events), "accepted": accepted, "rejected": rejected,
            "attack_scenarios": attacks,
            "average_mismatch_rate": round(sum(rates) / len(rates), 6) if rates else 0.0,
            "audit_integrity_mode": self.audit_integrity_mode,
        }

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify linkage and (when keyed) HMAC values of all stored events."""
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT event_json, previous_hash, event_hash FROM audit_events ORDER BY created_at ASC, rowid ASC"
            ).fetchall()
        finally:
            db.close()
        expected_previous = "GENESIS"
        for index, (encoded, previous_hash, event_hash) in enumerate(rows):
            material = f"{previous_hash}:{encoded}".encode("utf-8")
            expected_hash = (hmac.new(self._audit_key, material, hashlib.sha256).hexdigest()
                             if self._audit_key else hashlib.sha256(material).hexdigest())
            if previous_hash != expected_previous or not hmac.compare_digest(event_hash, expected_hash):
                return {"valid": False, "checked_events": len(rows), "failed_index": index,
                        "integrity_mode": self.audit_integrity_mode}
            expected_previous = event_hash
        return {"valid": True, "checked_events": len(rows), "integrity_mode": self.audit_integrity_mode}

    def reset_audit_events(self) -> None:
        db = self._connect()
        try:
            db.execute("DELETE FROM audit_events")
            db.commit()
        finally:
            db.close()

    def consume_signature(self, identifier: str) -> bool:
        return self._consume("consumed_signatures", identifier)

    def consume_authorization(self, identifier: str) -> bool:
        return self._consume("consumed_authorizations", identifier)

    def _consume(self, table: str, identifier: str) -> bool:
        db = self._connect()
        try:
            cursor = db.execute(
                f"INSERT OR IGNORE INTO {table}(id, consumed_at) VALUES (?, ?)",
                (identifier, time.time()),
            )
            db.commit()
            return cursor.rowcount == 1
        finally:
            db.close()
