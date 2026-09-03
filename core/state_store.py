"""Small durable replay/authorization store used by the verifier.

The protocol remains usable without a database (the verifier falls back to
process-local sets), but deployments can inject this store so replay state is
not lost whenever a worker is restarted.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3
import time


class SQLiteStateStore:
    """Atomic one-time-use state backed by SQLite."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
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
