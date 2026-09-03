"""Regression checks for the persistent SOC/audit layer."""
from pathlib import Path
import hashlib
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.state_store import SQLiteStateStore
from scenario_runner import run_scenario


def run():
    with tempfile.TemporaryDirectory() as folder:
        store = SQLiteStateStore(Path(folder) / "soc.sqlite3", audit_key=b"test-audit-key")
        result = run_scenario(
            attack="honest", length=8, noise=0, threshold=0, payload="private-payment:42",
            state_store=store, audit_store=store,
        )
        assert result["accepted"]
        assert result["audit_event"]["event_hash"]
        events = store.list_audit_events()
        assert len(events) == 1
        assert "private-payment:42" not in str(events)
        assert events[0]["payload_digest"] == hashlib.sha256(b"private-payment:42").hexdigest()
        assert store.verify_audit_chain()["valid"]
        summary = store.audit_summary()
        assert summary["accepted"] == 1
        assert summary["audit_integrity_mode"] == "hmac-sha256"
        store.reset_audit_events()
        assert store.audit_summary()["total_events"] == 0


if __name__ == "__main__":
    run()
    print("SOC OPERATIONS TESTS PASSED")
