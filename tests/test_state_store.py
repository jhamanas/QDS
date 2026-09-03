from pathlib import Path
import sys
import tempfile
import secrets
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.secure_protocol import SecureSession, SecureVerifier
from core.state_store import SQLiteStateStore


def run():
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "state.sqlite3"
        first = SQLiteStateStore(path)
        assert first.consume_signature("s1")
        second = SQLiteStateStore(path)
        assert not second.consume_signature("s1")
        assert first.consume_authorization("a1")
        assert not second.consume_authorization("a1")
        key = secrets.token_bytes(32)
        rng = np.random.default_rng(4)
        session = SecureSession.create("aditi", "bharat", 4, rng, key)
        verifier1 = SecureVerifier("bharat", {"aditi": key}, state_store=first)
        verifier1.register_distribution(session)
        signature = session.sign(0, "state")
        assert verifier1.verify(signature, "state", rng).accepted
        verifier2 = SecureVerifier("bharat", {"aditi": key}, state_store=second)
        verifier2.register_distribution(session)
        assert not verifier2.verify(signature, "state", rng).accepted


if __name__ == "__main__":
    run()
    print("STATE STORE TESTS PASSED")
