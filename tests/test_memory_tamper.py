from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import secrets
from core.secure_protocol import SecureSession, SecureVerifier


def run():
    key = secrets.token_bytes(32)
    rng = np.random.default_rng(2)
    session = SecureSession.create("alice", "bob", 4, rng, key)
    verifier = SecureVerifier("bob", {"alice": key})
    verifier.register_distribution(session)
    result = verifier.verify(session.sign(0, "x"), "x", rng, memory_integrity_ok=False)
    assert not result.accepted and "aborted" in result.reason


if __name__ == "__main__":
    run()
    print("MEMORY TAMPER TESTS PASSED")
