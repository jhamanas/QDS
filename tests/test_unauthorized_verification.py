"""Dedicated P0 authorization and replay tests."""
from dataclasses import replace
import secrets
import time
from pathlib import Path
import sys
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.secure_protocol import SecureSession, SecureVerifier, SecureSignature


def setup():
    key = secrets.token_bytes(32)
    rng = np.random.default_rng(21)
    session = SecureSession.create("alice", "bob", 12, rng, key)
    verifier = SecureVerifier("bob", {"alice": key})
    verifier.register_distribution(session)
    return key, rng, session, verifier


def run():
    key, rng, session, verifier = setup()
    signature = session.sign(0, "payload")
    assert verifier.verify(signature, "payload", rng).accepted

    # Missing, altered, expired and replayed authorizations are all rejected.
    key, rng, session, verifier = setup()
    signature = session.sign(0, "payload")
    assert verifier.verify(replace(signature, authorization=None), "payload", rng).accepted is False
    altered = replace(signature, authorization=replace(signature.authorization, verifier_id="eve"))
    assert verifier.verify(altered, "payload", rng).accepted is False

    key, rng, session, verifier = setup()
    expired = session.issue_authorization("bob", ttl_seconds=0.001)
    time.sleep(0.01)
    signature = session.sign(0, "payload", expired)
    assert verifier.verify(signature, "payload", rng).accepted is False

    key, rng, session, verifier = setup()
    authorization = session.issue_authorization("bob")
    first = session.sign(0, "payload", authorization)
    assert verifier.verify(first, "payload", rng).accepted
    second = replace(first, signature_id="second-signature")
    assert verifier.verify(second, "payload", rng).accepted is False


if __name__ == "__main__":
    run()
    print("UNAUTHORIZED VERIFICATION TESTS PASSED")
