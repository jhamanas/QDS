import os, secrets, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.forgery import blind_forgery_attempt
from core.secure_protocol import SecureSession, SecureSignature, SecureVerifier

def setup():
    rng = np.random.default_rng(33); key = secrets.token_bytes(32)
    verifier = SecureVerifier("bob", {"alice": key})
    session = SecureSession.create("alice", "bob", 12, rng, key); verifier.register_distribution(session)
    return rng, session, verifier

rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert verifier.verify(sig, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert verifier.verify(sig, "pay:10", rng).accepted; assert not verifier.verify(sig, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert not verifier.verify(sig, "pay:999", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); forged = blind_forgery_attempt(12, 0, rng)
bad = SecureSignature(sig.session_id, sig.signature_id, "alice", "bob", 0, sig.payload_digest, tuple(forged.disclosed_descriptions)); assert not verifier.verify(bad, "pay:10", rng).accepted
rng, session, verifier = setup(); session.sign(0, "pay:10")
try: session.sign(1, "pay:10"); raise AssertionError("key reuse was allowed")
except ValueError: pass
print("ALL HARDENED PROTOCOL TESTS PASSED")
