import hashlib, json, os, secrets, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.forgery import blind_forgery_attempt
from core.secure_protocol import SecureSession, SecureSignature, SecureVerifier

def setup():
    rng = np.random.default_rng(33); key = secrets.token_bytes(32)
    verifier = SecureVerifier("bharat", {"aditi": key})
    session = SecureSession.create("aditi", "bharat", 12, rng, key); verifier.register_distribution(session)
    return rng, session, verifier

rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert verifier.verify(sig, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert verifier.verify(sig, "pay:10", rng).accepted; assert not verifier.verify(sig, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); assert not verifier.verify(sig, "pay:999", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10"); forged = blind_forgery_attempt(12, 0, rng)
bad = SecureSignature(sig.session_id, sig.signature_id, "aditi", "bharat", 0, sig.payload_digest, tuple(forged.disclosed_descriptions), sig.opening_nonces); assert not verifier.verify(bad, "pay:10", rng).accepted

# Regression: an observer with only public commitment metadata cannot use the
# old six-candidate hash calculation to recover a description. The unknown
# opening nonce is not part of AuthenticatedPublicRecord.
rng, session, verifier = setup()
record = session.public_record
target = record.commitments[0][0]
old_style_candidates = []
for basis in ("X", "Y", "Z"):
    for eigen in (0, 1):
        old_style_candidates.append(hashlib.sha256(json.dumps(
            {"session_id": record.session_id, "set": 0, "index": 0,
             "basis": basis, "eigen": eigen},
            sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest())
assert target not in old_style_candidates

# Honest openings verify, while missing/altered openings fail commitment checks.
sig = session.sign(0, "pay:10")
assert verifier.verify(sig, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10")
missing_openings = SecureSignature(sig.session_id, sig.signature_id, "aditi", "bharat", 0,
                                   sig.payload_digest, sig.disclosed_descriptions, ())
assert not verifier.verify(missing_openings, "pay:10", rng).accepted
rng, session, verifier = setup(); sig = session.sign(0, "pay:10")
altered_openings = list(sig.opening_nonces); altered_openings[0] = "0" * 64
bad_opening = SecureSignature(sig.session_id, sig.signature_id, "aditi", "bharat", 0,
                              sig.payload_digest, sig.disclosed_descriptions,
                              tuple(altered_openings))
assert not verifier.verify(bad_opening, "pay:10", rng).accepted
rng, session, verifier = setup(); session.sign(0, "pay:10")
try: session.sign(1, "pay:10"); raise AssertionError("key reuse was allowed")
except ValueError: pass
print("ALL HARDENED PROTOCOL TESTS PASSED")
