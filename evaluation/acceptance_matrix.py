"""Evidence matrix for honest acceptance and security rejection claims."""
from __future__ import annotations

import secrets
import numpy as np

from core.secure_protocol import SecureSession, SecureVerifier
from evaluation.metrics import rate_summary


def evaluate_honest_acceptance(*, length: int = 64, trials: int = 100,
                               mismatch_threshold: int = 0, payload: str = "matrix",
                               seed: int = 7) -> dict[str, object]:
    """Run independent honest sessions and return a rate plus confidence interval."""
    if length < 1 or trials < 1 or mismatch_threshold < 0:
        raise ValueError("length/trials must be positive and threshold non-negative")
    rng = np.random.default_rng(seed)
    accepted = 0
    for _ in range(trials):
        key = secrets.token_bytes(32)
        session = SecureSession.create("alice", "bob", length, rng, key)
        verifier = SecureVerifier("bob", {"alice": key})
        verifier.register_distribution(session)
        accepted += verifier.verify(session.sign(0, payload), payload, rng, mismatch_threshold).accepted
    return {"case": "honest_ideal", "length": length, "trials": trials,
            "acceptance": rate_summary(accepted, trials),
            "deterministic_expected": mismatch_threshold == 0}
