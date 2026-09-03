"""Unauthorized-verifier attack helper."""
from __future__ import annotations

import numpy as np

from core.secure_protocol import SecureSession, SecureSignature, SecureVerificationResult, SecureVerifier


def unauthorized_verification_attack(session: SecureSession, payload: str,
                                     rng: np.random.Generator,
                                     mismatch_threshold: int = 0,
                                     attacker_id: str = "eve",
                                     signature: SecureSignature | None = None) -> SecureVerificationResult:
    """Attempt to verify Bob's signature as an unregistered verifier."""
    verifier = SecureVerifier(attacker_id, {session.signer_id: session._authentication_key})
    try:
        verifier.register_distribution(session)
    except ValueError as error:
        return SecureVerificationResult(False, f"unauthorized verifier rejected: {error}")
    signature = signature or session.sign(0, payload)
    return verifier.verify(signature, payload, rng, mismatch_threshold)
