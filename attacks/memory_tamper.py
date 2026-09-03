"""Model a compromised Bharat-memory integrity signal."""
from __future__ import annotations

from core.secure_protocol import SecureVerificationResult


def memory_tamper_attempt() -> SecureVerificationResult:
    """Return the mandatory fail-closed result for detected memory tampering."""
    return SecureVerificationResult(False, "integrity failure: quantum memory tamper detected; verification aborted")
