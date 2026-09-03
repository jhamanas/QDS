"""
detection/detector.py

Phase 4: the accept/reject decision engine itself.

This is intentionally a thin layer: core.qds_protocol.verify_bit already
accepts a mismatch_threshold parameter (built into Phase 3 for exactly
this purpose), so "detection" here means (1) calibrate a defensible
threshold from the honest baseline (thresholds.py), then (2) call
verify_bit with that calibrated threshold instead of the strict
threshold=0 used in Phase 3's own tests, and (3) surface enough
diagnostic detail (observed mismatch rate vs. threshold) for later
phases -- attack validation (Phase 6), security analysis (Phase 7) -- to
reason about *how* confidently a decision was made, not just whether it
was accept/reject.

No AI/ML anywhere in this decision path: it is a deterministic threshold
comparison on verify_bit's measurement-based mismatch count, matching the
project's core constraint.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np

from core.qds_protocol import SingleBitKeyMaterial, SignatureBit, VerificationResult, verify_bit


@dataclass
class DetectionResult:
    accepted: bool
    mismatch_count: int
    total_checked: int
    mismatch_rate: float
    mismatch_threshold: int
    verification: VerificationResult

    def __repr__(self) -> str:
        verdict = "ACCEPT" if self.accepted else "FLAG/REJECT"
        return (
            f"DetectionResult({verdict}, mismatches={self.mismatch_count}/"
            f"{self.total_checked} [rate={self.mismatch_rate:.4f}], "
            f"threshold={self.mismatch_threshold})"
        )


def verify_with_detection(key_material: SingleBitKeyMaterial, signature: SignatureBit,
                           rng: np.random.Generator, mismatch_threshold: int) -> DetectionResult:
    """
    Runs Bharat's physical verification (core.qds_protocol.verify_bit) using a
    calibrated mismatch_threshold (from detection.thresholds.calibrate_threshold)
    rather than the strict threshold=0 default, and wraps the result with
    the extra diagnostic fields (mismatch_rate, threshold used) that later
    phases will want. Deliberately delegates the actual measurement and
    comparison to verify_bit rather than reimplementing it, so there is
    exactly one place in the codebase that decides accept/reject.
    """
    result = verify_bit(key_material, signature, rng, mismatch_threshold=mismatch_threshold)
    mismatch_rate = result.mismatch_count / result.total_checked if result.total_checked else 0.0

    return DetectionResult(
        accepted=result.accepted,
        mismatch_count=result.mismatch_count,
        total_checked=result.total_checked,
        mismatch_rate=mismatch_rate,
        mismatch_threshold=mismatch_threshold,
        verification=result,
    )
