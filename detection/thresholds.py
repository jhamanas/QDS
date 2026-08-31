"""
detection/thresholds.py

Phase 4: turn the honest-run baseline (baseline.py) into an integer
mismatch_threshold suitable for core.qds_protocol.verify_bit's
mismatch_threshold parameter.

Note on "deterministic acceptance": Phase 3's honest, noiseless case is
exactly deterministic (mismatch_count == 0, always accepted -- see
tests/test_qds_protocol.py). Once realistic channel noise is admitted,
exact determinism is no longer physically meaningful: honest runs can
occasionally see a nonzero mismatch_count from noise alone, not attack.
What we guarantee instead is a *calibrated statistical* guarantee: the
threshold is set far enough above the honest baseline's mean (mean plus
a large multiple of its standard deviation) that the false-reject
probability for honest runs is negligible by construction, while
remaining low enough to flag disturbance whose mismatch rate is
characteristically much higher (quantified empirically once Phase 5/6
attack simulators exist, and analytically in Phase 7).
"""

from __future__ import annotations
import math


def calibrate_threshold(baseline_stats: dict, margin_std: float = 6.0,
                         min_margin_count: int = 1) -> dict:
    """
    Computes an integer mismatch_threshold from baseline stats returned by
    detection.baseline.collect_baseline():

        threshold = ceil(mean_mismatch_count + max(margin_std * std, min_margin_count))

    `min_margin_count` guards against a degenerate zero-variance baseline
    (e.g. channel_noise_p == 0, so std_mismatch_count == 0) collapsing the
    threshold to exactly the mean -- which would reject the very next
    honest run that happens to see even one stray mismatch.

    The threshold is capped at L (never require more agreement than there
    are qubits to check).
    """
    mean = baseline_stats["mean_mismatch_count"]
    std = baseline_stats["std_mismatch_count"]
    L = baseline_stats["L"]

    margin = max(margin_std * std, min_margin_count)
    threshold = math.ceil(mean + margin)
    threshold = min(threshold, L)

    return {
        "mismatch_threshold": threshold,
        "baseline_mean_mismatch_count": mean,
        "baseline_std_mismatch_count": std,
        "margin": margin,
        "margin_std_multiplier": margin_std,
        "L": L,
    }
