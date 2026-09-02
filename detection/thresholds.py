"""Turn the honest-run baseline into an operational mismatch threshold.

The former operational policy, ``ceil(mean + max(6 * std, 1))``, was an
empirical heuristic. The operational policy is now an exact binomial-tail
calibration for this repository's declared independent Pauli-noise model.
It is an educational/demo false-reject policy, not a QDS security proof.
"""

from __future__ import annotations
import math


DEFAULT_FALSE_REJECT_ALPHA = 1e-6


def _validate_probability(name: str, value: float, lower: float, upper: float) -> None:
    if not isinstance(value, (int, float)) or not math.isfinite(value) or not lower <= value <= upper:
        raise ValueError(f"{name} must be in [{lower}, {upper}], got {value!r}")


def _validate_parameters(L: int, channel_noise_p: float, alpha: float) -> None:
    if not isinstance(L, int) or isinstance(L, bool) or L < 0:
        raise ValueError(f"L must be a non-negative integer, got {L!r}")
    _validate_probability("channel_noise_p", channel_noise_p, 0.0, 1.0)
    if (not isinstance(alpha, (int, float)) or not math.isfinite(alpha)
            or not 0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")


def binomial_survival_probability(L: int, q: float, threshold: int) -> float:
    """Return ``P(Binomial(L, q) > threshold)`` using log-PMF summation."""
    if not isinstance(L, int) or isinstance(L, bool) or L < 0:
        raise ValueError(f"L must be a non-negative integer, got {L!r}")
    _validate_probability("q", q, 0.0, 1.0)
    if threshold < 0:
        return 1.0
    if threshold >= L or q == 0.0:
        return 0.0
    if q == 1.0:
        return 1.0

    log_terms = [
        (math.lgamma(L + 1) - math.lgamma(k + 1) - math.lgamma(L - k + 1)
         + k * math.log(q) + (L - k) * math.log1p(-q))
        for k in range(threshold + 1, L + 1)
    ]
    max_log_term = max(log_terms)
    return math.exp(max_log_term) * math.fsum(
        math.exp(log_term - max_log_term) for log_term in log_terms
    )


def binomial_tail_threshold(L: int, channel_noise_p: float,
                            alpha: float = DEFAULT_FALSE_REJECT_ALPHA) -> dict:
    """
    Select the smallest ``t`` with ``P(Binomial(L, 2p/3) > t) <= alpha``.

    ``threshold_equals_L`` explicitly identifies the no-discrimination case:
    a mismatch-count detector cannot reject if every count is accepted.
    """
    _validate_parameters(L, channel_noise_p, alpha)
    q = 2.0 * channel_noise_p / 3.0
    if not 0.0 <= q <= 2.0 / 3.0:
        raise ValueError(f"derived mismatch probability q must be in [0, 2/3], got {q}")

    # The survival probability decreases monotonically with the threshold.
    # Binary search avoids repeatedly summing nearly the same tails when L
    # is large, while preserving exact integer threshold selection.
    low, high = 0, L
    while low < high:
        threshold = (low + high) // 2
        if binomial_survival_probability(L, q, threshold) <= alpha:
            high = threshold
        else:
            low = threshold + 1

    threshold = low
    false_reject_probability = binomial_survival_probability(L, q, threshold)
    return {
        "mismatch_threshold": threshold,
        "L": L,
        "channel_noise_p": channel_noise_p,
        "per_qubit_mismatch_probability": q,
        "alpha": alpha,
        "actual_binomial_false_reject_probability": false_reject_probability,
        "threshold_equals_L": threshold == L,
        "mismatch_only_detection_possible": threshold < L,
    }


def calibrate_threshold(baseline_stats: dict,
                        alpha: float = DEFAULT_FALSE_REJECT_ALPHA) -> dict:
    """
    Calibrate from the declared Pauli-noise model while retaining the sampled
    baseline mean/std as empirical validation diagnostics.
    """
    calibration = binomial_tail_threshold(
        baseline_stats["L"], baseline_stats["channel_noise_p"], alpha
    )
    calibration.update({
        "baseline_mean_mismatch_count": baseline_stats["mean_mismatch_count"],
        "baseline_std_mismatch_count": baseline_stats["std_mismatch_count"],
    })

    return calibration
