"""
evaluation/security_analysis.py

Phase 7: Security Analysis -- forgery probability, bounds, and
deployment parameter recommendations.

Consolidates what were originally two separate modules
(validation/forgery_threshold_tradeoff.py and security/parameters.py)
into the single file the project structure calls for. Nothing about
the logic changed in the merge; imports were updated to the new
evaluation/ package layout.

Part 1: the threshold/forgery tradeoff
---------------------------------------
Phase 3's original (pre-Phase-5-fix) forgery bound was stated at
mismatch_threshold=0: a blind forger needs EVERY qubit to match, so the
bound is p^L for per-qubit success probability p (corrected in Phase 5
to p=1/2, not the wrong 1/6).

But Phase 4's detector does NOT use mismatch_threshold=0 in practice --
it calibrates a nonzero threshold specifically so that honest runs
experiencing realistic channel noise are not falsely rejected. The
operational policy selects the smallest binomial-tail threshold with a
declared false-reject target (detection/thresholds.py).
This is necessary and correct for noise tolerance, but it directly
WEAKENS forgery resistance: a blind forger no longer needs every single
qubit to match -- only "at most `threshold`" of them can mismatch. Since
each qubit still only succeeds (from the forger's perspective) with
probability 1/2, mismatches are Binomial(L, 1/2)-distributed:

    P(accept) = P(Binomial(L, 0.5) <= threshold)
              = sum_{k=0}^{threshold} C(L, k) * 0.5^L

Part 2: realistic-calibration parameter recommendation
--------------------------------------------------------
required_L_for_target_security (below) assumes a FIXED threshold
fraction of L, which is a simplification. required_L_under_realistic_
calibration directly evaluates the independent Pauli-noise binomial
model at each candidate L, and searches for the minimal L meeting a
target forgery probability under that operational threshold. The
empirical baseline remains a diagnostic/validation tool rather than the
source of the cutoff.

Part 3: bounds for the non-QBER attacks (qualitative, not probabilistic)
--------------------------------------------------------------------------
evaluation/validate_detection.py's attack_detectability_summary already
shows empirically that intercepting forgery, impersonation, and replay/
key-reuse are invisible to the QBER detector. This module's
non_qber_attack_bounds() states, for the record, what DOES bound each
of them (nothing computed here, since none of the three admit a
meaningful "probability of success" framing the way blind forgery
does -- each is either a total, certain break or contingent entirely on
an assumption external to this codebase).
"""

from __future__ import annotations
from dataclasses import dataclass
import math
import numpy as np

from core.qds_protocol import generate_key_material, distribute_public_key, sign_bit, verify_bit
from core.noise import apply_depolarizing_noise
from detection.baseline import collect_baseline
from detection.thresholds import (
    DEFAULT_FALSE_REJECT_ALPHA,
    binomial_tail_threshold,
    calibrate_threshold,
)
from attacks.forgery import blind_forgery_attempt, INTERCEPT_FORGE_SUCCESS_PROB
from attacks.impersonation import IMPERSONATION_SUCCESS_PROB
from evaluation.validate_detection import sweep_intercept_resend_detection


# ---------------------------------------------------------------------------
# Part 1: threshold / forgery tradeoff
# ---------------------------------------------------------------------------

def analytic_blind_forge_success_prob(L: int, threshold: int, p_mismatch: float = 0.5) -> float:
    """
    Closed-form P(accept) for a blind forger against an L-qubit key set
    verified with the given mismatch_threshold. `p_mismatch` defaults to
    0.5 (per attacks/forgery.py's derivation, mismatch and success are
    both 0.5 -- the distribution is symmetric); exposed as a parameter
    so this formula isn't silently re-hardcoded if that constant ever
    needs revisiting.
    """
    threshold = max(0, min(threshold, L))
    return sum(
        math.comb(L, k) * (p_mismatch ** k) * ((1 - p_mismatch) ** (L - k))
        for k in range(threshold + 1)
    )


def empirical_blind_forge_success_rate(L: int, threshold: int, n_trials: int,
                                        rng: np.random.Generator) -> float:
    """
    Empirically measures blind-forger acceptance rate against fresh,
    honestly-distributed key material verified at the given
    mismatch_threshold. Used by tests/test_security_analysis.py to
    confirm analytic_blind_forge_success_prob matches actual verify_bit
    behavior.
    """
    successes = 0
    for _ in range(n_trials):
        km = generate_key_material(L, rng)
        distribute_public_key(km, rng)
        sig = blind_forgery_attempt(L=L, message_bit=0, rng=rng)
        result = verify_bit(km, sig, rng, mismatch_threshold=threshold)
        successes += result.accepted
    return successes / n_trials


@dataclass
class TradeoffPoint:
    threshold: int
    forge_success_prob: float


def threshold_forgery_tradeoff(L: int, thresholds: tuple[int, ...]) -> list[TradeoffPoint]:
    """
    Analytic forgery-success-probability curve across a range of
    candidate mismatch_threshold values, for a fixed key-set size L.
    """
    return [
        TradeoffPoint(threshold=t, forge_success_prob=analytic_blind_forge_success_prob(L, t))
        for t in thresholds
    ]


def required_L_for_target_security(threshold_fraction: float, target_forge_prob: float,
                                    L_search_max: int = 2000) -> int | None:
    """
    Finds the smallest L such that a blind forger's success probability
    at a threshold set to `threshold_fraction * L` (rounded down) stays
    at or below `target_forge_prob`. A simplified, fixed-slack-fraction
    policy question; required_L_under_realistic_calibration (Part 2)
    answers the more realistic version where the threshold comes from
    Phase 4's actual calibration formula instead.

    Returns None if no L up to L_search_max achieves the target.
    """
    for L in range(1, L_search_max + 1):
        threshold = int(threshold_fraction * L)
        if analytic_blind_forge_success_prob(L, threshold) <= target_forge_prob:
            return L
    return None


# ---------------------------------------------------------------------------
# Part 2: realistic-calibration parameter recommendation
# ---------------------------------------------------------------------------

def estimate_per_qubit_mismatch_rate(channel_noise_p: float, rng: np.random.Generator,
                                      L_probe: int = 60, n_trials: int = 300) -> float:
    """
    Estimates the honest-run per-qubit mismatch rate under a given
    channel noise level from a real baseline collection. This remains a
    diagnostic for checking the simulation against q = 2p/3; it does not
    set the operational threshold.
    """
    baseline = collect_baseline(L=L_probe, n_trials=n_trials,
                                 channel_noise_p=channel_noise_p, rng=rng)
    return baseline["mean_mismatch_rate"]


def predicted_threshold(L: int, channel_noise_p: float,
                        alpha: float = DEFAULT_FALSE_REJECT_ALPHA) -> int:
    """
    Returns the exact operational binomial-tail threshold at key-set size L.
    This supersedes the former mean/std extrapolation.
    """
    return binomial_tail_threshold(L, channel_noise_p, alpha)["mismatch_threshold"]


def required_L_under_realistic_calibration(
    channel_noise_p: float, target_forge_prob: float, rng: np.random.Generator,
    alpha: float = DEFAULT_FALSE_REJECT_ALPHA, L_search_max: int = 3000,
) -> int | None:
    """
    Finds the smallest L such that a blind forger's success probability,
    verified against the threshold Phase 4's real calibration procedure
    would actually produce at that L (via predicted_threshold), stays at
    or below target_forge_prob. This is the number that should actually
    govern deployment choice of L -- not the naive (1/2)^L bound, which
    implicitly assumes threshold=0.

    Returns None if no L up to L_search_max achieves the target.
    """
    for L in range(1, L_search_max + 1):
        threshold = predicted_threshold(L, channel_noise_p, alpha=alpha)
        if analytic_blind_forge_success_prob(L, threshold) <= target_forge_prob:
            return L
    return None


@dataclass
class SecurityReport:
    L: int
    channel_noise_p: float
    per_qubit_mismatch_probability: float
    alpha: float
    calibrated_threshold: int
    actual_binomial_false_reject_probability: float
    threshold_equals_L: bool
    baseline_mean_mismatch_count: float
    empirical_false_reject_rate: float
    blind_forge_prob_at_threshold: float
    blind_forge_prob_at_threshold_zero: float
    intercept_forge_prob: float
    impersonation_prob: float
    eavesdrop_detection_by_intercept_prob: dict[float, float]
    recommended_L_for_2pow40: int | None
    recommended_L_for_2pow64: int | None


def generate_security_report(
    L: int, channel_noise_p: float, rng: np.random.Generator,
    alpha: float = DEFAULT_FALSE_REJECT_ALPHA, n_calibration_trials: int = 150,
    n_holdout_trials: int = 100,
    intercept_probs: tuple[float, ...] = (0.1, 0.25, 0.5, 0.75, 1.0),
    n_attack_trials: int = 60,
) -> SecurityReport:
    """
    Produces a single consolidated SecurityReport for a candidate
    deployment configuration (L, channel_noise_p, alpha): the real
    calibrated threshold and its false-reject rate, the corrected
    forgery bounds evaluated at that real threshold, the L-independent
    intercepting-forgery and impersonation constants, an eavesdropping
    detection-rate sweep, and recommended L for two illustrative
    security targets (2^-40 and 2^-64).
    """
    baseline = collect_baseline(L=L, n_trials=n_calibration_trials,
                                 channel_noise_p=channel_noise_p, rng=rng)
    calib = calibrate_threshold(baseline, alpha=alpha)
    threshold = calib["mismatch_threshold"]

    accepted = 0
    for _ in range(n_holdout_trials):
        km = generate_key_material(L, rng)
        distribute_public_key(km, rng)
        for kq in km.key_set_0:
            kq.bob_state = apply_depolarizing_noise(kq.bob_state, channel_noise_p,
                                                      target=0, n_qubits=1, rng=rng)
        sig = sign_bit(km, message_bit=0)
        result = verify_bit(km, sig, rng, mismatch_threshold=threshold)
        accepted += result.accepted
    false_reject_rate = 1 - accepted / n_holdout_trials

    blind_at_threshold = analytic_blind_forge_success_prob(L, threshold)
    blind_at_zero = analytic_blind_forge_success_prob(L, 0)

    sweep_points = sweep_intercept_resend_detection(
        L=L, channel_noise_p=channel_noise_p, intercept_probs=intercept_probs,
        rng=rng, n_calibration_trials=n_calibration_trials, n_attack_trials=n_attack_trials,
        alpha=alpha,
    )
    detection_by_prob = {pt.intercept_prob: pt.detection_rate for pt in sweep_points}

    rec_L_40 = required_L_under_realistic_calibration(channel_noise_p, 2 ** -40, rng, alpha)
    rec_L_64 = required_L_under_realistic_calibration(channel_noise_p, 2 ** -64, rng, alpha)

    return SecurityReport(
        L=L,
        channel_noise_p=channel_noise_p,
        per_qubit_mismatch_probability=calib["per_qubit_mismatch_probability"],
        alpha=alpha,
        calibrated_threshold=threshold,
        actual_binomial_false_reject_probability=calib["actual_binomial_false_reject_probability"],
        threshold_equals_L=calib["threshold_equals_L"],
        baseline_mean_mismatch_count=baseline["mean_mismatch_count"],
        empirical_false_reject_rate=false_reject_rate,
        blind_forge_prob_at_threshold=blind_at_threshold,
        blind_forge_prob_at_threshold_zero=blind_at_zero,
        intercept_forge_prob=INTERCEPT_FORGE_SUCCESS_PROB,
        impersonation_prob=IMPERSONATION_SUCCESS_PROB,
        eavesdrop_detection_by_intercept_prob=detection_by_prob,
        recommended_L_for_2pow40=rec_L_40,
        recommended_L_for_2pow64=rec_L_64,
    )


# ---------------------------------------------------------------------------
# Part 3: bounds for the non-QBER attacks (qualitative)
# ---------------------------------------------------------------------------

def non_qber_attack_bounds() -> dict[str, dict[str, object]]:
    """
    States, for the record, what actually bounds each attack that the
    QBER detector cannot see (evaluation/validate_detection.py's
    attack_detectability_summary confirms detection_rate ~= 0 for all
    three empirically). None of these admit a "security parameter" the
    way blind forgery does -- L does not help any of them.
    """
    return {
        "intercepting_forgery": {
            "success_probability": INTERCEPT_FORGE_SUCCESS_PROB,
            "l_dependent": False,
            "mitigation": "Physical security of the quantum channel and Bob's "
                           "qubit storage prior to verification. No parameter "
                           "in this codebase compensates for a breach here.",
        },
        "impersonation": {
            "success_probability": IMPERSONATION_SUCCESS_PROB,
            "l_dependent": False,
            "mitigation": "An authenticated channel or PKI binding the "
                           "distribution session to Alice's identity, external "
                           "to core/qds_protocol.py entirely.",
        },
        "replay_and_key_reuse": {
            "success_probability": 1.0,
            "l_dependent": False,
            "mitigation": "Deployment-level discipline: verification-side "
                           "freshness/nonce tracking (for naive replay) and "
                           "strict single-use enforcement of each "
                           "SingleBitKeyMaterial object (for key reuse). "
                           "Neither is enforced by core/qds_protocol.py itself.",
        },
    }
