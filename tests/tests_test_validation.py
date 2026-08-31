"""
tests/test_validation.py

Phase 6 validation. Run after tests/test_attacks.py passes.
If anything here fails, do not proceed to Phase 7 -- fix
validation/detection_sweep.py or validation/forgery_threshold_tradeoff.py
first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validation.detection_sweep import (
    sweep_intercept_resend_detection, minimum_detectable_intercept_prob,
)
from validation.forgery_threshold_tradeoff import (
    analytic_blind_forge_success_prob, empirical_blind_forge_success_rate,
    threshold_forgery_tradeoff, required_L_for_target_security,
)

rng = np.random.default_rng(2026)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Intercept-resend detection sweep: detection rate should rise with
#    intercept_prob, be low near 0.0 (should look like honest noise) and
#    high near 1.0 (matches tests/test_attacks.py's single-point result).
# ---------------------------------------------------------------------------
L_SWEEP = 40
intercept_probs = (0.0, 0.1, 0.25, 0.5, 0.75, 1.0)
points = sweep_intercept_resend_detection(
    L=L_SWEEP, channel_noise_p=0.03, intercept_probs=intercept_probs,
    rng=rng, n_calibration_trials=150, n_attack_trials=100,
)

by_prob = {pt.intercept_prob: pt for pt in points}
check(f"swept all {len(intercept_probs)} intercept_prob values",
      len(points) == len(intercept_probs))

check(f"intercept_prob=0.0 (no attack) has a low false-positive-like detection rate "
      f"(got {by_prob[0.0].detection_rate:.3f})",
      by_prob[0.0].detection_rate <= 0.10)

check(f"intercept_prob=1.0 (full attack) is detected essentially always "
      f"(got {by_prob[1.0].detection_rate:.3f})",
      by_prob[1.0].detection_rate >= 0.95)

# Detection rate should be (roughly) monotonically non-decreasing in
# intercept_prob -- allow a little slack for statistical noise at
# n_attack_trials=100 rather than requiring strict monotonicity.
rates_in_order = [by_prob[p].detection_rate for p in intercept_probs]
non_decreasing_violations = sum(
    1 for i in range(1, len(rates_in_order))
    if rates_in_order[i] < rates_in_order[i - 1] - 0.15  # tolerate noise, not reversals
)
check(f"detection rate is (roughly) monotonically non-decreasing in intercept_prob "
      f"(rates={[round(r, 2) for r in rates_in_order]})",
      non_decreasing_violations == 0)

min_detectable = minimum_detectable_intercept_prob(points, detection_rate_floor=0.5)
check(f"a 50%-detectable intercept_prob exists within the swept range (got {min_detectable})",
      min_detectable is not None)

# ---------------------------------------------------------------------------
# 2. Threshold/forgery tradeoff: analytic formula matches empirical
#    verify_bit behavior across several (L, threshold) combinations.
# ---------------------------------------------------------------------------
test_cases = [
    (10, 0),   # naive textbook bound: (1/2)^10
    (10, 1),
    (10, 3),
    (16, 2),
]
N_EMPIRICAL = 6000
for L, threshold in test_cases:
    analytic = analytic_blind_forge_success_prob(L, threshold)
    empirical = empirical_blind_forge_success_rate(L, threshold, N_EMPIRICAL, rng)
    # Statistical tolerance: a few standard deviations of a binomial
    # proportion at this sample size, plus a small floor for very-low-p cases.
    std = (analytic * (1 - analytic) / N_EMPIRICAL) ** 0.5
    tol = max(4 * std, 0.01)
    check(f"L={L}, threshold={threshold}: analytic P(accept)={analytic:.5f} matches "
          f"empirical rate={empirical:.5f} (tol={tol:.4f})",
          abs(analytic - empirical) <= tol)

# threshold=0 special case should reduce to the simple (1/2)^L bound
check("threshold=0 reduces to the simple (1/2)^L bound",
      np.isclose(analytic_blind_forge_success_prob(12, 0), 0.5 ** 12))

# ---------------------------------------------------------------------------
# 3. The tradeoff is real: raising the threshold measurably increases
#    forgery success probability at fixed L (this is the whole point of
#    this module -- confirm it's not a wash).
# ---------------------------------------------------------------------------
tradeoff = threshold_forgery_tradeoff(L=30, thresholds=(0, 1, 2, 4, 8))
tradeoff_probs = [pt.forge_success_prob for pt in tradeoff]
check(f"forgery success probability strictly increases with threshold at fixed L "
      f"(probs={[f'{p:.2e}' for p in tradeoff_probs]})",
      all(tradeoff_probs[i] < tradeoff_probs[i + 1] for i in range(len(tradeoff_probs) - 1)))

check(f"a generously-calibrated threshold (8 of 30 qubits) is dramatically weaker "
      f"than threshold=0 (got {tradeoff_probs[-1]:.2e} vs {tradeoff_probs[0]:.2e})",
      tradeoff_probs[-1] > 1000 * tradeoff_probs[0])

# ---------------------------------------------------------------------------
# 4. required_L_for_target_security: sanity checks against known values
# ---------------------------------------------------------------------------
# With zero slack (threshold_fraction=0.0), reaching 2^-20 forgery
# probability at p=1/2 per qubit requires exactly L=20.
L_needed = required_L_for_target_security(threshold_fraction=0.0, target_forge_prob=2 ** -20)
check(f"required_L_for_target_security(0.0, 2^-20) == 20 (got {L_needed})",
      L_needed == 20)

# With 10% slack allowed, more qubits should be needed to hit the same
# target than with zero slack -- confirms the function actually accounts
# for the threshold, not just L on its own.
L_needed_slack = required_L_for_target_security(threshold_fraction=0.1, target_forge_prob=2 ** -20)
check(f"10%-slack policy needs more qubits than zero-slack for the same target "
      f"(zero-slack L={L_needed}, 10%-slack L={L_needed_slack})",
      L_needed_slack is not None and L_needed_slack > L_needed)

# Confirm minimality: L_needed_slack - 1 should NOT meet the target.
if L_needed_slack is not None:
    threshold_at_L_minus_1 = int(0.1 * (L_needed_slack - 1))
    prob_at_L_minus_1 = analytic_blind_forge_success_prob(L_needed_slack - 1, threshold_at_L_minus_1)
    check(f"required_L_for_target_security returns the MINIMAL sufficient L "
          f"(L-1={L_needed_slack - 1} gives prob={prob_at_L_minus_1:.2e}, target=2^-20)",
          prob_at_L_minus_1 > 2 ** -20)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 6 TESTS PASSED")
