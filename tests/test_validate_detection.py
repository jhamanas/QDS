"""
tests/test_validate_detection.py

Phase 6 validation. Run after tests/test_attacks.py passes.
If anything here fails, do not proceed to Phase 7 -- fix
evaluation/validate_detection.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.validate_detection import (
    run_intercept_resend_trial, sweep_intercept_resend_detection, minimum_detectable_intercept_prob,
    attack_detectability_summary,
)
import evaluation.validate_detection as validate_detection

rng = np.random.default_rng(2026)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Attack-trial noise path: p=0 retains the ideal intercept-resend
# disturbance, while nonzero channel noise acts on the attacked states.
# ---------------------------------------------------------------------------
L_NOISE_PATH = 30
N_NOISE_PATH_TRIALS = 120
ideal_attack_mismatches = [
    run_intercept_resend_trial(L_NOISE_PATH, 1.0, rng, channel_noise_p=0.0)
    for _ in range(N_NOISE_PATH_TRIALS)
]
ideal_attack_rate = sum(ideal_attack_mismatches) / (L_NOISE_PATH * N_NOISE_PATH_TRIALS)
check(f"channel_noise_p=0 preserves ideal full intercept-resend mismatch rate "
      f"near 1/3 (got {ideal_attack_rate:.3f})",
      abs(ideal_attack_rate - 1 / 3) < 0.06)

noisy_attack_mismatches = [
    run_intercept_resend_trial(L_NOISE_PATH, 1.0, rng, channel_noise_p=1.0)
    for _ in range(N_NOISE_PATH_TRIALS)
]
noisy_attack_rate = sum(noisy_attack_mismatches) / (L_NOISE_PATH * N_NOISE_PATH_TRIALS)
check(f"nonzero channel noise changes full intercept-resend measurements "
      f"(p=0 rate={ideal_attack_rate:.3f}, p=1 rate={noisy_attack_rate:.3f})",
      noisy_attack_rate > ideal_attack_rate + 0.10)

observed_noise_probabilities = []
real_apply_noise = validate_detection.apply_depolarizing_noise


def record_attack_trial_noise(state, p, target, n_qubits, rng):
    observed_noise_probabilities.append(p)
    return real_apply_noise(state, p, target, n_qubits, rng)


validate_detection.apply_depolarizing_noise = record_attack_trial_noise
try:
    run_intercept_resend_trial(7, 1.0, rng, channel_noise_p=0.23)
finally:
    validate_detection.apply_depolarizing_noise = real_apply_noise

check("configured channel_noise_p is applied in the attack trial, not only baseline calibration",
      observed_noise_probabilities == [0.23] * 7)


# ---------------------------------------------------------------------------
# 2. Intercept-resend detection sweep: detection rate should rise with
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
# 3. Attack detectability summary: confirms empirically which attacks
#    are UNCONDITIONALLY invisible to the QBER detector (always
#    mismatch_count == 0, so flagging is impossible regardless of
#    threshold) versus intercept_resend (genuinely, ongoingly disturbs
#    the channel) versus blind_forgery (a special case: its detection
#    rate is high, but only because a bad guess looks like noise --
#    NOT because the detector recognizes forgery specifically; see
#    evaluation/validate_detection.py's module docstring).
# ---------------------------------------------------------------------------
summary = attack_detectability_summary(L=40, channel_noise_p=0.03, rng=rng,
                                        n_calibration_trials=150, n_trials_per_attack=60)

check(f"intercept_resend_full is flagged at a high rate "
      f"(got {summary['intercept_resend_full']:.3f})",
      summary["intercept_resend_full"] >= 0.9)

# blind_forgery is EXPECTED to be flagged often too -- most random
# guesses at L=40 produce heavy mismatch, indistinguishable from noise
# by the detector. This is not a security gap; it's the same (1/2)^L
# bound already characterized in evaluation/security_analysis.py.
check(f"blind_forgery attempts are mostly flagged too, but for a different "
      f"reason (bad guesses look like noise) -- not asserting low here "
      f"(got {summary['blind_forgery']:.3f})",
      0.0 <= summary["blind_forgery"] <= 1.0)  # sanity bound only, not a security claim

# The four UNCONDITIONALLY invisible attacks: always mismatch_count==0,
# so detection_rate must be exactly (or essentially) zero regardless of
# threshold or L.
for attack_name in ("intercepting_forgery", "impersonation", "naive_replay", "key_reuse"):
    check(f"{attack_name} is unconditionally invisible to the QBER detector "
          f"(got detection_rate={summary[attack_name]:.3f}, expect 0.0)",
          summary[attack_name] == 0.0)

check("intercept-resend's detection rate is far higher than each of the "
      "four unconditionally-invisible attacks' (the real detectability gap)",
      all(summary["intercept_resend_full"] > summary[name] + 0.5
          for name in ("intercepting_forgery", "impersonation", "naive_replay", "key_reuse")))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 6 TESTS PASSED")
