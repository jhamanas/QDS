"""
tests/test_security_analysis.py

Phase 7 validation. Run after tests/test_validate_detection.py passes.
If anything here fails, do not trust evaluation/security_analysis.py's
recommendations or the numbers in results/security_analysis.md -- fix
evaluation/security_analysis.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.baseline import collect_baseline
from detection.thresholds import DEFAULT_FALSE_REJECT_ALPHA, calibrate_threshold
from evaluation.security_analysis import (
    analytic_blind_forge_success_prob, empirical_blind_forge_success_rate,
    threshold_forgery_tradeoff, required_L_for_target_security,
    estimate_per_qubit_mismatch_rate, predicted_threshold,
    required_L_under_realistic_calibration, generate_security_report,
    non_qber_attack_bounds,
)

rng = np.random.default_rng(2026)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


CHANNEL_NOISE_P = 0.03

# ---------------------------------------------------------------------------
# 1. Threshold/forgery tradeoff: analytic formula matches empirical
#    verify_bit behavior across several (L, threshold) combinations.
# ---------------------------------------------------------------------------
test_cases = [(10, 0), (10, 1), (10, 3), (16, 2)]
N_EMPIRICAL = 6000
for L, threshold in test_cases:
    analytic = analytic_blind_forge_success_prob(L, threshold)
    empirical = empirical_blind_forge_success_rate(L, threshold, N_EMPIRICAL, rng)
    std = (analytic * (1 - analytic) / N_EMPIRICAL) ** 0.5
    tol = max(4 * std, 0.01)
    check(f"L={L}, threshold={threshold}: analytic P(accept)={analytic:.5f} matches "
          f"empirical rate={empirical:.5f} (tol={tol:.4f})",
          abs(analytic - empirical) <= tol)

check("threshold=0 reduces to the simple (1/2)^L bound",
      np.isclose(analytic_blind_forge_success_prob(12, 0), 0.5 ** 12))

# ---------------------------------------------------------------------------
# 2. The tradeoff is real: raising the threshold measurably increases
#    forgery success probability at fixed L.
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
# 3. required_L_for_target_security: sanity checks against known values
# ---------------------------------------------------------------------------
L_needed = required_L_for_target_security(threshold_fraction=0.0, target_forge_prob=2 ** -20)
check(f"required_L_for_target_security(0.0, 2^-20) == 20 (got {L_needed})",
      L_needed == 20)

L_needed_slack = required_L_for_target_security(threshold_fraction=0.1, target_forge_prob=2 ** -20)
check(f"10%-slack policy needs more qubits than zero-slack for the same target "
      f"(zero-slack L={L_needed}, 10%-slack L={L_needed_slack})",
      L_needed_slack is not None and L_needed_slack > L_needed)

if L_needed_slack is not None:
    threshold_at_L_minus_1 = int(0.1 * (L_needed_slack - 1))
    prob_at_L_minus_1 = analytic_blind_forge_success_prob(L_needed_slack - 1, threshold_at_L_minus_1)
    check(f"required_L_for_target_security returns the MINIMAL sufficient L "
          f"(L-1={L_needed_slack - 1} gives prob={prob_at_L_minus_1:.2e}, target=2^-20)",
          prob_at_L_minus_1 > 2 ** -20)

# ---------------------------------------------------------------------------
# 4. The exact operational threshold is independent of finite baseline
#    sampling; the baseline remains a diagnostic of q = 2p/3.
# ---------------------------------------------------------------------------
mean_rate = estimate_per_qubit_mismatch_rate(CHANNEL_NOISE_P, rng, L_probe=60, n_trials=400)
check(f"estimated per-qubit mismatch rate is positive and well below 1 "
      f"(got {mean_rate:.4f})", 0.0 < mean_rate < 0.1)

for L_check in (40, 80):
    real_baseline = collect_baseline(L=L_check, n_trials=300, channel_noise_p=CHANNEL_NOISE_P, rng=rng)
    real_calib = calibrate_threshold(real_baseline)
    real_threshold = real_calib["mismatch_threshold"]
    exact_threshold = predicted_threshold(L_check, CHANNEL_NOISE_P)
    check(f"predicted_threshold(L={L_check}) matches exact calibration "
          f"(predicted={exact_threshold}, real={real_threshold})",
          exact_threshold == real_threshold)

edge_threshold = predicted_threshold(L=10, channel_noise_p=1.0, alpha=0.5)
check("predicted_threshold remains within [0, L] at maximum channel noise",
      0 <= edge_threshold <= 10)

zero_rate_threshold = predicted_threshold(L=20, channel_noise_p=0.0)
check("predicted_threshold is zero for zero channel noise",
      zero_rate_threshold == 0)

# ---------------------------------------------------------------------------
# 5. required_L_under_realistic_calibration: larger L needed for a
#    tighter target; exceeds the naive threshold=0 estimate.
# ---------------------------------------------------------------------------
L_loose = required_L_under_realistic_calibration(CHANNEL_NOISE_P, 2 ** -20, rng)
L_tight = required_L_under_realistic_calibration(CHANNEL_NOISE_P, 2 ** -40, rng)
check(f"tighter forgery target needs a larger (or equal) L "
      f"(2^-20 -> L={L_loose}, 2^-40 -> L={L_tight})",
      L_loose is not None and L_tight is not None and L_tight >= L_loose)

check(f"required L for 2^-40 under realistic calibration exceeds the naive "
      f"threshold=0 estimate of 40 qubits (got {L_tight})",
      L_tight > 40)

# ---------------------------------------------------------------------------
# 6. generate_security_report: end-to-end sanity check.
# ---------------------------------------------------------------------------
report = generate_security_report(
    L=40, channel_noise_p=CHANNEL_NOISE_P, rng=rng, alpha=DEFAULT_FALSE_REJECT_ALPHA,
    n_calibration_trials=120, n_holdout_trials=80,
    intercept_probs=(0.25, 0.5, 1.0), n_attack_trials=50,
)

check("report calibrated_threshold is non-negative and <= L",
      0 <= report.calibrated_threshold <= report.L)
check("report exposes the binomial calibration model and tail probability",
      np.isclose(report.per_qubit_mismatch_probability, 2 * CHANNEL_NOISE_P / 3)
      and report.actual_binomial_false_reject_probability <= report.alpha)
check(f"report false-reject rate is low (got {report.empirical_false_reject_rate:.3f})",
      report.empirical_false_reject_rate <= 0.10)
check("blind forgery prob at calibrated threshold exceeds the threshold=0 bound",
      report.blind_forge_prob_at_threshold >= report.blind_forge_prob_at_threshold_zero)
check("blind forgery prob at threshold=0 matches (1/2)^L",
      np.isclose(report.blind_forge_prob_at_threshold_zero, 0.5 ** report.L))
check("intercepting-forger probability is reported as exactly 1.0",
      report.intercept_forge_prob == 1.0)
check("impersonation probability is reported as exactly 1.0",
      report.impersonation_prob == 1.0)
check("eavesdrop detection rate at intercept_prob=1.0 is high",
      report.eavesdrop_detection_by_intercept_prob[1.0] >= 0.9)
check("eavesdrop detection rate increases from 0.25 to 1.0 intercept_prob",
      report.eavesdrop_detection_by_intercept_prob[1.0] >=
      report.eavesdrop_detection_by_intercept_prob[0.25])
check("recommended L for 2^-64 target is larger than for 2^-40",
      report.recommended_L_for_2pow64 is None or report.recommended_L_for_2pow40 is None or
      report.recommended_L_for_2pow64 >= report.recommended_L_for_2pow40)

# ---------------------------------------------------------------------------
# 7. non_qber_attack_bounds: all three non-QBER attacks reported with
#    L-independent, probability-1.0 (or fully-exposing) outcomes.
# ---------------------------------------------------------------------------
bounds = non_qber_attack_bounds()
check("non_qber_attack_bounds covers all three qualitative-bound attacks",
      set(bounds.keys()) == {"intercepting_forgery", "impersonation", "replay_and_key_reuse"})
check("all three are reported as L-independent with success probability 1.0",
      all(not entry["l_dependent"] and entry["success_probability"] == 1.0
          for entry in bounds.values()))
check("each entry names a mitigation external to core/qds_protocol.py",
      all(isinstance(entry["mitigation"], str) and len(entry["mitigation"]) > 0
          for entry in bounds.values()))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 7 TESTS PASSED")
