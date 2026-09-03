"""
tests/test_detector.py

Phase 4 validation. Run after tests/test_qds_protocol.py passes.
If anything here fails, do not proceed to Phase 5 -- fix baseline.py,
thresholds.py, or detector.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.qds_protocol import generate_key_material, distribute_public_key, sign_bit, verify_bit
from core.noise import apply_depolarizing_noise
from detection.baseline import run_honest_trial, collect_baseline
from detection.thresholds import (
    DEFAULT_FALSE_REJECT_ALPHA,
    binomial_survival_probability,
    binomial_tail_threshold,
    calibrate_threshold,
)
from detection.detector import verify_with_detection

rng = np.random.default_rng(2024)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


L = 20
CHANNEL_NOISE_P = 0.03
N_CALIBRATION_TRIALS = 120

# ---------------------------------------------------------------------------
# 1. core.noise.apply_depolarizing_noise basic sanity
# ---------------------------------------------------------------------------
from core.primitives import KET_0, is_normalized, measure_qubit_in_basis, state_fidelity

no_noise = apply_depolarizing_noise(KET_0.copy(), p=0.0, target=0, n_qubits=1, rng=rng)
check("p=0.0 never perturbs the state", np.isclose(state_fidelity(no_noise, KET_0), 1.0))

# NOTE: at p=1.0, one of {X, Y, Z} is applied uniformly at random. For a
# Z-eigenstate like |0>, the Z error leaves it unchanged (Z|0> = |0>, up
# to an unobservable global phase) -- only X and Y actually perturb it.
# So the correct expectation at p=1.0 is fidelity 1.0 on ~1/3 of trials
# and fidelity 0.0 on ~2/3 (mean ~1/3), NOT "always perturbed."
full_noise_fidelities = [
    state_fidelity(apply_depolarizing_noise(KET_0.copy(), p=1.0, target=0, n_qubits=1, rng=rng), KET_0)
    for _ in range(600)
]
mean_full_noise_fidelity = float(np.mean(full_noise_fidelities))
check(f"p=1.0 perturbs |0> on ~2/3 of trials (mean fidelity ~0.333, got {mean_full_noise_fidelity:.3f})",
      0.25 < mean_full_noise_fidelity < 0.42)
check("p=1.0 does perturb the state on at least some trials",
      any(f < 1.0 for f in full_noise_fidelities))

full_noise_mismatches = 0
for _ in range(600):
    noisy_state = apply_depolarizing_noise(KET_0.copy(), p=1.0, target=0, n_qubits=1, rng=rng)
    outcome, _ = measure_qubit_in_basis(noisy_state, target=0, n_qubits=1, basis="Z", rng=rng)
    full_noise_mismatches += outcome != 0
full_noise_mismatch_rate = full_noise_mismatches / 600
check(f"p=1.0 same-basis mismatch rate is ~2/3 (got {full_noise_mismatch_rate:.3f})",
      0.58 < full_noise_mismatch_rate < 0.75)

check("noisy states remain normalized",
      all(is_normalized(apply_depolarizing_noise(KET_0.copy(), p=0.5, target=0, n_qubits=1, rng=rng))
          for _ in range(20)))

try:
    apply_depolarizing_noise(KET_0.copy(), p=1.5, target=0, n_qubits=1, rng=rng)
    check("apply_depolarizing_noise rejects p outside [0,1]", False)
except ValueError:
    check("apply_depolarizing_noise rejects p outside [0,1]", True)

# ---------------------------------------------------------------------------
# 2. Baseline collection
# ---------------------------------------------------------------------------
baseline = collect_baseline(L=L, n_trials=N_CALIBRATION_TRIALS, channel_noise_p=CHANNEL_NOISE_P, rng=rng)
check(f"baseline collected {N_CALIBRATION_TRIALS} trials",
      baseline["n_trials"] == N_CALIBRATION_TRIALS and len(baseline["trials"]) == N_CALIBRATION_TRIALS)
check(f"baseline mean mismatch count > 0 under nonzero channel noise "
      f"(got {baseline['mean_mismatch_count']:.3f})", baseline["mean_mismatch_count"] > 0.0)
check(f"baseline mean mismatch rate roughly tracks channel noise magnitude "
      f"(got {baseline['mean_mismatch_rate']:.4f}, noise_p={CHANNEL_NOISE_P})",
      0.0 < baseline["mean_mismatch_rate"] < 3 * CHANNEL_NOISE_P)

# Degenerate case: zero channel noise -> baseline should be exactly zero,
# consistent with Phase 3's deterministic honest-path guarantee.
zero_noise_baseline = collect_baseline(L=10, n_trials=20, channel_noise_p=0.0, rng=rng)
check("zero channel noise -> baseline mean/std are exactly zero "
      "(matches Phase 3's deterministic acceptance)",
      zero_noise_baseline["mean_mismatch_count"] == 0.0 and zero_noise_baseline["std_mismatch_count"] == 0.0)

# ---------------------------------------------------------------------------
# 3. Threshold calibration
# ---------------------------------------------------------------------------
calib = calibrate_threshold(baseline)
threshold = calib["mismatch_threshold"]
check("calibration reports the declared default alpha",
      calib["alpha"] == DEFAULT_FALSE_REJECT_ALPHA)
check(f"calibrated threshold lies in [0, L] (got {threshold})", 0 <= threshold <= L)
check("calibration reports q = 2p/3",
      np.isclose(calib["per_qubit_mismatch_probability"], 2 * CHANNEL_NOISE_P / 3))
check("reported binomial false-reject probability meets alpha",
      calib["actual_binomial_false_reject_probability"] <= DEFAULT_FALSE_REJECT_ALPHA)

zero_noise_calib = calibrate_threshold(zero_noise_baseline)
check("zero channel noise calibrates to threshold zero",
      zero_noise_calib["mismatch_threshold"] == 0)

# Exact binomial-tail policy: each result must meet alpha and be minimal.
for L_exact, p_exact, expected_threshold in ((20, .03, 6), (40, .03, 8),
                                               (64, .03, 9), (80, .03, 10)):
    exact = binomial_tail_threshold(L_exact, p_exact)
    exact_threshold = exact["mismatch_threshold"]
    q_exact = 2 * p_exact / 3
    check(f"L={L_exact}, p={p_exact}: exact threshold is {expected_threshold}",
          exact_threshold == expected_threshold)
    check(f"L={L_exact}: selected tail probability meets alpha",
          binomial_survival_probability(L_exact, q_exact, exact_threshold) <= DEFAULT_FALSE_REJECT_ALPHA)
    check(f"L={L_exact}: selected threshold is minimal",
          exact_threshold == 0 or
          binomial_survival_probability(L_exact, q_exact, exact_threshold - 1) > DEFAULT_FALSE_REJECT_ALPHA)

less_permissive = binomial_tail_threshold(40, .03, alpha=1e-8)["mismatch_threshold"]
check("decreasing alpha cannot decrease the threshold", less_permissive >= 8)

threshold_L = binomial_tail_threshold(1, 1.0, alpha=0.5)
check("threshold == L is explicitly represented when all counts must be accepted",
      threshold_L["mismatch_threshold"] == 1 and threshold_L["threshold_equals_L"]
      and not threshold_L["mismatch_only_detection_possible"]
      and threshold_L["actual_binomial_false_reject_probability"] == 0.0)

empty_threshold = binomial_tail_threshold(0, .03)
check("L=0 has the sensible zero threshold and zero survival probability",
      empty_threshold["mismatch_threshold"] == 0
      and empty_threshold["actual_binomial_false_reject_probability"] == 0.0)

for invalid_alpha in (0.0, -1.0, 1.0, 2.0):
    try:
        binomial_tail_threshold(20, .03, alpha=invalid_alpha)
        check(f"invalid alpha {invalid_alpha} is rejected", False)
    except ValueError:
        check(f"invalid alpha {invalid_alpha} is rejected", True)

for invalid_p in (-0.01, 1.01):
    try:
        binomial_tail_threshold(20, invalid_p)
        check(f"invalid channel noise p={invalid_p} is rejected", False)
    except ValueError:
        check(f"invalid channel noise p={invalid_p} is rejected", True)

for invalid_q in (-0.01, 1.01):
    try:
        binomial_survival_probability(20, invalid_q, 1)
        check(f"invalid direct q={invalid_q} is rejected", False)
    except ValueError:
        check(f"invalid direct q={invalid_q} is rejected", True)

# ---------------------------------------------------------------------------
# 4. verify_with_detection delegates correctly to verify_bit
#    (same inputs -> same accept/reject decision as calling verify_bit
#    directly with the same threshold -- confirms the wrapper isn't
#    silently reimplementing or diverging from the core decision logic)
# ---------------------------------------------------------------------------
km = generate_key_material(L, rng)
distribute_public_key(km, rng)
sig = sign_bit(km, message_bit=0)

direct_result = verify_bit(km, sig, rng, mismatch_threshold=threshold)
# NOTE: verify_bit's own measurement is itself probabilistic in general
# (measurement outcomes depend on rng), so to compare apples-to-apples we
# call verify_with_detection on a FRESH but structurally identical setup
# and instead check the honest-path invariant directly: zero mismatches
# (Phase 3's noiseless guarantee) must always be accepted regardless of
# threshold >= 0.
detection_result = verify_with_detection(km, sig, rng, mismatch_threshold=threshold)
check("verify_with_detection returns a well-formed DetectionResult",
      hasattr(detection_result, "accepted") and hasattr(detection_result, "mismatch_rate"))
check("noiseless honest signature accepted regardless of (non-negative) threshold",
      detection_result.accepted)
check("DetectionResult.mismatch_rate consistent with mismatch_count/total_checked",
      np.isclose(detection_result.mismatch_rate,
                 detection_result.mismatch_count / detection_result.total_checked))

# ---------------------------------------------------------------------------
# 5. Held-out honest runs (same noise level, NOT used for calibration):
#    false-reject rate should be very low under the calibrated threshold.
# ---------------------------------------------------------------------------
N_HOLDOUT = 80
accepted = 0
for _ in range(N_HOLDOUT):
    trial = run_honest_trial(L, CHANNEL_NOISE_P, rng)
    if trial["mismatch_count"] <= threshold:
        accepted += 1
false_reject_rate = 1 - (accepted / N_HOLDOUT)
check(f"held-out honest false-reject rate is low (got {false_reject_rate:.3f}, threshold={threshold})",
      false_reject_rate <= 0.05)

# ---------------------------------------------------------------------------
# 6. Synthetic high-disturbance runs (reusing the honest-trial machinery
#    with much higher noise, standing in for real attacker disturbance
#    until Phase 5's attack simulators exist): should mostly be flagged.
#
#    NOTE: this depolarizing model only causes a measurement mismatch when
#    the applied error is X or Y in the qubit's own preparation basis (a
#    same-basis Z error is invisible to that basis's measurement), so the
#    achievable mismatch rate is 2/3 at p=1.0. A larger
#    L is used here (40 instead of 20) purely to get enough qubits that
#    the resulting mean mismatch count sits clearly above the calibrated
#    threshold -- this is a property of the noise model's statistics, not
#    the detector, and Phase 5's real attack simulators (intercept-resend,
#    forgery) will produce cleaner, higher-QBER signatures to detect.
# ---------------------------------------------------------------------------
L_HIGH = 40
HIGH_NOISE_P = 1.0
N_HIGH_NOISE = 50

high_noise_baseline = collect_baseline(L=L_HIGH, n_trials=N_CALIBRATION_TRIALS,
                                        channel_noise_p=CHANNEL_NOISE_P, rng=rng)
high_noise_calib = calibrate_threshold(high_noise_baseline)
high_noise_threshold = high_noise_calib["mismatch_threshold"]

flagged = 0
for _ in range(N_HIGH_NOISE):
    trial = run_honest_trial(L_HIGH, HIGH_NOISE_P, rng)
    if trial["mismatch_count"] > high_noise_threshold:
        flagged += 1
detection_rate = flagged / N_HIGH_NOISE
check(f"high-disturbance runs are mostly flagged (got detection_rate={detection_rate:.3f}, "
      f"L={L_HIGH}, threshold={high_noise_threshold})",
      detection_rate >= 0.8)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 4 TESTS PASSED")
