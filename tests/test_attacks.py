"""
tests/test_attacks.py

Phase 5 validation. Run after tests/test_detector.py passes.
If anything here fails, do not proceed to Phase 6 -- fix
attacks/intercept_resend.py, attacks/forgery.py, attacks/impersonation.py,
or attacks/replay.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.qds_protocol import (
    generate_key_material, distribute_public_key, sign_bit, verify_bit,
)
from attacks.intercept_resend import intercept_resend_attack, expected_mismatch_rate
from attacks.forgery import (
    blind_forgery_attempt, intercepting_forgery_attempt,
    BLIND_FORGE_SUCCESS_PROB, INTERCEPT_FORGE_SUCCESS_PROB,
)
from attacks.impersonation import impersonation_attack, ImpersonationAttempt
from attacks.replay import naive_replay, key_reuse_attack, KeyReuseExposure

rng = np.random.default_rng(555)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Intercept-resend: sanity on a single qubit, many trials, tallied by
#    whether Esha guessed the basis correctly -- confirms the two-branch
#    analysis in the module docstring, not just the aggregate number.
# ---------------------------------------------------------------------------
N1 = 30000
same_basis_mismatches = 0
same_basis_count = 0
diff_basis_mismatches = 0
diff_basis_count = 0

for _ in range(N1):
    km = generate_key_material(1, rng)
    distribute_public_key(km, rng)
    logs = intercept_resend_attack(km, rng, intercept_prob=1.0)
    log = logs[0]  # key_set_0's single qubit
    sig = sign_bit(km, message_bit=0)  # honest disclosure of Aditi's TRUE description
    result = verify_bit(km, sig, rng, mismatch_threshold=0)
    mismatched = result.mismatch_count == 1
    if log.basis_guessed_correctly:
        same_basis_count += 1
        same_basis_mismatches += mismatched
    else:
        diff_basis_count += 1
        diff_basis_mismatches += mismatched

same_basis_rate = same_basis_mismatches / same_basis_count
diff_basis_rate = diff_basis_mismatches / diff_basis_count
overall_rate = (same_basis_mismatches + diff_basis_mismatches) / N1

check(f"Esha guesses basis correctly ~1/3 of the time (got {same_basis_count / N1:.3f})",
      abs(same_basis_count / N1 - 1 / 3) < 0.02)
check(f"Same-basis interception introduces ~0 mismatch (got {same_basis_rate:.4f})",
      same_basis_rate < 0.02)
check(f"Different-basis interception introduces ~50% mismatch (got {diff_basis_rate:.4f})",
      abs(diff_basis_rate - 0.5) < 0.03)
check(f"Overall intercept-resend mismatch rate matches analytic 1/3 "
      f"(got {overall_rate:.4f}, expected {expected_mismatch_rate():.4f})",
      abs(overall_rate - expected_mismatch_rate()) < 0.02)

# ---------------------------------------------------------------------------
# 2. Intercept-resend: intercept_prob < 1.0 leaves some qubits untouched
# ---------------------------------------------------------------------------
km_partial = generate_key_material(200, rng)
distribute_public_key(km_partial, rng)
logs_partial = intercept_resend_attack(km_partial, rng, intercept_prob=0.4)
check(f"intercept_prob=0.4 intercepts roughly 40% of 400 qubits "
      f"(got {len(logs_partial)}/400)",
      abs(len(logs_partial) / 400 - 0.4) < 0.08)

try:
    intercept_resend_attack(km_partial, rng, intercept_prob=1.5)
    check("intercept_resend_attack rejects intercept_prob outside [0,1]", False)
except ValueError:
    check("intercept_resend_attack rejects intercept_prob outside [0,1]", True)

try:
    fresh_km = generate_key_material(4, rng)
    intercept_resend_attack(fresh_km, rng)  # not yet distributed
    check("intercept_resend_attack raises if public key was never distributed", False)
except ValueError:
    check("intercept_resend_attack raises if public key was never distributed", True)

# ---------------------------------------------------------------------------
# 3. Intercept-resend attack is caught by the Phase 4 detector: run a
#    calibrated detector against honest baseline noise, then confirm
#    intercepted key material's mismatch rate sits far above threshold.
# ---------------------------------------------------------------------------
from detection.baseline import collect_baseline
from detection.thresholds import calibrate_threshold

L_DET = 40
honest_baseline = collect_baseline(L=L_DET, n_trials=100, channel_noise_p=0.03, rng=rng)
calib = calibrate_threshold(honest_baseline)
threshold = calib["mismatch_threshold"]

N_ATTACK_TRIALS = 40
flagged = 0
for _ in range(N_ATTACK_TRIALS):
    km_attack = generate_key_material(L_DET, rng)
    distribute_public_key(km_attack, rng)
    intercept_resend_attack(km_attack, rng, intercept_prob=1.0)
    sig = sign_bit(km_attack, message_bit=0)
    result = verify_bit(km_attack, sig, rng, mismatch_threshold=0)
    if result.mismatch_count > threshold:
        flagged += 1

detection_rate = flagged / N_ATTACK_TRIALS
check(f"Phase 4 detector flags full intercept-resend attacks at L={L_DET} "
      f"(got detection_rate={detection_rate:.3f}, threshold={threshold})",
      detection_rate >= 0.95)

# ---------------------------------------------------------------------------
# 4. Blind forgery: per-qubit success rate matches the CORRECTED 1/2
#    bound (not the wrong 1/6 originally in the Phase 3 docstring).
# ---------------------------------------------------------------------------
N4 = 40000
blind_successes = 0
for _ in range(N4):
    km = generate_key_material(1, rng)
    distribute_public_key(km, rng)
    sig = blind_forgery_attempt(L=1, message_bit=0, rng=rng)
    result = verify_bit(km, sig, rng, mismatch_threshold=0)
    blind_successes += result.accepted

blind_rate = blind_successes / N4
check(f"Blind forger per-qubit success rate matches corrected bound "
      f"(got {blind_rate:.4f}, expected {BLIND_FORGE_SUCCESS_PROB:.4f}, NOT the wrong 1/6={1/6:.4f})",
      abs(blind_rate - BLIND_FORGE_SUCCESS_PROB) < 0.02)

# Full-key-set forgery probability should shrink like (1/2)^L, and be
# utterly negligible for realistic L -- confirms the bound composes
# correctly across qubits, not just per-qubit.
L_FORGE = 24
N_FULL_FORGE_TRIALS = 4000
full_forge_successes = 0
for _ in range(N_FULL_FORGE_TRIALS):
    km = generate_key_material(L_FORGE, rng)
    distribute_public_key(km, rng)
    sig = blind_forgery_attempt(L=L_FORGE, message_bit=0, rng=rng)
    result = verify_bit(km, sig, rng, mismatch_threshold=0)
    full_forge_successes += result.accepted

check(f"Full L={L_FORGE}-qubit blind forgery essentially never succeeds "
      f"(got {full_forge_successes}/{N_FULL_FORGE_TRIALS}, "
      f"expected rate ~{BLIND_FORGE_SUCCESS_PROB ** L_FORGE:.2e})",
      full_forge_successes == 0)

# ---------------------------------------------------------------------------
# 5. Intercepting forgery: succeeds with probability 1.0, independent of
#    basis choice and independent of L -- the more serious finding.
# ---------------------------------------------------------------------------
N5 = 5000
intercept_forge_successes = 0
for _ in range(N5):
    km = generate_key_material(1, rng)
    distribute_public_key(km, rng)
    sig = intercepting_forgery_attempt(km, message_bit=0, rng=rng)
    result = verify_bit(km, sig, rng, mismatch_threshold=0)
    intercept_forge_successes += result.accepted

intercept_forge_rate = intercept_forge_successes / N5
check(f"Intercepting forger succeeds essentially always "
      f"(got rate={intercept_forge_rate:.4f}, expected {INTERCEPT_FORGE_SUCCESS_PROB})",
      intercept_forge_rate > 0.999)

# Confirm L-independence directly: even a large key set is forged with
# certainty, unlike blind forgery which collapses to ~0 at this L.
L_LARGE = 30
km_large = generate_key_material(L_LARGE, rng)
distribute_public_key(km_large, rng)
sig_large = intercepting_forgery_attempt(km_large, message_bit=0, rng=rng)
result_large = verify_bit(km_large, sig_large, rng, mismatch_threshold=0)
check(f"Intercepting forger succeeds at large L={L_LARGE} too (L-independent break)",
      result_large.accepted and result_large.mismatch_count == 0)

# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------
try:
    blind_forgery_attempt(L=5, message_bit=2, rng=rng)
    check("blind_forgery_attempt rejects invalid message_bit", False)
except ValueError:
    check("blind_forgery_attempt rejects invalid message_bit", True)

try:
    km_undist = generate_key_material(4, rng)
    intercepting_forgery_attempt(km_undist, message_bit=0, rng=rng)
    check("intercepting_forgery_attempt raises if public key was never distributed", False)
except ValueError:
    check("intercepting_forgery_attempt raises if public key was never distributed", True)

# ---------------------------------------------------------------------------
# 7. Impersonation: Meera runs the entire honest protocol herself and
#    presents the result as Aditi's. Should be accepted with certainty,
#    with ZERO mismatches (it's an honest run, just from the wrong
#    identity) -- no amount of L or threshold tuning matters here.
# ---------------------------------------------------------------------------
N7 = 300
impersonation_successes = 0
for _ in range(N7):
    attempt = impersonation_attack(L=12, message_bit=0, rng=rng)
    check_result = verify_bit(attempt.forged_key_material, attempt.forged_signature, rng,
                               mismatch_threshold=0)
    if check_result.accepted and check_result.mismatch_count == 0:
        impersonation_successes += 1

check(f"Impersonation succeeds with certainty across {N7} trials "
      f"(got {impersonation_successes}/{N7})",
      impersonation_successes == N7)

impersonation_large_L = impersonation_attack(L=100, message_bit=1, rng=rng)
check("impersonation_attack returns an ImpersonationAttempt instance",
      isinstance(impersonation_large_L, ImpersonationAttempt))
result_large_L = verify_bit(impersonation_large_L.forged_key_material,
                             impersonation_large_L.forged_signature, rng, mismatch_threshold=0)
check("Impersonation succeeds at large L=100 too (confirms L-independence)",
      result_large_L.accepted and result_large_L.mismatch_count == 0)

try:
    impersonation_attack(L=5, message_bit=7, rng=rng)
    check("impersonation_attack rejects invalid message_bit", False)
except ValueError:
    check("impersonation_attack rejects invalid message_bit", True)

# ---------------------------------------------------------------------------
# 8. Naive replay: resubmitting a captured, already-used signature
#    against the same key_material succeeds again, every time -- no
#    freshness/nonce check exists to stop it.
# ---------------------------------------------------------------------------
km_replay = generate_key_material(16, rng)
distribute_public_key(km_replay, rng)
original_sig = sign_bit(km_replay, message_bit=0)
original_result = verify_bit(km_replay, original_sig, rng, mismatch_threshold=0)
check("Original signature is honestly accepted before any replay",
      original_result.accepted and original_result.mismatch_count == 0)

N8 = 20
replay_successes = 0
for _ in range(N8):
    replay_result = naive_replay(km_replay, original_sig, rng)
    if replay_result.accepted and replay_result.mismatch_count == 0:
        replay_successes += 1

check(f"The SAME captured signature is accepted on every resubmission "
      f"(got {replay_successes}/{N8} replays accepted, expect all)",
      replay_successes == N8)

# ---------------------------------------------------------------------------
# 9. Key reuse: signing BOTH message bits with the same key_material
#    exposes the COMPLETE private description of both key sets --
#    total, not probabilistic, compromise.
# ---------------------------------------------------------------------------
km_reuse = generate_key_material(20, rng)
distribute_public_key(km_reuse, rng)
exposure = key_reuse_attack(km_reuse, rng)
check("key_reuse_attack returns a KeyReuseExposure instance",
      isinstance(exposure, KeyReuseExposure))

check("Key-reuse exposure captured a full-length key_set_0 description",
      len(exposure.key_set_0_descriptions) == 20)
check("Key-reuse exposure captured a full-length key_set_1 description",
      len(exposure.key_set_1_descriptions) == 20)
check("Key-reuse exposure reports itself as fully exposed",
      exposure.fully_exposed())

# The exposed descriptions must be the TRUE secret descriptions (not
# some placeholder) -- confirm they match key_material's own private
# fields exactly, which an honest disclosure necessarily reveals.
true_key_set_0 = [(kq.basis, kq.eigen) for kq in km_reuse.key_set_0]
true_key_set_1 = [(kq.basis, kq.eigen) for kq in km_reuse.key_set_1]
check("Exposed key_set_0 descriptions exactly match Aditi's true private key_set_0",
      exposure.key_set_0_descriptions == true_key_set_0)
check("Exposed key_set_1 descriptions exactly match Aditi's true private key_set_1",
      exposure.key_set_1_descriptions == true_key_set_1)

# Both captured signatures should themselves have been honestly valid at
# the time they were issued (this is what makes the exposure realistic:
# nothing about either individual signature looked wrong).
result_sig0 = verify_bit(km_reuse, exposure.sig_bit_0, rng, mismatch_threshold=0)
result_sig1 = verify_bit(km_reuse, exposure.sig_bit_1, rng, mismatch_threshold=0)
check("Both reused-key signatures were individually valid, honest signatures",
      result_sig0.accepted and result_sig1.accepted
      and result_sig0.mismatch_count == 0 and result_sig1.mismatch_count == 0)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 5 TESTS PASSED")
