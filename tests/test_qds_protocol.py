"""
tests/test_qds_protocol.py

Phase 3 validation. Run after tests/test_teleportation.py passes.
If anything here fails, do not proceed to Phase 4 -- fix qds_protocol.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.qds_protocol import (
    generate_key_material, distribute_public_key, sign_bit, verify_bit,
    DEFAULT_BASES, SignatureBit,
)
from core.primitives import prepare_pauli_eigenstate, state_fidelity

rng = np.random.default_rng(99)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# Use a modest L for test speed; each key qubit costs one full teleportation.
L = 8

# ---------------------------------------------------------------------------
# 1. Key generation produces the right shape and valid descriptions
# ---------------------------------------------------------------------------
key_material = generate_key_material(L, rng)
check(f"key_set_0 has length {L}", len(key_material.key_set_0) == L)
check(f"key_set_1 has length {L}", len(key_material.key_set_1) == L)

all_bases_valid = all(
    kq.basis in DEFAULT_BASES and kq.eigen in (0, 1)
    for key_set in (key_material.key_set_0, key_material.key_set_1)
    for kq in key_set
)
check("All key qubits have valid (basis, eigen) descriptions", all_bases_valid)

check("bharat_state is None before distribution",
      all(kq.bharat_state is None for kq in key_material.key_set_0))

# ---------------------------------------------------------------------------
# 2. Public key distribution (teleportation) delivers perfect fidelity
# ---------------------------------------------------------------------------
distribute_public_key(key_material, rng)

all_have_states = all(
    kq.bharat_state is not None
    for key_set in (key_material.key_set_0, key_material.key_set_1)
    for kq in key_set
)
check("All key qubits have bharat_state after distribution", all_have_states)

fidelities = [
    kq.teleport_fidelity
    for key_set in (key_material.key_set_0, key_material.key_set_1)
    for kq in key_set
]
min_fid = min(fidelities)
check(f"All {len(fidelities)} teleported key qubits have fidelity 1.0 "
      f"(minimum observed: {min_fid:.10f})", min_fid > 1 - 1e-8)

# ---------------------------------------------------------------------------
# 3. Honest signing + verification: signing bit 0 and verifying against
#    bit 0 always accepts, with ZERO mismatches (deterministic acceptance,
#    per the project's stated objective)
# ---------------------------------------------------------------------------
sig0 = sign_bit(key_material, message_bit=0)
check("Signature for bit 0 discloses L descriptions",
      len(sig0.disclosed_descriptions) == L)

result0 = verify_bit(key_material, sig0, rng)
check(f"Honest signature for bit 0 is accepted (mismatches={result0.mismatch_count})",
      result0.accepted)
check("Honest signature for bit 0 has ZERO mismatches (deterministic verification)",
      result0.mismatch_count == 0)

# ---------------------------------------------------------------------------
# 4. Same, for message bit 1, on FRESH key material (each bit's key
#    material is one-time-use, per protocol design)
# ---------------------------------------------------------------------------
key_material_2 = generate_key_material(L, rng)
distribute_public_key(key_material_2, rng)
sig1 = sign_bit(key_material_2, message_bit=1)
result1 = verify_bit(key_material_2, sig1, rng)
check(f"Honest signature for bit 1 is accepted (mismatches={result1.mismatch_count})",
      result1.accepted)
check("Honest signature for bit 1 has ZERO mismatches", result1.mismatch_count == 0)

# ---------------------------------------------------------------------------
# 5. Repeat across many independent random trials and both message bits,
#    to make sure zero-mismatch acceptance isn't a coincidence of one
#    particular random seed / key material instance.
# ---------------------------------------------------------------------------
n_trials = 15
all_deterministic = True
for trial in range(n_trials):
    bit_to_sign = trial % 2
    km = generate_key_material(L, rng)
    distribute_public_key(km, rng)
    sig = sign_bit(km, message_bit=bit_to_sign)
    result = verify_bit(km, sig, rng)
    if result.mismatch_count != 0 or not result.accepted:
        all_deterministic = False
        print(f"    (trial {trial}, bit={bit_to_sign}: "
              f"mismatches={result.mismatch_count}, accepted={result.accepted})")

check(f"All {n_trials} independent honest sign/verify trials are deterministic "
      f"(zero mismatches, always accepted)", all_deterministic)

# ---------------------------------------------------------------------------
# 6. Verification persists physical measurement collapse. Measure a
# Z-prepared state in X, then verify again in the measured X basis. The
# second verification must use the stored collapsed state, not the
# original Z state.
# ---------------------------------------------------------------------------
lifecycle_km = generate_key_material(1, rng, bases_pool=("Z",))
distribute_public_key(lifecycle_km, rng)
lifecycle_qubit = lifecycle_km.key_set_0[0]
pre_measurement_state = lifecycle_qubit.bharat_state.copy()
first_lifecycle_signature = SignatureBit(message_bit=0, disclosed_descriptions=[("X", 0)])
first_lifecycle_result = verify_bit(lifecycle_km, first_lifecycle_signature, rng)
first_outcome = first_lifecycle_result.per_qubit_outcomes[0][0]
expected_collapsed_state = prepare_pauli_eigenstate("X", first_outcome)

check("verification persists the observed X-basis collapsed state",
      state_fidelity(lifecycle_qubit.bharat_state, expected_collapsed_state) > 1 - 1e-8)
check("verification changes the stored state after an incompatible-basis measurement",
      state_fidelity(lifecycle_qubit.bharat_state, pre_measurement_state) < 1 - 1e-8)

second_lifecycle_signature = SignatureBit(
    message_bit=0, disclosed_descriptions=[("X", first_outcome)]
)
second_lifecycle_result = verify_bit(lifecycle_km, second_lifecycle_signature, rng)
check("a second X-basis verification uses the already-collapsed state",
      second_lifecycle_result.accepted
      and second_lifecycle_result.per_qubit_outcomes[0][0] == first_outcome)

# ---------------------------------------------------------------------------
# 7. Sanity check that verification is NOT vacuous: tampering with a
#    disclosed eigenvalue must be detected as a mismatch. This is a basic
#    arithmetic sanity check on verify_bit itself -- NOT a real attack
#    simulator (that is Phase 5's job) -- just confirming the comparison
#    logic actually distinguishes correct from incorrect disclosures.
# ---------------------------------------------------------------------------
km_tamper = generate_key_material(L, rng)
distribute_public_key(km_tamper, rng)
sig_honest = sign_bit(km_tamper, message_bit=0)

# Flip the first disclosed eigenvalue to simulate a corrupted/incorrect
# disclosure, holding the basis fixed.
tampered_descriptions = list(sig_honest.disclosed_descriptions)
basis0, eigen0 = tampered_descriptions[0]
tampered_descriptions[0] = (basis0, 1 - eigen0)
from core.qds_protocol import SignatureBit
sig_tampered = SignatureBit(message_bit=0, disclosed_descriptions=tampered_descriptions)

result_tampered = verify_bit(km_tamper, sig_tampered, rng)
check(f"Tampering with one disclosed eigenvalue is detected as a mismatch "
      f"(mismatches={result_tampered.mismatch_count}, expected >= 1)",
      result_tampered.mismatch_count >= 1)
check("Tampered signature is rejected under threshold=0",
      not result_tampered.accepted)

# ---------------------------------------------------------------------------
# 8. Error handling: signing an invalid message bit raises
# ---------------------------------------------------------------------------
try:
    sign_bit(key_material, message_bit=2)
    check("sign_bit rejects invalid message_bit", False)
except ValueError:
    check("sign_bit rejects invalid message_bit", True)

# ---------------------------------------------------------------------------
# 9. Error handling: verifying before distribution raises a clear error
# ---------------------------------------------------------------------------
km_undistributed = generate_key_material(L, rng)
sig_undistributed = sign_bit(km_undistributed, message_bit=0)
try:
    verify_bit(km_undistributed, sig_undistributed, rng)
    check("verify_bit raises if public key was never distributed", False)
except ValueError:
    check("verify_bit raises if public key was never distributed", True)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 3 TESTS PASSED")
