"""
tests/test_teleportation.py

Phase 2 validation. Run after tests/test_entanglement.py passes.
If anything here fails, do not proceed to Phase 3 -- fix teleportation.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.primitives import (
    KET_0, KET_1, single_qubit_state, apply_single_qubit_gate, HADAMARD,
    is_normalized,
)
from core.teleportation import teleport_qubit, required_correction

rng = np.random.default_rng(123)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Teleport basis states |0> and |1>
# ---------------------------------------------------------------------------
result0 = teleport_qubit(KET_0, rng)
check(f"Teleporting |0> succeeds with fidelity 1.0 (got {result0['fidelity']:.6f})",
      np.isclose(result0["fidelity"], 1.0))

result1 = teleport_qubit(KET_1, rng)
check(f"Teleporting |1> succeeds with fidelity 1.0 (got {result1['fidelity']:.6f})",
      np.isclose(result1["fidelity"], 1.0))

# ---------------------------------------------------------------------------
# 2. Teleport |+> and |->
# ---------------------------------------------------------------------------
plus = apply_single_qubit_gate(KET_0, HADAMARD, target=0, n_qubits=1)
result_plus = teleport_qubit(plus, rng)
check(f"Teleporting |+> succeeds with fidelity 1.0 (got {result_plus['fidelity']:.6f})",
      np.isclose(result_plus["fidelity"], 1.0))

# ---------------------------------------------------------------------------
# 3. Teleport many RANDOM single-qubit states -- this is the real test.
#    A protocol that only works for basis states could still be broken for
#    general superpositions; teleportation's whole point is that it must
#    work for an UNKNOWN, arbitrary state.
# ---------------------------------------------------------------------------
n_random_trials = 200
random_fidelities = []
for _ in range(n_random_trials):
    theta = rng.uniform(0, np.pi)
    phi = rng.uniform(0, 2 * np.pi)
    psi = single_qubit_state(theta, phi)
    result = teleport_qubit(psi, rng)
    random_fidelities.append(result["fidelity"])

min_fidelity = min(random_fidelities)
check(f"All {n_random_trials} random-state teleportations have fidelity 1.0 "
      f"(minimum observed: {min_fidelity:.10f})",
      min_fidelity > 1 - 1e-8)

# ---------------------------------------------------------------------------
# 4. Confirm ALL FOUR measurement-outcome branches are exercised and each
#    is corrected properly. If the correction logic were wrong for even
#    one of the four (m_A, m_B) combinations, this would show up as a
#    subset of trials in test #3 having imperfect fidelity while others
#    are fine. Explicitly bucket by outcome to make this visible.
# ---------------------------------------------------------------------------
psi_fixed = single_qubit_state(theta=1.1, phi=2.3)  # arbitrary fixed test state
fidelity_by_branch = {}
attempts = 0
while len(fidelity_by_branch) < 4 and attempts < 5000:
    result = teleport_qubit(psi_fixed, rng)
    bits = result["classical_bits"]
    fidelity_by_branch[bits] = result["fidelity"]
    attempts += 1

check(f"All 4 measurement-outcome branches observed within {attempts} trials",
      len(fidelity_by_branch) == 4)
for bits, fid in sorted(fidelity_by_branch.items()):
    check(f"Branch (m_A={bits[0]}, m_B={bits[1]}), correction={required_correction(*bits)}: "
          f"fidelity 1.0 (got {fid:.10f})", np.isclose(fid, 1.0))

# ---------------------------------------------------------------------------
# 5. received_state is always normalized (sanity check on the extraction
#    + correction pipeline, independent of the fidelity comparison above)
# ---------------------------------------------------------------------------
all_normalized = all(
    is_normalized(teleport_qubit(single_qubit_state(rng.uniform(0, np.pi),
                                                      rng.uniform(0, 2 * np.pi)), rng)
                   ["received_state"])
    for _ in range(20)
)
check("Teleported states are always properly normalized", all_normalized)

# ---------------------------------------------------------------------------
# 6. Classical bits are genuinely random-ish (each near 50/50) for a
#    generic input state -- a sanity check that measurement isn't
#    silently biased or broken in a way that happens to still give
#    fidelity 1.0 by coincidence.
# ---------------------------------------------------------------------------
bits_a = []
bits_b = []
for _ in range(2000):
    result = teleport_qubit(plus, rng)
    m_a, m_b = result["classical_bits"]
    bits_a.append(m_a)
    bits_b.append(m_b)

frac_a = np.mean(bits_a)
frac_b = np.mean(bits_b)
check(f"Classical bit m_A is ~50/50 across trials (got {frac_a:.3f})",
      abs(frac_a - 0.5) < 0.05)
check(f"Classical bit m_B is ~50/50 across trials (got {frac_b:.3f})",
      abs(frac_b - 0.5) < 0.05)

# ---------------------------------------------------------------------------
# 7. required_correction() sanity checks
# ---------------------------------------------------------------------------
check("required_correction(0,0) is identity", required_correction(0, 0).startswith("I"))
check("required_correction(1,0) is Z only", required_correction(1, 0) == "Z")
check("required_correction(0,1) is X only", required_correction(0, 1) == "X")
check("required_correction(1,1) is X then Z", required_correction(1, 1) == "X then Z")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 2 TESTS PASSED")
