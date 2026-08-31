"""
tests/test_primitives.py

Phase 0 validation. Run this before writing any Phase 1 code.
If anything here fails, do not proceed -- fix primitives.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.primitives import (
    KET_0, KET_1, PAULI_X, PAULI_Y, PAULI_Z, HADAMARD, CNOT,
    is_unitary, zero_state, single_qubit_state, is_normalized,
    apply_single_qubit_gate, apply_two_qubit_gate,
    measurement_probabilities, measure_qubit, measure_qubit_in_basis,
    state_fidelity,
)

rng = np.random.default_rng(42)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Gate matrices are valid (unitary)
# ---------------------------------------------------------------------------
check("Pauli X is unitary", is_unitary(PAULI_X))
check("Pauli Y is unitary", is_unitary(PAULI_Y))
check("Pauli Z is unitary", is_unitary(PAULI_Z))
check("Hadamard is unitary", is_unitary(HADAMARD))
check("CNOT is unitary", is_unitary(CNOT))

# ---------------------------------------------------------------------------
# 2. Basic state construction
# ---------------------------------------------------------------------------
psi0 = zero_state(1)
check("zero_state(1) equals |0>", np.allclose(psi0, KET_0))

psi00 = zero_state(2)
check("zero_state(2) has norm 1", is_normalized(psi00))
check("zero_state(2) equals |00>", np.allclose(psi00, [1, 0, 0, 0]))

# ---------------------------------------------------------------------------
# 3. Single-qubit gate application
# ---------------------------------------------------------------------------
# X|0> = |1>
after_x = apply_single_qubit_gate(KET_0, PAULI_X, target=0, n_qubits=1)
check("X|0> = |1>", np.allclose(after_x, KET_1))

# H|0> = (|0>+|1>)/sqrt(2)
after_h = apply_single_qubit_gate(KET_0, HADAMARD, target=0, n_qubits=1)
expected_plus = np.array([1, 1]) / np.sqrt(2)
check("H|0> = |+>", np.allclose(after_h, expected_plus))

# Apply X to qubit 1 of a 2-qubit |00> register -> should give |10>... need
# to confirm indexing convention: qubit 0 = rightmost bit.
after_x_q1 = apply_single_qubit_gate(zero_state(2), PAULI_X, target=1, n_qubits=2)
# basis order |q1 q0>: index 2 = binary 10 = q1=1, q0=0
expected = np.zeros(4, dtype=complex)
expected[2] = 1.0
check("X on qubit 1 of |00> flips the correct bit", np.allclose(after_x_q1, expected))

# ---------------------------------------------------------------------------
# 4. Two-qubit gate application: build a Bell pair with H + CNOT
# ---------------------------------------------------------------------------
state = zero_state(2)
state = apply_single_qubit_gate(state, HADAMARD, target=0, n_qubits=2)
state = apply_two_qubit_gate(state, CNOT, qubits=(0, 1), n_qubits=2)
# Expect (|00> + |11>) / sqrt(2)
expected_bell = np.zeros(4, dtype=complex)
expected_bell[0] = 1 / np.sqrt(2)   # |00>
expected_bell[3] = 1 / np.sqrt(2)   # |11>
check("H(q0) + CNOT(0->1) on |00> gives Bell state |Phi+>", np.allclose(state, expected_bell))
check("Bell state is normalized", is_normalized(state))

# ---------------------------------------------------------------------------
# 5. Measurement probabilities and statistics
# ---------------------------------------------------------------------------
probs = measurement_probabilities(state)
check("Bell state measurement probs are [0.5, 0, 0, 0.5]",
      np.allclose(probs, [0.5, 0, 0, 0.5]))

# Measure qubit 0 many times on a fresh |+> state: should split ~50/50
plus_state = apply_single_qubit_gate(zero_state(1), HADAMARD, target=0, n_qubits=1)
outcomes = []
for _ in range(2000):
    outcome, _ = measure_qubit(plus_state.copy(), target=0, n_qubits=1, rng=rng)
    outcomes.append(outcome)
frac_ones = np.mean(outcomes)
check(f"Z-measurement of |+> is ~50/50 (got {frac_ones:.3f})", abs(frac_ones - 0.5) < 0.05)

# ---------------------------------------------------------------------------
# 6. Measurement in Pauli eigenbases
# ---------------------------------------------------------------------------
# |+> measured in the X basis should be deterministic (always 0, by convention)
x_outcomes = []
for _ in range(500):
    outcome, _ = measure_qubit_in_basis(plus_state.copy(), target=0, n_qubits=1,
                                         basis="X", rng=rng)
    x_outcomes.append(outcome)
check("Measuring |+> in X-basis is deterministic", len(set(x_outcomes)) == 1)

# |0> measured in the X basis should be ~50/50 (since |0> is an equal
# superposition of |+> and |->)
z0_outcomes = []
for _ in range(2000):
    outcome, _ = measure_qubit_in_basis(KET_0.copy(), target=0, n_qubits=1,
                                         basis="X", rng=rng)
    z0_outcomes.append(outcome)
frac = np.mean(z0_outcomes)
check(f"Measuring |0> in X-basis is ~50/50 (got {frac:.3f})", abs(frac - 0.5) < 0.05)

# ---------------------------------------------------------------------------
# 7. Fidelity
# ---------------------------------------------------------------------------
check("Fidelity of a state with itself is 1.0", np.isclose(state_fidelity(KET_0, KET_0), 1.0))
check("Fidelity of |0> and |1> is 0.0", np.isclose(state_fidelity(KET_0, KET_1), 0.0))
check("Fidelity of |0> and |+> is 0.5", np.isclose(state_fidelity(KET_0, expected_plus), 0.5))

# ---------------------------------------------------------------------------
# 8. Arbitrary single-qubit state construction
# ---------------------------------------------------------------------------
arb = single_qubit_state(theta=np.pi / 3, phi=np.pi / 4)
check("single_qubit_state produces a normalized state", is_normalized(arb))

# ---------------------------------------------------------------------------
# 9. tensor_product (added in Phase 2, for teleportation register construction)
# ---------------------------------------------------------------------------
from core.primitives import tensor_product, extract_reduced_state

combined = tensor_product(KET_1, KET_0)  # should give |10>
expected_10 = np.array([0, 0, 1, 0], dtype=complex)
check("tensor_product(|1>, |0>) = |10>", np.allclose(combined, expected_10))

combined3 = tensor_product(KET_1, KET_0, KET_1)  # |101>
expected_101 = np.zeros(8, dtype=complex)
expected_101[0b101] = 1.0
check("tensor_product(|1>,|0>,|1>) = |101>", np.allclose(combined3, expected_101))

# ---------------------------------------------------------------------------
# 10. extract_reduced_state (added in Phase 2, for post-measurement extraction)
# ---------------------------------------------------------------------------
# Build a 3-qubit product state |1>|0>|+> (qubit2=1, qubit1=0, qubit0=+)
plus = apply_single_qubit_gate(KET_0, HADAMARD, target=0, n_qubits=1)
test_state = tensor_product(KET_1, KET_0, plus)

extracted = extract_reduced_state(test_state, target_qubit=0,
                                   fixed={1: 0, 2: 1}, n_qubits=3)
check("extract_reduced_state recovers |+> from a known product state",
      np.isclose(state_fidelity(extracted, plus), 1.0))

# Inconsistent fixed values (wrong classical outcome) should raise, since
# that combination has zero amplitude in this particular state.
try:
    extract_reduced_state(test_state, target_qubit=0, fixed={1: 1, 2: 1}, n_qubits=3)
    check("extract_reduced_state raises on inconsistent fixed values", False)
except ValueError:
    check("extract_reduced_state raises on inconsistent fixed values", True)

# ---------------------------------------------------------------------------
# 11. prepare_pauli_eigenstate (added in Phase 3, for QDS key material)
#     Confirms it's the true inverse of measure_qubit_in_basis: preparing
#     in basis B with eigenvalue e, then measuring in basis B, must
#     deterministically return e -- for ALL 3 bases and both eigenvalues.
# ---------------------------------------------------------------------------
from core.primitives import prepare_pauli_eigenstate, measure_qubit_in_basis

for basis in ("X", "Y", "Z"):
    for eigen in (0, 1):
        prepared = prepare_pauli_eigenstate(basis, eigen)
        check(f"prepare_pauli_eigenstate({basis},{eigen}) is normalized",
              is_normalized(prepared))

        outcomes = []
        for _ in range(200):
            outcome, _ = measure_qubit_in_basis(prepared.copy(), target=0, n_qubits=1,
                                                  basis=basis, rng=rng)
            outcomes.append(outcome)
        check(f"prepare({basis},{eigen}) then measure({basis}) is deterministic == {eigen} "
              f"(got outcomes {set(outcomes)})",
              set(outcomes) == {eigen})

# Cross-check: a basis-Z eigenstate measured in the X basis should be ~50/50
# (mismatched basis => maximal uncertainty), confirming this isn't just
# trivially always deterministic regardless of basis.
z0 = prepare_pauli_eigenstate("Z", 0)
mismatched_outcomes = []
for _ in range(2000):
    outcome, _ = measure_qubit_in_basis(z0.copy(), target=0, n_qubits=1, basis="X", rng=rng)
    mismatched_outcomes.append(outcome)
frac_mismatched = np.mean(mismatched_outcomes)
check(f"Z-eigenstate measured in mismatched X-basis is ~50/50 (got {frac_mismatched:.3f})",
      abs(frac_mismatched - 0.5) < 0.05)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 0 TESTS PASSED")
