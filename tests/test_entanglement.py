"""
tests/test_entanglement.py

Phase 1 validation. Run after tests/test_primitives.py passes.
If anything here fails, do not proceed to Phase 2 -- fix entanglement.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.primitives import is_normalized, state_fidelity
from core.entanglement import (
    generate_bell_pair, bell_state_vector, verify_entanglement, BELL_STATE_NAMES
)

rng = np.random.default_rng(7)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


# ---------------------------------------------------------------------------
# 1. Each Bell state is normalized and matches its analytic reference
# ---------------------------------------------------------------------------
for kind in BELL_STATE_NAMES:
    generated = generate_bell_pair(kind)
    reference = bell_state_vector(kind)

    check(f"{kind}: generated state is normalized", is_normalized(generated))
    # NOTE: we check physical equivalence via fidelity, not raw array
    # equality. Two statevectors that differ only by an overall global
    # phase (e.g. a factor of -1 or i) represent the exact same physical
    # state -- global phase is not observable in any measurement. The
    # circuit construction here happens to produce psi- up to a global
    # phase of -1 relative to the analytic reference, which is correct
    # physics, not a bug. Fidelity |<a|b>|^2 correctly ignores global phase.
    check(f"{kind}: fidelity with analytic reference is 1.0 "
          f"(physically identical state, regardless of global phase)",
          np.isclose(state_fidelity(generated, reference), 1.0))

# ---------------------------------------------------------------------------
# 2. Different Bell states are distinguishable (orthogonal)
# ---------------------------------------------------------------------------
phi_plus = generate_bell_pair("phi+")
phi_minus = generate_bell_pair("phi-")
psi_plus = generate_bell_pair("psi+")
psi_minus = generate_bell_pair("psi-")

all_states = {"phi+": phi_plus, "phi-": phi_minus, "psi+": psi_plus, "psi-": psi_minus}
for name_a, state_a in all_states.items():
    for name_b, state_b in all_states.items():
        if name_a == name_b:
            continue
        fid = state_fidelity(state_a, state_b)
        check(f"{name_a} and {name_b} are orthogonal (fidelity ~0, got {fid:.4f})",
              fid < 1e-8)

# ---------------------------------------------------------------------------
# 3. Entanglement correlation structure via repeated measurement
# ---------------------------------------------------------------------------
# Phi-type states: perfectly correlated outcomes (00 or 11 only)
stats_phi_plus = verify_entanglement(phi_plus, rng, n_trials=3000)
check(f"phi+ measurement outcomes are perfectly correlated "
      f"(agree_fraction={stats_phi_plus['agree_fraction']:.3f})",
      stats_phi_plus["agree_fraction"] > 0.999)
check("phi+ qubit 0 marginal is unbiased (~50/50)", stats_phi_plus["q0_is_unbiased"])
check("phi+ qubit 1 marginal is unbiased (~50/50)", stats_phi_plus["q1_is_unbiased"])

stats_phi_minus = verify_entanglement(phi_minus, rng, n_trials=3000)
check(f"phi- measurement outcomes are perfectly correlated "
      f"(agree_fraction={stats_phi_minus['agree_fraction']:.3f})",
      stats_phi_minus["agree_fraction"] > 0.999)

# Psi-type states: perfectly ANTI-correlated outcomes (01 or 10 only)
stats_psi_plus = verify_entanglement(psi_plus, rng, n_trials=3000)
check(f"psi+ measurement outcomes are perfectly anti-correlated "
      f"(agree_fraction={stats_psi_plus['agree_fraction']:.3f}, expect ~0)",
      stats_psi_plus["agree_fraction"] < 0.001)
check("psi+ qubit 0 marginal is unbiased (~50/50)", stats_psi_plus["q0_is_unbiased"])

stats_psi_minus = verify_entanglement(psi_minus, rng, n_trials=3000)
check(f"psi- measurement outcomes are perfectly anti-correlated "
      f"(agree_fraction={stats_psi_minus['agree_fraction']:.3f}, expect ~0)",
      stats_psi_minus["agree_fraction"] < 0.001)

# ---------------------------------------------------------------------------
# 4. Sanity check: a NON-entangled (product) state should show no such
#    perfect correlation -- confirms verify_entanglement() can actually
#    tell entangled from non-entangled states, not just always pass.
# ---------------------------------------------------------------------------
from core.primitives import zero_state, apply_single_qubit_gate, HADAMARD

product_state = zero_state(2)
product_state = apply_single_qubit_gate(product_state, HADAMARD, target=0, n_qubits=2)
product_state = apply_single_qubit_gate(product_state, HADAMARD, target=1, n_qubits=2)
# This is |+>|+> -- an unentangled product state, NOT a Bell state.

stats_product = verify_entanglement(product_state, rng, n_trials=3000)
check(f"unentangled |+>|+> shows NO perfect correlation "
      f"(agree_fraction={stats_product['agree_fraction']:.3f}, expect ~0.5)",
      0.4 < stats_product["agree_fraction"] < 0.6)

# ---------------------------------------------------------------------------
# 5. Invalid input handling
# ---------------------------------------------------------------------------
try:
    generate_bell_pair("not_a_real_state")
    check("generate_bell_pair rejects invalid kind", False)
except ValueError:
    check("generate_bell_pair rejects invalid kind", True)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 1 TESTS PASSED")
