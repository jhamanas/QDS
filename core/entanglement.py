"""
core/entanglement.py

Phase 1: Bell-State Entanglement Module.

Purpose
-------
This module generates the entangled Bell pairs that serve as the shared
quantum resource for:
  - quantum teleportation (Phase 2), and
  - the "quantum public key distribution" step of the QDS protocol
    described in the project's problem statement (Phase 3).

All four Bell states are supported, since different QDS/teleportation
sub-steps may need different entangled resources (e.g. attack simulators
in Phase 5 will sometimes substitute the "wrong" Bell state to model
tampering).

Bell states (using qubit 0 = rightmost bit convention from primitives.py):
    |Phi+> = (|00> + |11>) / sqrt(2)
    |Phi-> = (|00> - |11>) / sqrt(2)
    |Psi+> = (|01> + |10>) / sqrt(2)
    |Psi-> = (|01> - |10>) / sqrt(2)

Standard circuit: start from |00>, apply H to qubit 0, then CNOT(0 -> 1).
This produces |Phi+>. The other three Bell states are reached by applying
an extra Pauli gate to one qubit before the CNOT, or equivalently in front
of the finished |Phi+> state -- both approaches are provided below since
Phase 2's teleportation correction step needs the "apply Pauli then
reinterpret" logic directly.
"""

from __future__ import annotations
import numpy as np

from core.primitives import (
    zero_state, apply_single_qubit_gate, apply_two_qubit_gate,
    HADAMARD, CNOT, PAULI,
)

BELL_STATE_NAMES = ("phi+", "phi-", "psi+", "psi-")

# Pre-gates applied to qubits 0 and 1 (as X flips on |00>, BEFORE H(q0)+CNOT)
# to reach each target Bell state.
#
# Derivation: starting from |b0 b1> (b0, b1 in {0,1}), applying H to qubit 0
# then CNOT(0 -> 1) gives:
#     (|0, b1> + (-1)^b0 |1, NOT b1>) / sqrt(2)
# Substituting b0, b1:
#     b0=0, b1=0 -> (|00> + |11>)/sqrt2   = |Phi+>
#     b0=1, b1=0 -> (|00> - |11>)/sqrt2   = |Phi->
#     b0=0, b1=1 -> (|01> + |10>)/sqrt2   = |Psi+>
#     b0=1, b1=1 -> (|01> - |10>)/sqrt2   = |Psi->
# So b0 controls the relative sign (+/-), and b1 controls phi-type vs
# psi-type. Each bi=1 means "apply X to qubit i before H+CNOT" (since
# X|0> = |1>).
_BELL_PREP_FLIPS = {
    "phi+": (0, 0),  # (flip_q0, flip_q1)
    "phi-": (1, 0),
    "psi+": (0, 1),
    "psi-": (1, 1),
}


def generate_bell_pair(kind: str = "phi+") -> np.ndarray:
    """
    Generates a 2-qubit Bell state statevector of the requested kind.

    Parameters
    ----------
    kind : one of "phi+", "phi-", "psi+", "psi-"

    Returns
    -------
    A length-4 complex statevector for the entangled pair (qubit 0, qubit 1).
    """
    kind = kind.lower()
    if kind not in BELL_STATE_NAMES:
        raise ValueError(f"Unknown Bell state '{kind}', expected one of {BELL_STATE_NAMES}")

    flip_q0, flip_q1 = _BELL_PREP_FLIPS[kind]

    state = zero_state(2)
    if flip_q0:
        state = apply_single_qubit_gate(state, PAULI["X"], target=0, n_qubits=2)
    if flip_q1:
        state = apply_single_qubit_gate(state, PAULI["X"], target=1, n_qubits=2)

    state = apply_single_qubit_gate(state, HADAMARD, target=0, n_qubits=2)
    state = apply_two_qubit_gate(state, CNOT, qubits=(0, 1), n_qubits=2)
    return state


def bell_state_vector(kind: str = "phi+") -> np.ndarray:
    """
    Returns the analytically-known target statevector for a given Bell
    state, independent of the circuit construction. Used as a ground-truth
    reference to test generate_bell_pair() against.
    """
    kind = kind.lower()
    s = np.zeros(4, dtype=complex)
    inv_sqrt2 = 1 / np.sqrt(2)
    if kind == "phi+":
        s[0], s[3] = inv_sqrt2, inv_sqrt2      # |00> + |11>
    elif kind == "phi-":
        s[0], s[3] = inv_sqrt2, -inv_sqrt2     # |00> - |11>
    elif kind == "psi+":
        s[1], s[2] = inv_sqrt2, inv_sqrt2      # |01> + |10>
    elif kind == "psi-":
        s[1], s[2] = inv_sqrt2, -inv_sqrt2     # |01> - |10>
    else:
        raise ValueError(f"Unknown Bell state '{kind}', expected one of {BELL_STATE_NAMES}")
    return s


def verify_entanglement(state: np.ndarray, rng: np.random.Generator,
                         n_trials: int = 2000, atol: float = 0.05) -> dict:
    """
    Sanity-check helper: confirms a 2-qubit state exhibits genuine Bell-pair
    correlation, by simulating repeated Z-basis measurement of both qubits
    and checking that outcomes are perfectly correlated (phi-type) or
    perfectly anti-correlated (psi-type), and that each qubit individually
    reads out ~50/50 (a hallmark of maximal entanglement -- each qubit
    alone is in a maximally mixed marginal state).

    Returns a dict of diagnostic statistics rather than asserting directly,
    so callers (tests, or later the Phase 4 baseline calibrator) can decide
    what to do with the numbers.
    """
    from core.primitives import measure_qubit  # local import avoids cycle at module load

    q0_outcomes = []
    q1_outcomes = []
    for _ in range(n_trials):
        working_state = state.copy()
        o0, working_state = measure_qubit(working_state, target=0, n_qubits=2, rng=rng)
        o1, working_state = measure_qubit(working_state, target=1, n_qubits=2, rng=rng)
        q0_outcomes.append(o0)
        q1_outcomes.append(o1)

    q0_outcomes = np.array(q0_outcomes)
    q1_outcomes = np.array(q1_outcomes)

    agree_fraction = np.mean(q0_outcomes == q1_outcomes)
    q0_marginal = np.mean(q0_outcomes)
    q1_marginal = np.mean(q1_outcomes)

    return {
        "n_trials": n_trials,
        "agree_fraction": float(agree_fraction),
        "q0_marginal_prob_1": float(q0_marginal),
        "q1_marginal_prob_1": float(q1_marginal),
        "q0_is_unbiased": bool(abs(q0_marginal - 0.5) < atol),
        "q1_is_unbiased": bool(abs(q1_marginal - 0.5) < atol),
    }
