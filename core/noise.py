"""
core/noise.py

Phase 4 support: a minimal stochastic noise model used to give the honest
baseline (detection/baseline.py) a non-trivial, realistic mismatch
distribution to calibrate against, and reused in Phase 5 to model
attacker-induced disturbance.

Modeled as a Monte-Carlo depolarizing channel over pure states: with
total probability p, a uniformly random Pauli error (X, Y, or Z) is
applied to the target qubit (p/3 each); otherwise the qubit is left
untouched. Averaged over many trials this reproduces standard
depolarizing-channel measurement statistics without needing a
density-matrix simulator, consistent with the pure-statevector
representation used throughout core/primitives.py.
"""

from __future__ import annotations
import numpy as np

from core.primitives import apply_single_qubit_gate, PAULI


def apply_depolarizing_noise(state: np.ndarray, p: float, target: int,
                              n_qubits: int, rng: np.random.Generator) -> np.ndarray:
    """
    With total probability p, applies a uniformly random Pauli error (X, Y,
    or Z) to `target` qubit within an n_qubits register; otherwise returns
    `state` unchanged. p is split evenly across the three Pauli errors
    (p/3 each), matching the standard depolarizing-channel convention.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError(f"p must be in [0, 1], got {p}")

    r = rng.random()
    if r < p / 3:
        gate = PAULI["X"]
    elif r < 2 * p / 3:
        gate = PAULI["Y"]
    elif r < p:
        gate = PAULI["Z"]
    else:
        return state
    return apply_single_qubit_gate(state, gate, target=target, n_qubits=n_qubits)
