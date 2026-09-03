"""
core/primitives.py

Phase 0: Foundations.

Purpose
-------
This module defines how quantum states and gates are represented and
manipulated for the entire project. Every later phase (Bell states,
teleportation, QDS signing/verification, attack simulation, statistical
detection) builds directly on the functions here. If the linear algebra
here is wrong, every downstream result is meaningless -- so this module
is kept small, explicit, and thoroughly tested.

Representation choice
----------------------
We represent an n-qubit register as a statevector: a complex NumPy array
of length 2^n, using the standard computational basis ordering
|q_{n-1} ... q_1 q_0> (qubit 0 is the least-significant / rightmost bit).

We use statevectors (not density matrices) for Phases 0-3, since the
honest-path protocol is modeled as a pure-state process. Density-matrix /
mixed-state support is added later (Phase 5) when we need to model noisy
channels and eavesdropping, where the state becomes mixed from the
legitimate party's point of view.
"""

from __future__ import annotations
import numpy as np
from typing import Sequence

# ---------------------------------------------------------------------------
# Single-qubit basis states
# ---------------------------------------------------------------------------

KET_0 = np.array([1.0, 0.0], dtype=complex)
KET_1 = np.array([0.0, 1.0], dtype=complex)

# ---------------------------------------------------------------------------
# Standard gate matrices
# ---------------------------------------------------------------------------

I2 = np.eye(2, dtype=complex)

PAULI_X = np.array([[0, 1],
                     [1, 0]], dtype=complex)

PAULI_Y = np.array([[0, -1j],
                     [1j, 0]], dtype=complex)

PAULI_Z = np.array([[1, 0],
                     [0, -1]], dtype=complex)

HADAMARD = (1 / np.sqrt(2)) * np.array([[1, 1],
                                         [1, -1]], dtype=complex)

# CNOT with qubit 0 = control, qubit 1 = target, basis order |q1 q0>
CNOT = np.array([[1, 0, 0, 0],
                  [0, 1, 0, 0],
                  [0, 0, 0, 1],
                  [0, 0, 1, 0]], dtype=complex)

PAULI = {"I": I2, "X": PAULI_X, "Y": PAULI_Y, "Z": PAULI_Z}


def is_unitary(matrix: np.ndarray, atol: float = 1e-8) -> bool:
    """Sanity check: confirms a gate matrix is unitary (U U^dagger = I)."""
    n = matrix.shape[0]
    return np.allclose(matrix @ matrix.conj().T, np.eye(n), atol=atol)


# ---------------------------------------------------------------------------
# Statevector construction
# ---------------------------------------------------------------------------

def zero_state(n_qubits: int) -> np.ndarray:
    """Returns the |0...0> statevector for n_qubits."""
    state = np.zeros(2 ** n_qubits, dtype=complex)
    state[0] = 1.0
    return state


def single_qubit_state(theta: float, phi: float) -> np.ndarray:
    """
    Returns a general single-qubit pure state on the Bloch sphere:
        |psi> = cos(theta/2)|0> + e^{i phi} sin(theta/2)|1>
    Used later to prepare arbitrary states for teleportation fidelity tests.
    """
    return np.array([
        np.cos(theta / 2),
        np.exp(1j * phi) * np.sin(theta / 2)
    ], dtype=complex)


def prepare_pauli_eigenstate(basis: str, eigen: int) -> np.ndarray:
    """
    Prepares a single-qubit state that is an eigenstate of the given Pauli
    operator, for the given eigenvalue sign (eigen=0 -> +1 eigenvalue,
    eigen=1 -> -1 eigenvalue). This is the state-preparation counterpart
    to measure_qubit_in_basis(): preparing in basis B with eigen e, then
    measuring in basis B, deterministically returns outcome e.

    Used starting Phase 3 to build the QDS protocol's private key material
    (random Pauli eigenstates), where basis and eigenvalue together form
    the secret classical description Aditi keeps until signing.

        Z basis: eigen=0 -> |0>,  eigen=1 -> |1>
        X basis: eigen=0 -> |+>,  eigen=1 -> |->
        Y basis: eigen=0 -> |+i>, eigen=1 -> |-i>
    """
    basis = basis.upper()
    if eigen not in (0, 1):
        raise ValueError(f"eigen must be 0 or 1, got {eigen}")

    if basis == "Z":
        return KET_0.copy() if eigen == 0 else KET_1.copy()
    elif basis == "X":
        plus = apply_single_qubit_gate(KET_0, HADAMARD, target=0, n_qubits=1)
        minus = apply_single_qubit_gate(KET_1, HADAMARD, target=0, n_qubits=1)
        return plus if eigen == 0 else minus
    elif basis == "Y":
        plus_i = np.array([1, 1j], dtype=complex) / np.sqrt(2)
        minus_i = np.array([1, -1j], dtype=complex) / np.sqrt(2)
        return plus_i if eigen == 0 else minus_i
    else:
        raise ValueError(f"Unknown basis '{basis}', expected X, Y, or Z.")


def normalize(state: np.ndarray) -> np.ndarray:
    """Normalizes a statevector to unit norm (guards against float drift)."""
    norm = np.linalg.norm(state)
    if norm == 0:
        raise ValueError("Cannot normalize a zero vector.")
    return state / norm


def is_normalized(state: np.ndarray, atol: float = 1e-8) -> bool:
    return np.isclose(np.linalg.norm(state), 1.0, atol=atol)


# ---------------------------------------------------------------------------
# Applying gates to a multi-qubit statevector
# ---------------------------------------------------------------------------

def apply_single_qubit_gate(state: np.ndarray, gate: np.ndarray,
                             target: int, n_qubits: int) -> np.ndarray:
    """
    Applies a 2x2 gate to `target` qubit within an n_qubits register,
    via full-space tensor (Kronecker) product construction.

    Qubit indexing: qubit 0 is the rightmost (least significant) in the
    tensor order used by zero_state / basis printing.
    """
    op = np.array([[1.0]], dtype=complex)
    # Build operator from most-significant qubit down to least-significant,
    # since np.kron builds left-to-right = most-significant-first.
    for q in range(n_qubits - 1, -1, -1):
        op = np.kron(op, gate if q == target else I2)
    return op @ state


def apply_two_qubit_gate(state: np.ndarray, gate: np.ndarray,
                          qubits: Sequence[int], n_qubits: int) -> np.ndarray:
    """
    Applies a 4x4 two-qubit gate (e.g. CNOT) to a pair of qubits within an
    n_qubits register. `qubits` = (control, target) for CNOT.

    Implementation note: for n_qubits > 2 this uses a permutation-based
    approach -- reorder the register so the two target qubits are adjacent
    and in the expected order, apply the gate via Kronecker product with
    identities on the rest, then permute back.
    """
    if len(qubits) != 2:
        raise ValueError("apply_two_qubit_gate expects exactly 2 qubit indices.")
    q_a, q_b = qubits
    dim = 2 ** n_qubits

    # Build full permutation mapping each basis index to itself but with
    # bits at positions q_a, q_b moved to the front (positions n-1, n-2)
    # in order (q_a, q_b), matching the gate's own bit ordering.
    other_qubits = [q for q in range(n_qubits - 1, -1, -1) if q not in (q_a, q_b)]
    new_order = [q_a, q_b] + other_qubits  # most-significant-first target order

    perm = np.zeros(dim, dtype=int)
    for idx in range(dim):
        bits = [(idx >> q) & 1 for q in range(n_qubits)]  # bits[q] = value of qubit q
        new_idx = 0
        for pos, q in enumerate(reversed(new_order)):
            new_idx |= bits[q] << pos
        perm[idx] = new_idx

    permuted_state = np.zeros_like(state)
    permuted_state[perm] = state

    full_gate = np.kron(gate, np.eye(2 ** (n_qubits - 2), dtype=complex))
    new_state = full_gate @ permuted_state

    inv_perm = np.argsort(perm)
    return new_state[inv_perm]


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def measurement_probabilities(state: np.ndarray) -> np.ndarray:
    """Born-rule probabilities for each computational basis outcome."""
    return np.abs(state) ** 2


def measure_qubit(state: np.ndarray, target: int, n_qubits: int,
                   rng: np.random.Generator) -> tuple[int, np.ndarray]:
    """
    Projectively measures `target` qubit in the computational (Z) basis.
    Returns (outcome, post_measurement_state) with the state collapsed
    and renormalized.
    """
    dim = 2 ** n_qubits
    prob_1 = 0.0
    for idx in range(dim):
        if (idx >> target) & 1:
            prob_1 += abs(state[idx]) ** 2

    outcome = 1 if rng.random() < prob_1 else 0

    new_state = np.zeros_like(state)
    for idx in range(dim):
        if ((idx >> target) & 1) == outcome:
            new_state[idx] = state[idx]

    new_state = normalize(new_state)
    return outcome, new_state


def measure_qubit_in_basis(state: np.ndarray, target: int, n_qubits: int,
                            basis: str, rng: np.random.Generator) -> tuple[int, np.ndarray]:
    """
    Projectively measures `target` qubit in a chosen Pauli eigenbasis
    ("X", "Y", or "Z"). This is the operation the QDS verification step
    (Phase 3) and the statistical detector (Phase 4) both depend on.

    Implementation: rotate the target qubit's basis so the desired Pauli
    eigenbasis maps to the computational basis, measure in Z, rotate back
    is not needed since we only need the outcome (state is left collapsed
    in the rotated frame's computational basis, then rotated back for
    consistency with the rest of the register).
    """
    basis = basis.upper()
    if basis == "Z":
        return measure_qubit(state, target, n_qubits, rng)

    if basis == "X":
        # H maps X-eigenbasis <-> Z-eigenbasis
        rot = HADAMARD
    elif basis == "Y":
        # S^dagger then H maps Y-eigenbasis <-> Z-eigenbasis
        S_DAG = np.array([[1, 0], [0, -1j]], dtype=complex)
        rot = HADAMARD @ S_DAG
    else:
        raise ValueError(f"Unknown basis '{basis}', expected X, Y, or Z.")

    rotated_state = apply_single_qubit_gate(state, rot, target, n_qubits)
    outcome, collapsed = measure_qubit(rotated_state, target, n_qubits, rng)

    rot_inv = rot.conj().T
    unrotated = apply_single_qubit_gate(collapsed, rot_inv, target, n_qubits)
    return outcome, normalize(unrotated)


def state_fidelity(state_a: np.ndarray, state_b: np.ndarray) -> float:
    """
    Fidelity between two pure states: |<a|b>|^2.
    Used from Phase 2 onward to verify teleportation correctness and to
    quantify how much an attack disturbs a state.
    """
    overlap = np.vdot(state_a, state_b)
    return float(np.abs(overlap) ** 2)


# ---------------------------------------------------------------------------
# Multi-qubit register construction and post-measurement extraction
# (added in Phase 2, for teleportation -- but these are generic quantum
# operations, not teleportation-specific, so they live here alongside the
# other foundational primitives.)
# ---------------------------------------------------------------------------

def tensor_product(*states: np.ndarray) -> np.ndarray:
    """
    Combines separate statevectors into one joint register via Kronecker
    product, in the order given: the FIRST argument becomes the most
    significant qubit(s), matching the MSB-first convention used
    throughout this module (see module docstring).

    Example: tensor_product(psi, bell_pair) where psi is a 1-qubit state
    and bell_pair is a 2-qubit state produces a 3-qubit register where
    psi occupies the highest-index qubit and bell_pair's own qubits 1,0
    occupy the new register's qubits 1,0 respectively.
    """
    result = states[0]
    for s in states[1:]:
        result = np.kron(result, s)
    return result


def extract_reduced_state(state: np.ndarray, target_qubit: int,
                           fixed: dict[int, int], n_qubits: int) -> np.ndarray:
    """
    Extracts the pure state of a single remaining qubit, given that every
    OTHER qubit in the register has already been projectively measured
    and collapsed to a known classical value (passed in `fixed` as
    {qubit_index: 0_or_1}).

    This is valid because: if an n-qubit register is in a pure state and
    (n-1) of its qubits are projectively measured to definite outcomes,
    the remaining qubit is necessarily left in a definite pure state
    (not a mixed state) -- there is no lingering entanglement with
    qubits that no longer have any superposition left. This is exactly
    the situation after Aditi's two measurements in teleportation: only
    Bharat's qubit remains free, and its state is what teleportation
    delivers (up to a known Pauli correction).

    Raises ValueError if the given `fixed` values are inconsistent with
    the state (i.e. correspond to a combination with zero amplitude,
    meaning target_qubit is not actually the only qubit left free, or
    the fixed values don't match how the state actually collapsed).
    """
    if len(fixed) != n_qubits - 1:
        raise ValueError(
            f"extract_reduced_state expects exactly one free qubit; "
            f"got {n_qubits - len(fixed)} free qubits for n_qubits={n_qubits}."
        )

    amps = []
    for bit in (0, 1):
        idx = 0
        for q in range(n_qubits):
            val = bit if q == target_qubit else fixed[q]
            idx |= (val << q)
        amps.append(state[idx])

    vec = np.array(amps, dtype=complex)
    norm = np.linalg.norm(vec)
    if norm == 0:
        raise ValueError(
            "extract_reduced_state: zero amplitude for all values of the "
            "target qubit given the fixed values -- the fixed dict does "
            "not match how this state actually collapsed."
        )
    return vec / norm
