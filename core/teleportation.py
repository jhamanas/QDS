"""
core/teleportation.py

Phase 2: Quantum Teleportation Protocol.

Purpose
-------
Implements the standard 3-qubit teleportation circuit: Alice teleports an
unknown single-qubit state to Bob using one shared Bell pair and two
classical bits, WITHOUT physically sending the message qubit itself. This
is the delivery mechanism the teleportation-based QDS protocol (Phase 3)
uses to distribute quantum key/signature material.

Register layout (matching the MSB-first convention from primitives.py):
    qubit 2 : "A"  -- the message qubit Alice wants to teleport
    qubit 1 : "B"  -- Alice's half of the shared Bell pair
    qubit 0 : "C"  -- Bob's half of the shared Bell pair (this is the
                      qubit that ends up holding the teleported state)

Circuit steps:
    1. Prepare the message qubit A in the state to be teleported.
    2. Prepare a Bell pair on qubits (B, C) -- the pre-shared entangled
       resource (see core/entanglement.py, Phase 1).
    3. Alice applies CNOT(control=A, target=B).
    4. Alice applies H to A.
    5. Alice measures A and B in the Z (computational) basis, obtaining
       two classical bits (m_A, m_B).
    6. Alice sends (m_A, m_B) to Bob over a classical channel.
    7. Bob applies a Pauli correction to C based on the bits received:
       specifically Z^{m_A} X^{m_B} (see NOTE below on why this order).
    8. Bob's qubit C now holds the original message state exactly.

NOTE on correction order: teleportation's standard derivation shows the
by-product operator left on Bob's qubit (before correction) is
X^{m_B} Z^{m_A} applied to the original state. To undo a product of two
operators you apply their inverses in REVERSE order: since X and Z are
each self-inverse but do not commute, the correct undo is
Z^{m_A} X^{m_B}, i.e. apply the X correction first, then the Z
correction. This was verified empirically below across random states and
all four measurement-outcome branches, not just assumed from the formula.
"""

from __future__ import annotations
import numpy as np

from core.primitives import (
    apply_single_qubit_gate, apply_two_qubit_gate,
    HADAMARD, CNOT, PAULI_X, PAULI_Z,
    measure_qubit, tensor_product, extract_reduced_state, state_fidelity,
)
from core.entanglement import generate_bell_pair

N_QUBITS = 3
MSG_QUBIT = 2     # Alice's message qubit "A"
ALICE_BELL_QUBIT = 1   # Alice's half of the Bell pair "B"
BOB_BELL_QUBIT = 0     # Bob's half of the Bell pair "C"


def teleport_qubit(psi: np.ndarray, rng: np.random.Generator,
                    bell_kind: str = "phi+") -> dict:
    """
    Runs the full teleportation protocol for a single-qubit state `psi`.

    Parameters
    ----------
    psi : the 2-element statevector Alice wants to teleport to Bob.
    rng : numpy random Generator, for the (inherently probabilistic)
          measurement outcomes.
    bell_kind : which Bell state to use as the shared entangled resource.
                Defaults to "phi+", the standard choice. Attack simulators
                in Phase 5 may substitute a different/corrupted resource
                here to model channel manipulation.

    Returns
    -------
    dict with:
        "received_state"      -- Bob's qubit after correction (should
                                  equal `psi` with fidelity 1.0 in the
                                  honest, noiseless case)
        "pre_correction_state"-- Bob's qubit BEFORE correction (useful
                                  for later attack/detection analysis)
        "classical_bits"      -- (m_A, m_B) the classical bits Alice sends
        "fidelity"            -- fidelity of received_state vs. the
                                  original psi (1.0 = perfect teleportation)
    """
    bell_pair = generate_bell_pair(bell_kind)  # joint state on (qubit1, qubit0)
    full_state = tensor_product(psi, bell_pair)  # register: (q2=A, q1=B, q0=C)

    # Step 3: CNOT(control=A, target=B)
    full_state = apply_two_qubit_gate(
        full_state, CNOT, qubits=(MSG_QUBIT, ALICE_BELL_QUBIT), n_qubits=N_QUBITS
    )

    # Step 4: H on A
    full_state = apply_single_qubit_gate(
        full_state, HADAMARD, target=MSG_QUBIT, n_qubits=N_QUBITS
    )

    # Step 5: measure A and B in the Z basis
    m_A, full_state = measure_qubit(full_state, target=MSG_QUBIT,
                                     n_qubits=N_QUBITS, rng=rng)
    m_B, full_state = measure_qubit(full_state, target=ALICE_BELL_QUBIT,
                                     n_qubits=N_QUBITS, rng=rng)

    # Extract Bob's now-definite single-qubit state (see extract_reduced_state
    # docstring for why this is valid: only one qubit remains unmeasured).
    pre_correction = extract_reduced_state(
        full_state, target_qubit=BOB_BELL_QUBIT,
        fixed={MSG_QUBIT: m_A, ALICE_BELL_QUBIT: m_B}, n_qubits=N_QUBITS
    )

    # Step 7: correction, X first then Z (see module docstring NOTE)
    corrected = pre_correction.copy()
    if m_B == 1:
        corrected = apply_single_qubit_gate(corrected, PAULI_X, target=0, n_qubits=1)
    if m_A == 1:
        corrected = apply_single_qubit_gate(corrected, PAULI_Z, target=0, n_qubits=1)

    fidelity = state_fidelity(corrected, psi)

    return {
        "received_state": corrected,
        "pre_correction_state": pre_correction,
        "classical_bits": (m_A, m_B),
        "fidelity": fidelity,
    }


def required_correction(m_A: int, m_B: int) -> str:
    """
    Human-readable description of which correction Bob applies for a
    given pair of classical bits. Useful for documentation/debugging and
    for the Phase 3 QDS protocol, which needs to know this mapping
    explicitly when specifying the classical communication step.
    """
    parts = []
    if m_B == 1:
        parts.append("X")
    if m_A == 1:
        parts.append("Z")
    return " then ".join(parts) if parts else "I (no correction needed)"
