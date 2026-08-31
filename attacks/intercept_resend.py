"""
attacks/intercept_resend.py

Phase 5: Intercept-resend eavesdropping attack simulator.

Purpose
-------
Models an eavesdropper (Eve) sitting on the quantum public key
distribution channel (Phase 3 step 2), between Alice's teleportation and
Bob's eventual verification. Eve does NOT know Alice's private
(basis, eigen) description for any qubit -- that is the whole point of
the protocol -- so she cannot copy a qubit's exact information without
disturbing it (no-cloning theorem). The intercept-resend strategy is the
standard way to attack such a channel:

  1. Eve intercepts the qubit in transit (here modeled as replacing
     kq.bob_state immediately after distribute_public_key has delivered
     Alice's honestly-teleported qubit -- i.e. we attack the delivered
     state directly rather than re-deriving the teleportation circuit,
     since the physical effect is identical: Bob ends up holding
     whatever Eve decides to forward).
  2. Eve measures the intercepted qubit in a basis she guesses uniformly
     at random from {X, Y, Z} (she has no better information).
  3. Eve re-prepares a fresh eigenstate in her guessed basis, with her
     measured eigenvalue, and forwards THAT to Bob in place of the
     original.

This is applied independently per qubit, across BOTH key sets (Eve
cannot tell which key set will later be disclosed as the signature, so
she must attack everything crossing the channel).

Expected disturbance (worked out analytically, confirmed by
tests/test_attacks.py)
------------------------------------------------------------------------
Bob later verifies by measuring in the basis Alice actually used and
honestly discloses at signing time (her true basis for that qubit).
For a single intercepted-and-resent qubit:

  - Eve's guessed basis matches Alice's true basis (prob 1/3): her
    measurement was non-disturbing (she measured a true eigenstate in
    its own basis, got the true eigenvalue deterministically, and
    resent an identical copy). Bob's later measurement in the same
    (true) basis reproduces the true eigenvalue with certainty ->
    no mismatch introduced by this qubit.
  - Eve's guessed basis differs from Alice's true basis (prob 2/3): her
    resent state is now a definite eigenstate of the WRONG basis, so
    when Bob measures it in Alice's true (disclosed) basis, the result
    is maximally uncertain (mutually unbiased bases) -> 50/50 mismatch.

  Overall per-qubit mismatch probability introduced by full-channel
  interception: (2/3) * (1/2) = 1/3.

This ~33% QBER is the quantum-mechanical "fingerprint" of eavesdropping
on this 3-basis (X/Y/Z) scheme -- the direct analogue of BB84's familiar
25% intercept-resend QBER, scaled up because guessing right among 3
mutually unbiased bases is harder than guessing right among BB84's 2.
It is exactly the kind of elevated, above-honest-baseline mismatch rate
the Phase 4 statistical detector was built to catch.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np

from core.primitives import prepare_pauli_eigenstate, measure_qubit_in_basis
from core.qds_protocol import SingleBitKeyMaterial, DEFAULT_BASES


@dataclass
class InterceptResendLog:
    """Per-qubit diagnostic record of what Eve did, for later analysis
    (Phase 6 validation, Phase 7 security writeup) -- not needed by the
    attack itself, but useful to confirm the 1/3 figure empirically
    without re-deriving it from scratch each time."""
    key_set_index: int          # 0 or 1, which key set this qubit belongs to
    qubit_index: int
    true_basis: str
    true_eigen: int
    eve_guessed_basis: str
    eve_measured_eigen: int
    basis_guessed_correctly: bool
    intercepted: bool


def intercept_resend_attack(key_material: SingleBitKeyMaterial, rng: np.random.Generator,
                             intercept_prob: float = 1.0,
                             bases_pool: tuple[str, ...] = DEFAULT_BASES) -> list[InterceptResendLog]:
    """
    Applies an intercept-resend attack to an ALREADY-DISTRIBUTED
    key_material (i.e. call this after distribute_public_key, mirroring
    the convention detection/baseline.py uses for applying channel
    noise post-distribution). Mutates each intercepted qubit's
    `bob_state` in place, replacing Alice's honestly-teleported state
    with Eve's guessed-basis resend.

    `intercept_prob` lets Eve intercept only a fraction of qubits (a
    partial eavesdropper is harder to detect but leaks less information
    to her -- useful for Phase 6/7 sensitivity analysis of the
    detector's power at different attack intensities). Defaults to 1.0
    (full interception) since that is the strongest, most detectable
    case and the natural first attack to validate the detector against.

    NOTE: this deliberately requires the true (basis, eigen) fields on
    each KeyQubit to record what Eve's measurement extracted and how it
    compares to ground truth (InterceptResendLog), for diagnostics only
    -- Eve's own ATTACK LOGIC never reads kq.basis / kq.eigen (that would
    be cheating: Eve has no access to Alice's private description, only
    to the physical qubit itself). Only the returned log uses them,
    purely for after-the-fact analysis.

    Returns a list of InterceptResendLog, one entry per qubit actually
    intercepted (qubits skipped due to intercept_prob < 1.0 are omitted).
    """
    if not (0.0 <= intercept_prob <= 1.0):
        raise ValueError(f"intercept_prob must be in [0, 1], got {intercept_prob}")

    logs: list[InterceptResendLog] = []

    for key_set_idx, key_set in enumerate((key_material.key_set_0, key_material.key_set_1)):
        for qubit_idx, kq in enumerate(key_set):
            if kq.bob_state is None:
                raise ValueError(
                    "Public key has not been distributed yet (bob_state is None). "
                    "Call distribute_public_key before intercept_resend_attack."
                )

            if rng.random() >= intercept_prob:
                continue  # this qubit passes through unintercepted

            # Eve has NO access to kq.basis / kq.eigen here -- only to the
            # physical state she intercepted.
            eve_guessed_basis = bases_pool[rng.integers(0, len(bases_pool))]
            eve_measured_eigen, _ = measure_qubit_in_basis(
                kq.bob_state.copy(), target=0, n_qubits=1,
                basis=eve_guessed_basis, rng=rng
            )

            # Resend: a freshly prepared eigenstate of Eve's guessed basis
            # and measured eigenvalue, replacing what Bob will receive.
            kq.bob_state = prepare_pauli_eigenstate(eve_guessed_basis, eve_measured_eigen)

            logs.append(InterceptResendLog(
                key_set_index=key_set_idx,
                qubit_index=qubit_idx,
                true_basis=kq.basis,
                true_eigen=kq.eigen,
                eve_guessed_basis=eve_guessed_basis,
                eve_measured_eigen=eve_measured_eigen,
                basis_guessed_correctly=(eve_guessed_basis == kq.basis),
                intercepted=True,
            ))

    return logs


def expected_mismatch_rate(n_bases: int = 3) -> float:
    """
    Analytic expected per-qubit mismatch rate a full intercept-resend
    attack introduces, for a scheme using `n_bases` mutually unbiased
    bases (3 for this project's X/Y/Z scheme):

        P(wrong basis guess) * P(mismatch | wrong basis)
      = ((n_bases - 1) / n_bases) * (1/2)

    For n_bases=3 this is 1/3 (~0.333), matching the module docstring's
    derivation. Provided as a single source of truth so
    tests/test_attacks.py and any later Phase 6/7 analysis don't
    hardcode the number twice.
    """
    return ((n_bases - 1) / n_bases) * 0.5
