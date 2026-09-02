"""
core/qds_protocol.py

Phase 3: Quantum Digital Signature Protocol (honest path only).

Purpose
-------
Implements signing and verification for a teleportation-based QDS scheme.
No attackers exist yet in this phase -- the goal is a correct, fully
working "happy path" between an honest signer (Alice) and an honest
verifier (Bob), which Phase 4's statistical detector will later use as
its baseline for "normal," and which Phase 5's attack simulators will
later try to break.

Protocol design (Lamport-style one-time signature over quantum key
material -- see conversation design notes for the rationale)
--------------------------------------------------------------
For each bit of the message to be signed:

  1. KEY GENERATION (Alice, private):
     Alice generates TWO independent key sets, KeySet_0 and KeySet_1,
     each containing L qubits. Each qubit i in a key set has a randomly
     chosen (basis_i, eigen_i) pair -- basis_i in {X, Y, Z}, eigen_i in
     {0, 1} -- and is prepared as the corresponding Pauli eigenstate
     (see prepare_pauli_eigenstate in primitives.py). This (basis, eigen)
     description is Alice's private signing key; it stays secret.

  2. QUANTUM PUBLIC KEY DISTRIBUTION:
     Alice teleports every qubit in both key sets to Bob (the verifier),
     using the teleportation protocol from Phase 2, one fresh Bell pair
     per qubit. Bob ends up holding 2L qubits, but has NO information
     about which basis or eigenvalue any of them represents -- this
     description was never sent over any channel, classical or quantum.
     Bob's set of received qubits is the "quantum public key."

  3. SIGNING:
     To sign message bit m, Alice discloses the classical description
     (basis_i, eigen_i) for every qubit in KeySet_m ONLY. KeySet_{1-m}
     is never disclosed and should be discarded after use (one-time
     signature -- reusing key material breaks the security argument,
     which is exactly what the Phase 5 replay-attack simulator will
     exploit).

  4. VERIFICATION:
     Bob measures his stored qubits corresponding to the disclosed
     KeySet_m, each in its disclosed basis, and compares each outcome
     to its disclosed eigenvalue. In the honest, noiseless case (this
     phase), every single measurement matches -- because Bob's qubit
     really is the eigenstate Alice prepared (teleportation delivered
     it with fidelity 1.0), and measuring an eigenstate in its own
     basis is deterministic. This gives EXACTLY the "deterministic
     acceptance of legitimate signatures" property required by the
     project's objectives.

Security intuition (formalized later in Phase 7)
-------------------------------------------------
CORRECTED in Phase 5 (see attacks/forgery.py for the full derivation and
empirical confirmation) -- the original claim here was wrong:

  A blind forger's per-qubit success probability is NOT 1/6. verify_bit
  does not check the forger's disclosed (basis, eigen) against Alice's
  true description directly -- it measures Bob's real qubit in whatever
  basis the forger discloses and compares to whatever eigenvalue the
  forger discloses. When the forger's guessed basis happens to match
  Alice's true basis (prob 1/3), success requires also guessing the
  eigenvalue (prob 1/2): contributes 1/6. But when the guessed basis is
  WRONG (prob 2/3), the mismatched-basis measurement is exactly 50/50
  regardless of the claimed eigenvalue -- NOT an automatic failure --
  contributing a further 1/3. Total per-qubit success probability is
  1/6 + 1/3 = 1/2, giving a forgery bound of (1/2)^L across L qubits,
  not (1/6)^L. Reaching a given security margin therefore requires a
  substantially larger L than this module originally suggested (e.g.
  L=128 for 2^-128 security under the correct bound).

  A second, more serious result (attacks/forgery.py,
  intercepting_forgery_attempt): an attacker with PHYSICAL ACCESS to
  Bob's stored qubits before verification -- e.g. one who compromised
  the quantum distribution channel -- can forge with probability
  EXACTLY 1.0, independent of L. This is because verify_bit always
  measures in the disclosed basis rather than Alice's true secret
  basis, so an attacker who measures a qubit once and truthfully
  discloses what she saw always passes: her own measurement IS the
  verification-relevant collapse. This means unforgeability rests
  entirely on the assumption that Bob's qubits are physically
  inaccessible to attackers before verification, not on any
  cryptographic hardness in the disclosure/verification logic itself --
  a much stronger physical assumption than the (1/2)^L blind-forger
  bound alone would suggest. See attacks/forgery.py for both findings
  in full, and Phase 7 for the complete security writeup.
"""

from __future__ import annotations
import numpy as np
from dataclasses import dataclass, field

from core.primitives import prepare_pauli_eigenstate, measure_qubit_in_basis
from core.teleportation import teleport_qubit

DEFAULT_BASES = ("X", "Y", "Z")


@dataclass
class KeyQubit:
    """One qubit of QDS key material: its secret classical description
    plus, once distributed, Bob's received quantum state."""
    basis: str
    eigen: int
    bob_state: np.ndarray | None = None       # filled in by distribute_public_key
    teleport_fidelity: float | None = None     # diagnostic: should be 1.0 (honest path)


@dataclass
class SingleBitKeyMaterial:
    """Alice's full private key material for signing ONE message bit:
    two independent key sets, one for each possible bit value."""
    key_set_0: list[KeyQubit]
    key_set_1: list[KeyQubit]


def generate_key_material(L: int, rng: np.random.Generator,
                           bases_pool: tuple[str, ...] = DEFAULT_BASES) -> SingleBitKeyMaterial:
    """
    Phase 3 step 1: Alice generates her private key material for signing
    a single message bit -- two key sets of L random Pauli-eigenstate
    descriptions each.
    """
    def make_key_set() -> list[KeyQubit]:
        key_set = []
        for _ in range(L):
            basis = bases_pool[rng.integers(0, len(bases_pool))]
            eigen = int(rng.integers(0, 2))
            key_set.append(KeyQubit(basis=basis, eigen=eigen))
        return key_set

    return SingleBitKeyMaterial(key_set_0=make_key_set(), key_set_1=make_key_set())


def distribute_public_key(key_material: SingleBitKeyMaterial, rng: np.random.Generator,
                           bell_kind: str = "phi+") -> None:
    """
    Phase 3 step 2: teleports every qubit in both key sets to Bob.

    Mutates `key_material` in place, filling in each KeyQubit's
    `bob_state` and `teleport_fidelity`. In the honest, noiseless case,
    every teleport_fidelity should be 1.0 -- Bob's copy is exactly
    Alice's prepared eigenstate, he just doesn't know its description.
    """
    for key_set in (key_material.key_set_0, key_material.key_set_1):
        for key_qubit in key_set:
            alice_state = prepare_pauli_eigenstate(key_qubit.basis, key_qubit.eigen)
            result = teleport_qubit(alice_state, rng, bell_kind=bell_kind)
            key_qubit.bob_state = result["received_state"]
            key_qubit.teleport_fidelity = result["fidelity"]


@dataclass
class SignatureBit:
    """A signature for one message bit: the bit itself plus the fully
    disclosed classical description of the corresponding key set."""
    message_bit: int
    disclosed_descriptions: list[tuple[str, int]]  # [(basis, eigen), ...] length L


def sign_bit(key_material: SingleBitKeyMaterial, message_bit: int) -> SignatureBit:
    """
    Phase 3 step 3: Alice signs a single message bit by disclosing the
    classical description of KeySet_{message_bit} only.
    """
    if message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit}")

    key_set = key_material.key_set_0 if message_bit == 0 else key_material.key_set_1
    descriptions = [(kq.basis, kq.eigen) for kq in key_set]
    return SignatureBit(message_bit=message_bit, disclosed_descriptions=descriptions)


@dataclass
class VerificationResult:
    accepted: bool
    mismatch_count: int
    total_checked: int
    per_qubit_outcomes: list[tuple[int, int]] = field(default_factory=list)  # (measured, disclosed)


def verify_bit(key_material: SingleBitKeyMaterial, signature: SignatureBit,
               rng: np.random.Generator, mismatch_threshold: int = 0) -> VerificationResult:
    """
    Phase 3 step 4: Bob verifies a signed bit.

    NOTE: this function takes `key_material` directly (i.e. the object
    Bob's own qubits live on, filled in by distribute_public_key) rather
    than some separate "Bob's public key" object, since in this
    single-process simulation both Alice's and Bob's data live in the
    same KeyQubit objects for simplicity (bob_state is Bob's; basis/eigen
    are Alice's private description, which Bob only learns from the
    signature's disclosed_descriptions, NOT from key_material directly --
    verify_bit deliberately reads bob_state and the signature's disclosed
    values, never key_material's own .basis/.eigen fields, to accurately
    model what Bob actually has access to).

    `mismatch_threshold`: number of mismatched qubits still tolerated
    before rejecting. Defaults to 0, matching the honest, noiseless case
    where perfect agreement is expected. A future noisy-channel version
    (introduced when attacks/noise are modeled in Phase 5) would use a
    small positive threshold, calibrated in Phase 4.
    """
    key_set = key_material.key_set_0 if signature.message_bit == 0 else key_material.key_set_1

    if len(key_set) != len(signature.disclosed_descriptions):
        raise ValueError("Signature length does not match key set length.")

    mismatch_count = 0
    per_qubit_outcomes = []
    for key_qubit, (disclosed_basis, disclosed_eigen) in zip(key_set, signature.disclosed_descriptions):
        if key_qubit.bob_state is None:
            raise ValueError("Public key has not been distributed yet (bob_state is None). "
                              "Call distribute_public_key first.")
        measured_outcome, collapsed_state = measure_qubit_in_basis(
            key_qubit.bob_state, target=0, n_qubits=1,
            basis=disclosed_basis, rng=rng
        )
        key_qubit.bob_state = collapsed_state
        per_qubit_outcomes.append((measured_outcome, disclosed_eigen))
        if measured_outcome != disclosed_eigen:
            mismatch_count += 1

    accepted = mismatch_count <= mismatch_threshold
    return VerificationResult(
        accepted=accepted,
        mismatch_count=mismatch_count,
        total_checked=len(key_set),
        per_qubit_outcomes=per_qubit_outcomes,
    )
