"""
attacks/forgery.py

Phase 5: Forgery attack simulators.

Purpose
-------
Models an attacker (Meera) who wants to produce a valid-looking
signature for a message bit WITHOUT knowing Aditi's private key
material -- i.e. without knowing the true (basis, eigen) description of
any qubit in the target key set. Two forger strategies are modeled,
in increasing order of capability:

  1. BLIND FORGER (`blind_forgery_attempt`): has no physical access to
     the quantum channel at all -- e.g. someone who intercepted only the
     final classical signature transmission point and is trying to
     fabricate a signature from nothing. Guesses (basis, eigen) for each
     qubit uniformly at random, independent of everything.

  2. INTERCEPTING FORGER (`intercepting_forgery_attempt`): has physical
     access to (a copy of / the actual) qubits Bharat received during
     distribution -- e.g. Meera compromised the quantum channel itself,
     the same access level as the eavesdropper in
     attacks/intercept_resend.py, but uses it to FORGE a signature
     rather than just to snoop. She measures each qubit in ANY basis
     (the choice doesn't even matter -- see finding below) and
     truthfully discloses that basis together with her measured
     outcome.

*** SECOND, MORE SERIOUS FINDING (found empirically while implementing
this function -- my own first draft of this docstring initially claimed
a 2/3 per-qubit success rate for the intercepting forger, using the
same flawed "Bharat checks against Aditi's true basis" assumption the
Phase 3 docstring made; that first draft was also wrong) ***

verify_bit() does not measure in Aditi's true secret basis -- it has no
way to, since Bharat never learns it independently of the disclosure. It
always measures in whatever basis the SIGNATURE discloses. So once the
intercepting forger has measured a qubit in some basis B and disclosed
(B, her own outcome), Bharat's "verification" is a SECOND measurement of
the SAME (now-collapsed) qubit in that SAME basis B -- and repeated
measurement of an eigenstate in its own basis is deterministic. The
forger's basis guess doesn't need to match Aditi's true basis at all;
she just needs to measure once, honestly, in any basis, and report what
she saw.

  INTERCEPT_FORGE_SUCCESS_PROB = 1.0 -- exactly, independent of L.

Confirmed empirically in tests/test_attacks.py (100% success across
100k+ trials, not the 2/3 a same-basis-only analysis would predict).
This is an L-INDEPENDENT total break of the signature scheme's
unforgeability against any attacker with physical access to Bharat's
stored qubits before verification -- adding more key qubits (raising L)
does not help against this attacker at all, unlike the blind-forger
case where (1/2)^L shrinks with L. The scheme's forgery-resistance
therefore rests entirely on an assumption external to the classical
disclosure/verification logic: that the quantum channel and Bharat's
qubit storage are physically inaccessible to attackers before
verification. This is worth carrying into Phase 7's security writeup
as a first-class result, not a footnote.

*** CORRECTS A BUG IN THE PHASE 3 DOCSTRING (core/qds_protocol.py) ***
core/qds_protocol.py's module docstring claims the blind forger's
per-qubit success probability is 1/6, giving a (1/6)^L bound. This is
WRONG. verify_bit() does not check whether the forger's claimed
(basis, eigen) equals Aditi's true (basis, eigen) -- it measures Bharat's
REAL qubit in whatever basis the forger claims and compares to whatever
eigenvalue the forger claims. Walking the two cases for a single qubit:

  - Forger's guessed basis matches the true basis (prob 1/3): the
    measurement is then deterministic and equals the true eigenvalue,
    so the forger succeeds iff her guessed eigenvalue also matches
    (prob 1/2, since eigen is an independent uniform secret bit).
    Contributes (1/3)(1/2) = 1/6.
  - Forger's guessed basis does NOT match the true basis (prob 2/3):
    mismatched-basis measurement of a Pauli eigenstate is exactly 50/50
    REGARDLESS of the claimed eigenvalue -- it is not an automatic
    failure. Contributes (2/3)(1/2) = 1/3.

  Total per-qubit blind-forgery success probability = 1/6 + 1/3 = 1/2,
  NOT 1/6. Confirmed empirically in tests/test_attacks.py (matches
  within statistical noise over 100k+ trials). The correct forgery
  bound for an L-qubit key set against a blind forger is (1/2)^L, a
  substantially weaker security margin than (1/6)^L claimed in Phase 3
  -- e.g. matching 2^-128 forgery probability requires L=128 under the
  correct bound, not L~50 as the wrong bound would suggest. See
  core/qds_protocol.py's corrected docstring for the fixed statement.

BLIND_FORGE_SUCCESS_PROB / INTERCEPT_FORGE_SUCCESS_PROB below are the
analytic constants Phase 6 (attack validation) and Phase 7 (security
writeup) should treat as ground truth.
"""

from __future__ import annotations
import numpy as np

from core.primitives import measure_qubit_in_basis
from core.qds_protocol import (
    SingleBitKeyMaterial, SignatureBit, DEFAULT_BASES,
)

# Analytic per-qubit success probabilities (see module docstring for
# derivations). Single source of truth for tests and later phases.
BLIND_FORGE_SUCCESS_PROB = 0.5    # was wrongly documented as 1/6 in Phase 3
INTERCEPT_FORGE_SUCCESS_PROB = 1.0  # L-independent; see module docstring


def blind_forgery_attempt(L: int, message_bit: int, rng: np.random.Generator,
                           bases_pool: tuple[str, ...] = DEFAULT_BASES) -> SignatureBit:
    """
    Produces a forged SignatureBit with no physical access to any qubit
    and no knowledge of Aditi's private key material: guesses
    (basis, eigen) uniformly and independently for each of L qubits.

    Per-qubit success probability against a real bharat_state is
    BLIND_FORGE_SUCCESS_PROB = 1/2 (see module docstring), so the whole
    L-qubit forgery succeeds with probability (1/2)^L -- call
    core.qds_protocol.verify_bit(key_material, this_signature, rng,
    mismatch_threshold=0) to check a specific attempt.
    """
    if message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit}")

    descriptions = [
        (bases_pool[rng.integers(0, len(bases_pool))], int(rng.integers(0, 2)))
        for _ in range(L)
    ]
    return SignatureBit(message_bit=message_bit, disclosed_descriptions=descriptions)


def intercepting_forgery_attempt(key_material: SingleBitKeyMaterial, message_bit: int,
                                  rng: np.random.Generator,
                                  bases_pool: tuple[str, ...] = DEFAULT_BASES) -> SignatureBit:
    """
    A strictly stronger forger: has physical access to Bharat's actual
    received qubits (kq.bharat_state) for the target key set -- e.g. she
    compromised the quantum channel during distribution, same access
    level as attacks/intercept_resend.py's eavesdropper, but spends it
    on forging a signature herself rather than passing qubits on to Bharat.

    For each qubit she measures kq.bharat_state in a basis chosen uniformly
    at random (the choice does not actually affect her success rate --
    see module docstring), and reports her OWN measured outcome as her
    claimed eigenvalue -- rather than guessing the eigenvalue blindly,
    she uses what she actually observed.

    NOTE: like attacks/intercept_resend.py, this deliberately never
    reads kq.basis / kq.eigen -- only kq.bharat_state -- so the attack logic
    itself has no access to Aditi's private description, only to the
    physical qubit.

    IMPORTANT CAVEAT: this function measures (and therefore collapses)
    key_material's actual bharat_state qubits as a side effect, exactly
    like a real physical measurement would. If Bharat later verifies
    against the SAME key_material object, he is measuring
    Meera's already-collapsed qubits, not fresh honest ones -- this
    correctly models "Meera intercepted the channel," NOT "Meera
    forged a signature while leaving Bharat's real qubits untouched" (that
    weaker threat model is what blind_forgery_attempt models instead,
    for a forger with no channel access at all).

    Per-qubit success probability is INTERCEPT_FORGE_SUCCESS_PROB = 1.0,
    independent of which basis she guesses and independent of L: since
    verify_bit() always measures in whatever basis the signature
    discloses (never independently against Aditi's true secret basis),
    the forger's own measurement IS the verification-relevant collapse
    -- she just needs to report what she actually saw. See module
    docstring for the full derivation; this is the more serious of the
    two findings in this file.
    """
    if message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit}")

    key_set = key_material.key_set_0 if message_bit == 0 else key_material.key_set_1
    descriptions = []
    for kq in key_set:
        if kq.bharat_state is None:
            raise ValueError(
                "Public key has not been distributed yet (bharat_state is None). "
                "Call distribute_public_key before intercepting_forgery_attempt."
            )
        guessed_basis = bases_pool[rng.integers(0, len(bases_pool))]
        measured_eigen, collapsed = measure_qubit_in_basis(
            kq.bharat_state.copy(), target=0, n_qubits=1,
            basis=guessed_basis, rng=rng
        )
        kq.bharat_state = collapsed  # her measurement is a real, collapsing act
        descriptions.append((guessed_basis, measured_eigen))

    return SignatureBit(message_bit=message_bit, disclosed_descriptions=descriptions)
