"""
attacks/impersonation.py

Phase 5 (completion): Impersonation attack simulator.

Purpose
-------
Every attack so far (attacks/intercept_resend.py, attacks/forgery.py)
assumes a REAL, honest Aditi has already generated key material and
distributed it, and the attacker interferes with that transmission or
tries to forge a disclosure against it. This module models a different,
more basic threat: Meera never touches Aditi's real channel at all --
she simply runs the ENTIRE honest protocol herself (key generation,
distribution, signing) and presents the result to Bharat AS IF it came
from Aditi.

Why this works (a protocol-design gap, not an implementation bug)
-------------------------------------------------------------------
core/qds_protocol.py's `distribute_public_key` and `verify_bit` never
bind the distributed qubits to any Aditi-specific credential. There is
no classical PKI signature over the distribution event, no pre-shared
authenticated channel, and no identity check anywhere in the honest
path (by design -- Phase 3 only aimed to get signing/verification
correct assuming the source is already trusted). `verify_bit` only
checks INTERNAL self-consistency: does the measured qubit match the
disclosed description. It has no way to ask "did this quantum public
key actually originate from Aditi." So a completely independent,
internally-consistent run of the honest protocol -- with Meera
standing in for Aditi -- looks EXACTLY like a legitimate one to Bharat.

    P(impersonation succeeds) = 1.0, independent of L,
    independent of channel noise, independent of the Phase 4 detector
    (there is no disturbance to detect -- Meera's run is honest by
    construction, just from the wrong person).

This is the third distinct way this scheme can fail, alongside the
blind-forger bound (Phase 5/attacks/forgery.py, mitigated by large L)
and the intercepting-forger break (Phase 5/attacks/forgery.py,
mitigated only by physical channel security). Impersonation is
mitigated only by a mechanism OUTSIDE this module's scope entirely: an
authenticated classical channel or PKI binding "this quantum
transmission came from Aditi" to the distribution event, before Bharat
accepts any qubits as Aditi's public key. Nothing in core/qds_protocol.py
provides that binding, so it must be supplied by the deployment layer.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np

from core.qds_protocol import (
    SingleBitKeyMaterial, SignatureBit,
    generate_key_material, distribute_public_key, sign_bit,
)

# Analytic constant (see module docstring for derivation). Single source
# of truth for tests and evaluation/security_analysis.py, matching the
# pattern used in attacks/forgery.py.
IMPERSONATION_SUCCESS_PROB = 1.0


@dataclass
class ImpersonationAttempt:
    """The forged key material and signature Meera presents to Bharat as
    if they came from Aditi, plus a note on what would be needed to
    actually distinguish them from a legitimate run (nothing internal
    to the protocol does)."""
    forged_key_material: SingleBitKeyMaterial
    forged_signature: SignatureBit
    message_bit: int


def impersonation_attack(L: int, message_bit: int, rng: np.random.Generator) -> ImpersonationAttempt:
    """
    Meera runs the complete honest protocol herself -- generate_key_material,
    distribute_public_key, sign_bit -- exactly as Aditi would, and the
    result is handed to Bharat as "Aditi's" quantum public key and signature.

    Deliberately calls the SAME honest-path functions Aditi uses (not a
    parallel implementation) to make the point precisely: there is
    nothing different about Meera's run at the protocol level. Any
    verifier calling core.qds_protocol.verify_bit against
    forged_key_material / forged_signature will accept it exactly as
    readily as a genuine Aditi-originated signature, because the two are
    computationally and physically identical -- the only thing that
    differs is WHO ran the key generation, which the protocol as
    specified has no way to check.
    """
    if message_bit not in (0, 1):
        raise ValueError(f"message_bit must be 0 or 1, got {message_bit}")

    forged_key_material = generate_key_material(L, rng)
    distribute_public_key(forged_key_material, rng)
    forged_signature = sign_bit(forged_key_material, message_bit)

    return ImpersonationAttempt(
        forged_key_material=forged_key_material,
        forged_signature=forged_signature,
        message_bit=message_bit,
    )
