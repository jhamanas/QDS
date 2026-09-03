"""
attacks/replay.py

Phase 5: Replay / key-reuse attack simulator.

Purpose
-------
core/qds_protocol.py's module docstring explicitly calls this out:

    "KeySet_{1-m} is never disclosed and should be discarded after use
    (one-time signature -- reusing key material breaks the security
    argument, which is exactly what the Phase 5 replay-attack simulator
    will exploit)."

This module implements that exploit directly. The QDS scheme here is a
Lamport-style ONE-TIME signature: each SingleBitKeyMaterial object may
safely sign exactly one message bit. Signing discloses the FULL
(basis, eigen) description of one entire key set -- that is not a
partial leak, it is total transparency of everything Bharat needs to
verify that bit. If the SAME key_material is (incorrectly) reused to
sign a SECOND message bit, an observer who captures both signatures now
holds the complete, exact private description of BOTH key_set_0 and
key_set_1 -- there is nothing left unknown about that key_material at
all.

Two distinct exploits are modeled:

  1. `naive_replay`: the simpler case -- an attacker who merely captured
     a single valid (message_bit, signature) pair resubmits the EXACT
     same pair again later. verify_bit has no freshness/nonce check, so
     it is accepted identically every time it is resubmitted against
     the same key_material. This doesn't require any key reuse by
     Aditi -- it exploits the total absence of a replay-protection
     mechanism in the verification logic itself.

  2. `key_reuse_attack`: the scenario the Phase 3 docstring specifically
     warned about -- Aditi (or a system built on this protocol) reuses
     the same key_material to sign BOTH possible message bits. The
     resulting pair of captured signatures gives an attacker Aditi's
     ENTIRE private key material for that session: every (basis, eigen)
     for every qubit in both key sets. This is a complete break, not a
     probabilistic one -- there is no forgery probability to compute
     here because nothing is being guessed anymore.

Neither exploit produces any measurement disturbance (mismatch_count
stays 0 throughout), so -- like forgery and impersonation, and unlike
intercept-resend -- NEITHER is detectable by the Phase 4 statistical
QBER detector. Both are entirely a matter of protocol/deployment
discipline: never reuse a SingleBitKeyMaterial object, and track which
(key_material, signature) pairs have already been consumed.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np

from core.qds_protocol import (
    SingleBitKeyMaterial, SignatureBit, VerificationResult,
    sign_bit, verify_bit,
)


def naive_replay(key_material: SingleBitKeyMaterial, captured_signature: SignatureBit,
                  rng: np.random.Generator, mismatch_threshold: int = 0) -> VerificationResult:
    """
    Resubmits an already-used, previously captured signature against the
    SAME key_material it was originally issued for. Nothing about the
    signature or key material is modified -- this models an attacker (or
    a buggy/malicious client) simply sending the identical message a
    second time. Since core.qds_protocol.verify_bit performs no
    freshness check (no nonce, no "already verified" bookkeeping), this
    is accepted on every resubmission, indistinguishably from the first,
    legitimate one.
    """
    return verify_bit(key_material, captured_signature, rng, mismatch_threshold=mismatch_threshold)


@dataclass
class KeyReuseExposure:
    """Everything an attacker learns by observing two signatures over
    the same (mis-used) key_material -- Aditi's ENTIRE private
    description for both key sets. There is no residual secrecy left to
    quantify probabilistically."""
    key_set_0_descriptions: list[tuple[str, int]]
    key_set_1_descriptions: list[tuple[str, int]]
    sig_bit_0: SignatureBit
    sig_bit_1: SignatureBit

    def fully_exposed(self) -> bool:
        """Sanity/diagnostic check: True if both key sets' descriptions
        were fully captured (length matches, every entry present) --
        i.e. the exposure is total, not partial."""
        return (len(self.key_set_0_descriptions) == len(self.sig_bit_0.disclosed_descriptions)
                and len(self.key_set_1_descriptions) == len(self.sig_bit_1.disclosed_descriptions))


def key_reuse_attack(key_material: SingleBitKeyMaterial, rng: np.random.Generator) -> KeyReuseExposure:
    """
    Simulates the one-time-key violation the Phase 3 docstring warns
    about: the SAME key_material is used to honestly sign BOTH message
    bits (0 and 1) -- something a correct deployment must never do, but
    which this function demonstrates the consequences of if it happens
    (e.g. a bug that fails to discard key_material after first use, or a
    system that signs multiple messages per key_material to save on key
    generation cost).

    Calls the SAME honest core.qds_protocol.sign_bit function Aditi
    would use, twice, against the same key_material -- deliberately, to
    show this requires no attacker cleverness at all. An attacker who
    merely observes both resulting signatures (e.g. on a public
    broadcast channel, which is how signatures are meant to be
    verifiable by third parties in the first place) now holds the
    complete private description of every qubit in both key sets.

    Returns a KeyReuseExposure recording exactly what was captured, for
    tests/test_attacks.py to confirm the exposure is total.
    """
    sig0 = sign_bit(key_material, message_bit=0)
    sig1 = sign_bit(key_material, message_bit=1)

    return KeyReuseExposure(
        key_set_0_descriptions=list(sig0.disclosed_descriptions),
        key_set_1_descriptions=list(sig1.disclosed_descriptions),
        sig_bit_0=sig0,
        sig_bit_1=sig1,
    )
