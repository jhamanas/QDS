"""Hardened session layer for the QDS simulator.

The original ``qds_protocol`` module is retained as a minimal protocol and
attack-study model. This module adds deployment controls: authenticated key
distribution records, commitments to the original Pauli descriptions, payload
binding, and single-use signatures.

The commitment and HMAC authentication are explicit classical stand-ins for
an authenticated channel and immutable public-key registry; they do not make
the toy statevector protocol a production-grade QDS implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import secrets
import uuid
import numpy as np

from core.qds_protocol import DEFAULT_BASES, SignatureBit, SingleBitKeyMaterial, distribute_public_key, generate_key_material, verify_bit


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _commitment(session_id: str, set_index: int, qubit_index: int, basis: str, eigen: int) -> str:
    return hashlib.sha256(_canonical({"session_id": session_id, "set": set_index,
                                      "index": qubit_index, "basis": basis, "eigen": eigen})).hexdigest()


@dataclass(frozen=True)
class AuthenticatedPublicRecord:
    session_id: str
    signer_id: str
    recipient_id: str
    commitments: tuple[tuple[str, ...], tuple[str, ...]]
    authentication_tag: str


@dataclass(frozen=True)
class SecureSignature:
    session_id: str
    signature_id: str
    signer_id: str
    recipient_id: str
    message_bit: int
    payload_digest: str
    disclosed_descriptions: tuple[tuple[str, int], ...]


@dataclass
class SecureVerificationResult:
    accepted: bool
    reason: str
    mismatch_count: int = 0
    mismatch_threshold: int = 0


@dataclass
class SecureSession:
    """Alice-side session. Its key material can issue exactly one signature."""
    signer_id: str
    recipient_id: str
    key_material: SingleBitKeyMaterial
    public_record: AuthenticatedPublicRecord
    _authentication_key: bytes = field(repr=False)
    _used: bool = False

    @classmethod
    def create(cls, signer_id: str, recipient_id: str, L: int, rng: np.random.Generator,
               authentication_key: bytes) -> "SecureSession":
        if not signer_id or not recipient_id or L < 1 or not authentication_key:
            raise ValueError("signer_id, recipient_id, positive L, and authentication_key are required")
        key_material = generate_key_material(L, rng, DEFAULT_BASES)
        distribute_public_key(key_material, rng)
        session_id = uuid.uuid4().hex
        commitments = tuple(tuple(_commitment(session_id, set_idx, index, q.basis, q.eigen)
                                  for index, q in enumerate(key_set))
                            for set_idx, key_set in enumerate((key_material.key_set_0, key_material.key_set_1)))
        body = {"session_id": session_id, "signer_id": signer_id, "recipient_id": recipient_id,
                "commitments": commitments}
        tag = hmac.new(authentication_key, _canonical(body), hashlib.sha256).hexdigest()
        return cls(signer_id, recipient_id, key_material,
                   AuthenticatedPublicRecord(session_id, signer_id, recipient_id, commitments, tag),
                   authentication_key)

    def sign(self, message_bit: int, payload: str) -> SecureSignature:
        if message_bit not in (0, 1):
            raise ValueError("message_bit must be 0 or 1")
        if self._used:
            raise ValueError("Session key material is one-time use and has already signed a message")
        self._used = True
        key_set = self.key_material.key_set_0 if message_bit == 0 else self.key_material.key_set_1
        return SecureSignature(self.public_record.session_id, secrets.token_urlsafe(18), self.signer_id,
                               self.recipient_id, message_bit,
                               hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                               tuple((q.basis, q.eigen) for q in key_set))


@dataclass
class SecureVerifier:
    """Bob-side verifier with independent authentication and replay state."""
    recipient_id: str
    authentication_registry: dict[str, bytes]
    _records: dict[str, AuthenticatedPublicRecord] = field(default_factory=dict)
    _bob_key_material: dict[str, SingleBitKeyMaterial] = field(default_factory=dict, repr=False)
    _consumed_signature_ids: set[str] = field(default_factory=set)

    def register_distribution(self, session: SecureSession) -> None:
        record = session.public_record
        key = self.authentication_registry.get(record.signer_id)
        body = {"session_id": record.session_id, "signer_id": record.signer_id,
                "recipient_id": record.recipient_id, "commitments": record.commitments}
        if key is None or not hmac.compare_digest(
            hmac.new(key, _canonical(body), hashlib.sha256).hexdigest(), record.authentication_tag
        ):
            raise ValueError("Distribution record authentication failed")
        if record.recipient_id != self.recipient_id:
            raise ValueError("Distribution record is addressed to a different recipient")
        self._records[record.session_id] = record
        self._bob_key_material[record.session_id] = session.key_material

    def verify(self, signature: SecureSignature, payload: str, rng: np.random.Generator,
               mismatch_threshold: int = 0) -> SecureVerificationResult:
        record = self._records.get(signature.session_id)
        if record is None:
            return SecureVerificationResult(False, "unknown or unauthenticated distribution session")
        if signature.signature_id in self._consumed_signature_ids:
            return SecureVerificationResult(False, "replay detected: signature ID was already consumed")
        if signature.signer_id != record.signer_id or signature.recipient_id != self.recipient_id:
            return SecureVerificationResult(False, "signature identity binding failed")
        if signature.payload_digest != hashlib.sha256(payload.encode("utf-8")).hexdigest():
            return SecureVerificationResult(False, "payload integrity check failed")
        if signature.message_bit not in (0, 1):
            return SecureVerificationResult(False, "invalid message bit")
        commitments = record.commitments[signature.message_bit]
        if len(commitments) != len(signature.disclosed_descriptions):
            return SecureVerificationResult(False, "signature length does not match committed key set")
        for index, (basis, eigen) in enumerate(signature.disclosed_descriptions):
            if basis not in DEFAULT_BASES or eigen not in (0, 1) or not hmac.compare_digest(
                commitments[index], _commitment(signature.session_id, signature.message_bit, index, basis, eigen)
            ):
                return SecureVerificationResult(False, "key-description commitment check failed")
        physical = verify_bit(self._bob_key_material[signature.session_id],
                              SignatureBit(signature.message_bit, list(signature.disclosed_descriptions)), rng,
                              mismatch_threshold=mismatch_threshold)
        self._consumed_signature_ids.add(signature.signature_id)
        if not physical.accepted:
            return SecureVerificationResult(False, "quantum mismatch threshold exceeded",
                                            physical.mismatch_count, mismatch_threshold)
        return SecureVerificationResult(True, "accepted", physical.mismatch_count, mismatch_threshold)
