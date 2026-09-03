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
import time
import uuid
import numpy as np

from core.qds_protocol import DEFAULT_BASES, SignatureBit, SingleBitKeyMaterial, distribute_public_key, generate_key_material, verify_bit


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _commitment(session_id: str, set_index: int, qubit_index: int,
                basis: str, eigen: int, opening_nonce: str) -> str:
    """Commit to one description with a secret high-entropy opening nonce.

    The nonce is deliberately absent from ``AuthenticatedPublicRecord`` and
    disclosed only with the selected key set in ``SecureSignature``. Without
    it, the six possible (basis, eigen) values cannot be checked against a
    public commitment by the old enumeration attack.
    """
    return hashlib.sha256(_canonical({"session_id": session_id, "set": set_index,
                                      "index": qubit_index, "basis": basis, "eigen": eigen,
                                      "opening_nonce": opening_nonce})).hexdigest()


@dataclass(frozen=True)
class AuthenticatedPublicRecord:
    session_id: str
    signer_id: str
    recipient_id: str
    commitments: tuple[tuple[str, ...], tuple[str, ...]]
    authentication_tag: str


@dataclass(frozen=True)
class VerifierAuthorization:
    """Signer-issued, time-limited authorization for one verifier."""
    authorization_id: str
    session_id: str
    signer_id: str
    verifier_id: str
    issued_at: float
    expires_at: float
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
    opening_nonces: tuple[str, ...]
    authorization: VerifierAuthorization | None = None


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
    _opening_nonces: tuple[tuple[str, ...], tuple[str, ...]] = field(repr=False)
    _used: bool = False

    @classmethod
    def create(cls, signer_id: str, recipient_id: str, L: int, rng: np.random.Generator,
               authentication_key: bytes) -> "SecureSession":
        if not signer_id or not recipient_id or L < 1 or not authentication_key:
            raise ValueError("signer_id, recipient_id, positive L, and authentication_key are required")
        key_material = generate_key_material(L, rng, DEFAULT_BASES)
        distribute_public_key(key_material, rng)
        session_id = uuid.uuid4().hex
        key_sets = (key_material.key_set_0, key_material.key_set_1)
        opening_nonces = tuple(tuple(secrets.token_hex(32) for _ in key_set)
                               for key_set in key_sets)
        commitments = tuple(
            tuple(_commitment(session_id, set_idx, index, q.basis, q.eigen,
                              opening_nonces[set_idx][index])
                  for index, q in enumerate(key_set))
            for set_idx, key_set in enumerate(key_sets)
        )
        body = {"session_id": session_id, "signer_id": signer_id, "recipient_id": recipient_id,
                "commitments": commitments}
        tag = hmac.new(authentication_key, _canonical(body), hashlib.sha256).hexdigest()
        return cls(signer_id, recipient_id, key_material,
                   AuthenticatedPublicRecord(session_id, signer_id, recipient_id, commitments, tag),
                   authentication_key, opening_nonces)

    def issue_authorization(self, verifier_id: str, ttl_seconds: float = 300.0) -> VerifierAuthorization:
        if not verifier_id or ttl_seconds <= 0:
            raise ValueError("verifier_id and a positive authorization TTL are required")
        issued = time.time()
        body = {"authorization_id": uuid.uuid4().hex, "session_id": self.public_record.session_id,
                "signer_id": self.signer_id, "verifier_id": verifier_id,
                "issued_at": issued, "expires_at": issued + ttl_seconds}
        tag = hmac.new(self._authentication_key, _canonical(body), hashlib.sha256).hexdigest()
        return VerifierAuthorization(authentication_tag=tag, **body)

    def sign(self, message_bit: int, payload: str,
             authorization: VerifierAuthorization | None = None) -> SecureSignature:
        if message_bit not in (0, 1):
            raise ValueError("message_bit must be 0 or 1")
        if self._used:
            raise ValueError("Session key material is one-time use and has already signed a message")
        authorization = authorization or self.issue_authorization(self.recipient_id)
        if authorization.session_id != self.public_record.session_id or authorization.verifier_id != self.recipient_id:
            raise ValueError("authorization does not belong to this session and recipient")
        self._used = True
        key_set = self.key_material.key_set_0 if message_bit == 0 else self.key_material.key_set_1
        return SecureSignature(self.public_record.session_id, secrets.token_urlsafe(18), self.signer_id,
                               self.recipient_id, message_bit,
                               hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                               tuple((q.basis, q.eigen) for q in key_set),
                               self._opening_nonces[message_bit], authorization)


@dataclass
class SecureVerifier:
    """Bob-side verifier with independent authentication and replay state."""
    recipient_id: str
    authentication_registry: dict[str, bytes]
    _records: dict[str, AuthenticatedPublicRecord] = field(default_factory=dict)
    _bob_key_material: dict[str, SingleBitKeyMaterial] = field(default_factory=dict, repr=False)
    _consumed_signature_ids: set[str] = field(default_factory=set)
    _consumed_authorization_ids: set[str] = field(default_factory=set)
    state_store: object | None = None

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
               mismatch_threshold: int = 0, memory_integrity_ok: bool = True) -> SecureVerificationResult:
        if not memory_integrity_ok:
            return SecureVerificationResult(False, "integrity failure: quantum memory tamper detected; verification aborted")
        record = self._records.get(signature.session_id)
        if record is None:
            return SecureVerificationResult(False, "unknown or unauthenticated distribution session")
        if signature.signature_id in self._consumed_signature_ids:
            return SecureVerificationResult(False, "replay detected: signature ID was already consumed")
        if signature.signer_id != record.signer_id or signature.recipient_id != self.recipient_id:
            return SecureVerificationResult(False, "signature identity binding failed")
        authorization = signature.authorization
        if authorization is None:
            return SecureVerificationResult(False, "verifier authorization is missing")
        auth_body = {"authorization_id": authorization.authorization_id,
                     "session_id": authorization.session_id, "signer_id": authorization.signer_id,
                     "verifier_id": authorization.verifier_id, "issued_at": authorization.issued_at,
                     "expires_at": authorization.expires_at}
        key = self.authentication_registry.get(record.signer_id)
        if (key is None or authorization.session_id != record.session_id
                or authorization.signer_id != record.signer_id
                or authorization.verifier_id != self.recipient_id
                or authorization.expires_at < time.time()
                or not hmac.compare_digest(hmac.new(key, _canonical(auth_body), hashlib.sha256).hexdigest(),
                                           authorization.authentication_tag)):
            return SecureVerificationResult(False, "verifier authorization failed or expired")
        if authorization.authorization_id in self._consumed_authorization_ids:
            return SecureVerificationResult(False, "replay detected: verifier authorization was already consumed")
        if signature.payload_digest != hashlib.sha256(payload.encode("utf-8")).hexdigest():
            return SecureVerificationResult(False, "payload integrity check failed")
        if signature.message_bit not in (0, 1):
            return SecureVerificationResult(False, "invalid message bit")
        commitments = record.commitments[signature.message_bit]
        if (len(commitments) != len(signature.disclosed_descriptions)
                or len(commitments) != len(signature.opening_nonces)):
            return SecureVerificationResult(False, "signature openings do not match committed key set length")
        for index, ((basis, eigen), opening_nonce) in enumerate(
                zip(signature.disclosed_descriptions, signature.opening_nonces)):
            if basis not in DEFAULT_BASES or eigen not in (0, 1) or not hmac.compare_digest(
                commitments[index], _commitment(signature.session_id, signature.message_bit, index,
                                                  basis, eigen, opening_nonce)
            ):
                return SecureVerificationResult(False, "key-description commitment check failed")
        # Consume both one-time identifiers before the physical measurement so
        # a failed quantum check cannot be retried with the same authorization.
        if self.state_store is not None:
            if not self.state_store.consume_authorization(authorization.authorization_id):
                return SecureVerificationResult(False, "replay detected: verifier authorization was already consumed")
            if not self.state_store.consume_signature(signature.signature_id):
                return SecureVerificationResult(False, "replay detected: signature ID was already consumed")
        self._consumed_authorization_ids.add(authorization.authorization_id)
        self._consumed_signature_ids.add(signature.signature_id)
        physical = verify_bit(self._bob_key_material[signature.session_id],
                              SignatureBit(signature.message_bit, list(signature.disclosed_descriptions)), rng,
                              mismatch_threshold=mismatch_threshold)
        if not physical.accepted:
            return SecureVerificationResult(False, "quantum mismatch threshold exceeded",
                                            physical.mismatch_count, mismatch_threshold)
        return SecureVerificationResult(True, "accepted", physical.mismatch_count, mismatch_threshold)
