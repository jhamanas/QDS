"""Run a selectable attack scenario against the hardened QDS layer."""
from __future__ import annotations
import argparse, json, secrets, sys
import numpy as np
from attacks.forgery import blind_forgery_attempt, intercepting_forgery_attempt
from attacks.intercept_resend import intercept_resend_attack
from core.noise import apply_depolarizing_noise
from core.secure_protocol import SecureSession, SecureSignature, SecureVerifier


def main() -> int:
    p = argparse.ArgumentParser(description="QDS hardened-protocol attack simulator")
    p.add_argument("--attack", choices=("honest", "intercept-resend", "blind-forgery", "intercepting-forgery", "impersonation", "replay", "key-reuse", "payload-tamper", "unauthorized-verification"), default="honest")
    p.add_argument("--intensity", type=float, default=1.0, help="fraction intercepted (0 to 1)")
    p.add_argument("--length", type=int, default=64); p.add_argument("--noise", type=float, default=0.0)
    p.add_argument("--threshold", type=int, default=0); p.add_argument("--message-bit", type=int, choices=(0, 1), default=0)
    p.add_argument("--payload", default="authorise-transfer:100"); p.add_argument("--seed", type=int, default=7)
    a = p.parse_args()
    if not 0 <= a.intensity <= 1 or not 0 <= a.noise <= 1 or a.threshold < 0:
        p.error("intensity/noise must be in [0, 1], and threshold must be non-negative")
    rng = np.random.default_rng(a.seed); alice_key = secrets.token_bytes(32)
    verifier = SecureVerifier("bob", {"alice": alice_key})
    session = SecureSession.create("alice", "bob", a.length, rng, alice_key); verifier.register_distribution(session)
    details = {"attack": a.attack, "length": a.length, "intensity": a.intensity, "noise": a.noise}
    if a.attack == "impersonation":
        mallory = SecureSession.create("mallory", "bob", a.length, rng, secrets.token_bytes(32))
        result = verifier.verify(mallory.sign(a.message_bit, a.payload), a.payload, rng, a.threshold)
    else:
        if a.attack == "intercept-resend": details["qubits_intercepted"] = len(intercept_resend_attack(session.key_material, rng, a.intensity))
        if a.noise:
            for key_set in (session.key_material.key_set_0, session.key_material.key_set_1):
                for qubit in key_set: qubit.bob_state = apply_depolarizing_noise(qubit.bob_state, a.noise, 0, 1, rng)
        sig = session.sign(a.message_bit, a.payload)
        if a.attack in ("blind-forgery", "intercepting-forgery"):
            legacy = (blind_forgery_attempt(a.length, a.message_bit, rng) if a.attack == "blind-forgery" else intercepting_forgery_attempt(session.key_material, a.message_bit, rng))
            sig = SecureSignature(sig.session_id, sig.signature_id, "alice", "bob", a.message_bit, sig.payload_digest, tuple(legacy.disclosed_descriptions))
        target = (SecureVerifier("eve", {"alice": alice_key})
                  if a.attack == "unauthorized-verification" else verifier)
        result = target.verify(sig, a.payload + "-tampered" if a.attack == "payload-tamper" else a.payload, rng, a.threshold)
        if a.attack == "replay": result = verifier.verify(sig, a.payload, rng, a.threshold)
        if a.attack == "key-reuse":
            try: session.sign(1 - a.message_bit, a.payload); details["key_reuse_prevented"] = False
            except ValueError: details["key_reuse_prevented"] = True
    details.update({"accepted": result.accepted, "reason": result.reason, "mismatch_count": result.mismatch_count, "mismatch_threshold": result.mismatch_threshold})
    print(json.dumps(details, indent=2)); return 0

if __name__ == "__main__": sys.exit(main())
