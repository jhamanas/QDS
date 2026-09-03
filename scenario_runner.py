"""Shared scenario execution used by the CLI and local dashboard."""
from __future__ import annotations
import hashlib
import secrets
import numpy as np
from attacks.forgery import blind_forgery_attempt, intercepting_forgery_attempt
from attacks.intercept_resend import intercept_resend_attack
from attacks.unauthorized_verification import unauthorized_verification_attack
from core.noise import apply_noise
from core.secure_protocol import SecureSession, SecureSignature, SecureVerifier
ATTACKS = ("honest", "intercept-resend", "blind-forgery", "intercepting-forgery", "impersonation", "replay", "key-reuse", "payload-tamper", "unauthorized-verification", "memory-tamper")
def run_scenario(*, attack="honest", intensity=1.0, length=64, noise=0.0, threshold=0, message_bit=0, payload="authorise-transfer:100", seed=7, state_store=None, audit_store=None, noise_model="depolarizing"):
    if attack not in ATTACKS: raise ValueError(f"Unknown attack: {attack}")
    if not 0 <= intensity <= 1 or not 0 <= noise <= 1 or threshold < 0 or length < 1: raise ValueError("intensity/noise must be in [0, 1]; threshold >= 0; length >= 1")
    if noise_model not in ("depolarizing", "bit-flip", "phase-flip"): raise ValueError("Unknown noise model")
    rng=np.random.default_rng(seed); key=secrets.token_bytes(32); verifier=SecureVerifier("bharat", {"aditi":key}, state_store=state_store); session=SecureSession.create("aditi","bharat",length,rng,key); verifier.register_distribution(session)
    data={"attack":attack,"length":length,"intensity":intensity,"noise":noise,"noise_model":noise_model,"threshold":threshold,"message_bit":message_bit}
    if attack=="impersonation":
        meera=SecureSession.create("meera","bharat",length,rng,secrets.token_bytes(32)); result=verifier.verify(meera.sign(message_bit,payload),payload,rng,threshold)
    else:
        if attack=="intercept-resend": data["qubits_intercepted"]=len(intercept_resend_attack(session.key_material,rng,intensity))
        if noise:
            for ks in (session.key_material.key_set_0,session.key_material.key_set_1):
                for q in ks: q.bharat_state=apply_noise(q.bharat_state,noise,0,1,rng,noise_model)
        sig=session.sign(message_bit,payload)
        if attack in ("blind-forgery","intercepting-forgery"):
            legacy=blind_forgery_attempt(length,message_bit,rng) if attack=="blind-forgery" else intercepting_forgery_attempt(session.key_material,message_bit,rng)
            # Intensity is the fraction of key descriptions controlled by the
            # attacker; untouched entries retain Aditi's honest disclosure.
            controlled = int(round(length * intensity))
            descriptions = list(sig.disclosed_descriptions)
            descriptions[:controlled] = legacy.disclosed_descriptions[:controlled]
            sig=SecureSignature(sig.session_id,sig.signature_id,"aditi","bharat",message_bit,sig.payload_digest,tuple(descriptions),sig.opening_nonces,sig.authorization)
        if attack == "memory-tamper":
            result = verifier.verify(sig, payload, rng, threshold, memory_integrity_ok=False)
        elif attack == "unauthorized-verification":
            result = unauthorized_verification_attack(session, payload, rng, threshold, signature=sig)
        else:
            result=verifier.verify(sig,payload+"-tampered" if attack=="payload-tamper" else payload,rng,threshold)
        if attack=="replay": result=verifier.verify(sig,payload,rng,threshold)
        if attack=="key-reuse":
            try: session.sign(1-message_bit,payload); data["key_reuse_prevented"]=False
            except ValueError: data["key_reuse_prevented"]=True
    data.update({"accepted":result.accepted,"reason":result.reason,"mismatch_count":result.mismatch_count,"mismatch_threshold":result.mismatch_threshold,"mismatch_rate":result.mismatch_count/length,
                 # Correlation fields are safe to show in an investigation view;
                 # the payload itself and all key material stay out of the log.
                 "session_id": session.public_record.session_id,
                 "signature_id": sig.signature_id if attack != "impersonation" else None,
                 "payload_digest": hashlib.sha256(payload.encode("utf-8")).hexdigest()})
    if audit_store is not None:
        data["audit_event"] = audit_store.record_audit_event({
            "attack": attack, "accepted": result.accepted, "reason": result.reason,
            "length": length, "intensity": intensity, "noise": noise,
            "noise_model": noise_model, "threshold": threshold,
            "mismatch_count": result.mismatch_count,
            "mismatch_threshold": result.mismatch_threshold,
            "mismatch_rate": result.mismatch_count / length,
            "session_id": session.public_record.session_id,
            "signature_id": sig.signature_id if attack != "impersonation" else None,
            "payload_digest": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        })
    return data
