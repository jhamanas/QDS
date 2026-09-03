# Final Report — Quantum-Inspired Threat Detection Framework

## Scope

This repository is an educational quantum-inspired simulation and evaluation
framework. It implements a small NumPy statevector simulator, ideal
teleportation, a one-bit QDS-inspired disclosure model, stochastic Pauli-noise
experiments, a mismatch-count (QBER) detector, attack scenarios, and a local
dashboard. It is not a complete, standardized, production-ready, or formally
secure Quantum Digital Signature implementation.

The project deliberately distinguishes two layers:

- `core/qds_protocol.py` is the legacy simulator model used for the
  attack/detection experiments.
- `core/secure_protocol.py` adds operational controls for dashboard scenarios:
  nonce-based commitments, HMAC-authenticated distribution records, payload
  binding, verifier authorization, and one-time replay controls.

HMAC is a shared-secret authenticated-channel stand-in; it is not a public
digital signature and does not establish transferability or non-repudiation.

## Current reproducible evaluation

Run `python -m evaluation.regenerate_results` from the repository root to
produce the checked-in evaluation artifacts. The fixed evaluation uses
`L=64`, channel-noise probability `p=0.03`, seed `20260903`, 200 calibration
trials, and 100 attack trials. The command records the commit, environment,
artifact hashes, and seed in `results/reproducibility.json`.

The stochastic Pauli channel gives a same-basis mismatch probability of
`2p/3`; at `p=0.03` this is `0.02`. Independent ordinary channel noise is
applied to both honest calibration and attack trials, so the reported sweep is
for the combined noise-plus-attack condition.

The regenerated `results/security_analysis.json` reports, for this reference
configuration:

| Measure | Value |
|---|---:|
| Calibrated mismatch threshold | 9 |
| Binomial honest false-reject bound | 5.78 × 10⁻⁷ |
| Blind-forgery acceptance bound at threshold 0 | 5.42 × 10⁻²⁰ |
| Blind-forgery acceptance bound at threshold 9 | 1.77 × 10⁻⁹ |
| Recommended legacy-model `L` for a 2⁻⁴⁰ target | 81 |

These are simulation/model results, not deployment security parameters. In
particular, increasing `L` does not address attacks outside the legacy
disclosure model.

## What the detector does—and does not—detect

The QBER detector measures channel disturbance. It is useful for the
intercept-resend model, where the regenerated sweep at `p=0.03` detects 0%,
15%, 81%, 99%, and 100% of trials at intercept fractions 0.10, 0.25, 0.50,
0.75, and 1.00 respectively (100 trials per point; see
`results/detection_results.json` for all points).

It is not a general attack detector. A replay, an identity/authorization
failure, or an attacker controlling a stored state can leave no ordinary
channel-disturbance signal. In the hardened layer these are stopped by
authorization, commitment, integrity, or replay controls rather than QBER.
Blind-forgery rejection in the legacy model is also not an independent QBER
capability: a bad disclosure simply yields a high mismatch count.

## Commitment and state-lifecycle position

Each secure-session commitment includes a secret, per-qubit 256-bit opening
nonce. The nonce is not present in the public distribution record, is revealed
only with a selected signature opening, and is checked before state
measurement. Tests cover the former six-candidate enumeration regression,
valid openings, and tampered openings. This prevents the former low-entropy
enumeration shortcut under the SHA-256/nonce-secrecy assumptions; it does not
constitute a QDS security proof.

The base statevector model remains reusable by design: it measures a copy of a
stored state so experiments can be repeated. It therefore does not model
physical quantum-state consumption. The hardened session consumes signature
and authorization identifiers before verification, which provides operational
replay protection within its configured state store but does not change that
simulation boundary.

## Verification and operational checks

The full script-style suite is run from the repository root with:

```powershell
Get-ChildItem tests/test_*.py | ForEach-Object { python $_.FullName }
```

It includes primitives, teleportation, protocol, detector, attack, noise,
metrics, secure-session, authorization, memory-tamper, state-store, SOC/audit,
security-analysis, and performance checks. The dashboard is exercised against
honest, intercept-resend, blind-forgery, replay, and key-reuse scenarios; its
result view distinguishes a prevented key-reuse attempt from the valid initial
signature.

## Further reading

| Topic | Location |
|---|---|
| Architecture and module map | `docs/architecture.md`, `docs/CANONICAL_MODULES.md` |
| Mathematical model and scope boundaries | `docs/protocol_math.md` |
| Reproduction configuration and provenance | `docs/reproducibility.md` |
| Generated detection and security data | `results/detection_results.json`, `results/security_analysis.json` |
| Historical audit and remediation trail | `docs/QDS_TECHNICAL_AUDIT.md`, `docs/REMEDIATION_PLAN.md` |
