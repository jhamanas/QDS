# Security Analysis — Quantum-Inspired Threat Detection Framework

**Scope:** the teleportation-based QDS scheme in `core/qds_protocol.py`, its
statistical disturbance detector (`detection/`), the four attack classes
simulated in `attacks/`, and their evaluation in `evaluation/`. This
document consolidates Phases 3–8 into one place with concrete numbers.

All figures below come from `evaluation/security_analysis.py`'s
`generate_security_report()` and `evaluation/validate_detection.py`'s
`attack_detectability_summary()` / `sweep_intercept_resend_detection()`, run
at a reference configuration of **L=64, channel noise p=0.03,
margin_std=6.0**. See `tests/test_security_analysis.py` and
`tests/test_validate_detection.py` for the automated checks these numbers
satisfy, and `results/detection_results.json` for the raw generated data.

---

## 1. Threat model

Five distinct attack surfaces are considered:

| Attack | Capability required | Disturbs the channel? |
|---|---|---|
| **Intercept-resend** (eavesdropping) | Taps the quantum channel during key distribution | **Yes** — the only one |
| **Blind forgery** | No channel access, no private key | No (on success); mismatch on failure looks like noise |
| **Intercepting forgery** | Physical access to Bharat's stored qubits before verification | No |
| **Impersonation** | Ability to initiate a distribution session as "Aditi" | No |
| **Replay / key reuse** | Observes previously-broadcast signatures | No |

Only the first produces an ongoing physical disturbance a QBER-based
detector can see. The other four each represent a different way the
scheme can be defeated without ever touching the quantum measurement
statistics at all.

---

## 2. Corrected forgery bounds

`core/qds_protocol.py`'s original design docstring claimed a blind forger's
per-qubit success probability was **1/6**, giving a `(1/6)^L` bound. This was
wrong, and has been corrected in that file. `verify_bit()` measures Bharat's
real qubit in whatever basis the *signature discloses*, not in some basis
independently known to be Aditi's true one:

- Forger's guessed basis matches Aditi's true basis (prob 1/3): the
  measurement is deterministic, so success requires also guessing the
  eigenvalue (prob 1/2) → contributes **1/6**.
- Forger's guessed basis does **not** match (prob 2/3): a mismatched-basis
  measurement of a Pauli eigenstate is exactly 50/50, *regardless of the
  claimed eigenvalue* → contributes **1/3**.

**Total per-qubit success probability: 1/6 + 1/3 = 1/2**, not 1/6, confirmed
empirically at 0.4991 over 200,000 trials (`attacks/forgery.py`). The bound
across L qubits at strict `mismatch_threshold=0` is `(1/2)^L` — at L=64 this
is **5.42 × 10⁻²⁰**.

### 2.1 The intercepting forger: a total, L-independent break

`verify_bit()` has no way to check a disclosed basis against Aditi's *true*
secret basis independently — it only ever measures in whichever basis the
signature claims. An attacker with physical access to Bharat's qubits measures
once, in any basis, and truthfully discloses what she saw; verification then
re-measures the same already-collapsed qubit in the same basis —
deterministic by construction.

```
P(intercepting forgery succeeds) = 1.0, independent of L
```

Confirmed empirically at exactly 1.0 across 5,000+ trials, including at
L=100 (`attacks/forgery.py`, `tests/test_attacks.py`). **No choice of L
protects against this.** Unforgeability rests on an assumption external to
the disclosure/verification math: that Bharat's qubits are physically
inaccessible to attackers before verification.

### 2.2 Impersonation: no channel breach required at all

A third, more basic failure mode found while building Phase 5's remaining
simulators: `distribute_public_key` and `verify_bit` never bind the
distributed qubits to any Aditi-specific credential. An attacker (Meera)
can simply run the **entire honest protocol herself** — generate her own key
material, distribute it to Bharat, sign it — and present the result as if it
came from Aditi. Since Meera calls the exact same honest functions Aditi
would, the resulting session is internally consistent in every way Bharat can
check.

```
P(impersonation succeeds) = 1.0, independent of L, independent of noise,
independent of the Phase 4 detector (there is no disturbance — the run
is honest by construction, just from the wrong identity)
```

Confirmed at 300/300 trials and at L=100 (`attacks/impersonation.py`,
`tests/test_attacks.py`). This is mitigated only by a mechanism entirely
outside `core/qds_protocol.py`'s scope: an authenticated classical or
quantum channel binding the distribution session to Aditi's identity before
Bharat accepts it as her public key. Every real QDS proposal in the literature
assumes exactly this; this project makes the assumption explicit rather than
leaving it implicit.

### 2.3 Replay and key reuse: total exposure, not a probability

`core/qds_protocol.py`'s own module docstring warned that this is a
Lamport-style **one-time** signature and that reusing key material "breaks
the security argument." Phase 5 implements that exploit directly
(`attacks/replay.py`):

- **Naive replay** — `verify_bit` performs no freshness/nonce check, so an
  already-used, captured `(key_material, signature)` pair is accepted again
  on every resubmission, indefinitely (confirmed: 20/20 resubmissions
  accepted in `tests/test_attacks.py`).
- **Key reuse** — if the same `SingleBitKeyMaterial` object signs *both*
  possible message bits (a one-time-use violation), an observer who captures
  both resulting signatures now holds the complete, exact private
  description of **both** key sets — confirmed to match Aditi's true
  private fields exactly, byte for byte, in `tests/test_attacks.py`. There
  is no residual secrecy left to quantify probabilistically; this is a
  total compromise the instant the reuse happens.

Mitigation is entirely a deployment-discipline matter: verification-side
freshness tracking, and strict single-use enforcement of every key material
object. Neither is enforced by `core/qds_protocol.py` itself.

---

## 3. What the QBER detector actually catches

`evaluation/validate_detection.py`'s `attack_detectability_summary()` runs
all five attacks against a calibrated detector (L=64, threshold=8) and
measures the fraction of attempts flagged:

| Attack | Detection rate |
|---|---|
| Intercept-resend (full) | **100%** |
| Blind forgery | 100%* |
| Intercepting forgery | **0%** |
| Impersonation | **0%** |
| Naive replay | **0%** |
| Key reuse | **0%** |

*Blind forgery's 100% figure needs a caveat the raw number doesn't convey:
at L=64 a forgery attempt's mismatch count is typically around 32 (half the
qubits), which trivially exceeds any reasonable threshold — so it gets
flagged, but only because a bad guess looks exactly like heavy channel
noise, not because the detector recognized a forgery attempt specifically.
Flagging and rejection are the *same check* here (both are
`mismatch_count > threshold`), so this number just restates the `(1/2)^L`
bound already covered in Section 2 — it is not independent evidence of
detection capability.

The other four rows are genuine, unconditional zeros: each of those attacks
produces `mismatch_count == 0` **by construction**, in every single trial,
regardless of L, threshold, or margin_std. **Statistical QBER detection
covers exactly one of five attack surfaces.**

Sweeping intercept-resend detection rate against attack intensity (same
config):

| Intercept probability | 0.05 | 0.10 | 0.25 | 0.50 | 0.75 | 1.00 |
|---|---|---|---|---|---|---|
| Detection rate | 0% | 0% | 3% | 59% | 97% | 100% |

A stealthy eavesdropper tapping a small fraction of the channel is
effectively invisible at this L; reliable detection requires roughly
50–75%+ interception intensity.

---

## 4. The noise-tolerance / forgery-resistance tradeoff

Phase 4's detector calibrates a nonzero threshold specifically to avoid
falsely rejecting honest signatures under realistic channel noise
(`threshold = ceil(mean + margin_std · std)`). This directly weakens the
blind-forger bound:

```
P(accept) = P(Binomial(L, 0.5) ≤ threshold)
```

At the reference configuration (L=64, noise=0.03, margin_std=6.0):

| Quantity | Value |
|---|---|
| Calibrated threshold | **8** |
| Blind forgery probability at threshold=0 (naive bound) | 5.42 × 10⁻²⁰ |
| Blind forgery probability at the *actual* calibrated threshold=8 | **2.78 × 10⁻¹⁰** |

Roughly **10 orders of magnitude weaker** than the naive bound implies —
noise tolerance and forgery resistance trade directly against each other.

---

## 5. Recommended parameters

`evaluation/security_analysis.py` searches for the minimum L that meets a
forgery target **under the threshold that would actually be calibrated at
that L** (not a fixed threshold=0 assumption). At channel noise p=0.03,
margin_std=6.0:

| Target blind-forgery probability | Naive threshold=0 estimate | **L required under realistic calibration** |
|---|---|---|
| 2⁻²⁰ | 20 | 46 |
| 2⁻⁴⁰ | 40 | **78** |
| 2⁻⁶⁴ | 64 | **~115** |

**Recommendation:** for ~2⁻⁴⁰ blind-forgery resistance under p≈0.03 channel
noise and margin_std=6.0, use **L ≈ 78–81**, not L = 40. This says nothing
about intercepting forgery, impersonation, or replay/key-reuse — no L
compensates for any of those three. They are separate, non-negotiable
deployment requirements:

1. **Physical channel/storage security** (prevents intercepting forgery)
2. **An authenticated distribution channel** (prevents impersonation)
3. **Freshness tracking + strict one-time-key enforcement** (prevents replay
   and key reuse)

---

## 6. Performance (Phase 8)

`evaluation/performance_benchmark.py` confirms the implementation scales as
expected: every per-qubit operation (state prep, a fixed 3-qubit
teleportation circuit, a single measurement) is constant-size work, so total
protocol time is linear in L. Measured (see `results/performance_benchmark.csv`
for full data):

| L | Protocol total | Baseline collection (n=30 trials) |
|---|---|---|
| 10 | 5.0 ms | 148 ms |
| 40 | 19.3 ms | 602 ms |
| 160 | 76.6 ms | 2.38 s |
| 320 | 151.1 ms | 4.63 s |

A linear fit of total protocol time against L gives **R² ≈ 0.99996** —
essentially perfectly linear, confirming no accidental superlinear behavior
crept in across Phases 0–7. Distribution (teleportation) dominates total
time at every L (>85% of it), as expected since it's the only stage doing
real linear-algebra work rather than bookkeeping. At the recommended L≈80
for 2⁻⁴⁰ security, a single sign/verify cycle costs on the order of 20 ms —
comfortably practical for the simulation scale this project targets.

---

## 7. Summary

1. Blind-forger security is `(1/2)^L` at threshold=0, not the originally
   claimed `(1/6)^L` — corrected in `core/qds_protocol.py`.
2. An attacker with physical access to Bharat's stored qubits forges with
   probability 1.0, independent of L.
3. An attacker who never touches the real channel at all can impersonate
   Aditi with probability 1.0, independent of L — this scheme has no
   built-in identity binding.
4. Reusing key material, or replaying a captured signature, is a total
   compromise or an indefinitely-repeatable forgery respectively — both
   require deployment-level discipline the protocol itself does not enforce.
5. Statistical QBER detection catches exactly one of these five attack
   surfaces (intercept-resend); the rest are unconditionally invisible to it.
6. Noise-tolerant calibration trades directly against forgery resistance —
   roughly 10 orders of magnitude of margin given up at the reference
   configuration.
7. Recommended L for realistic deployment at p=0.03 channel noise:
   **~78–81 for 2⁻⁴⁰ forgery resistance**, well above the naive threshold=0
   estimate of 40.
8. The implementation scales linearly in L (R²≈0.9999+), and is practical
   at the recommended L (tens of milliseconds per sign/verify cycle).
