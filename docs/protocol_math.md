# Protocol Mathematics

This document collects every mathematical derivation used or corrected
across the project, in one place, with references to where each is
implemented and tested.

## 1. State representation and gates (`core/primitives.py`)

An n-qubit register is a statevector in `C^(2^n)`, indexed with qubit 0
as the least-significant bit: `|q_{n-1} ... q_1 q_0>`. A single-qubit
gate `U` acting on qubit `k` of an n-qubit register is built via
Kronecker product:

```
U_full = I ⊗ ... ⊗ U ⊗ ... ⊗ I     (U at position k, built MSB-first)
```

Measurement in the computational (Z) basis of qubit `k` uses the Born
rule: `P(outcome=1) = sum over all basis states with bit k = 1 of |amplitude|^2`,
then collapses and renormalizes. Measurement in the X or Y basis is
implemented by rotating (H for X; `H @ S_dagger` for Y), measuring in Z,
then rotating back -- so the returned outcome is in the ORIGINAL
(unrotated) frame's eigenbasis, but the returned state is expressed back
in the standard computational basis for the rest of the register to use
consistently.

Fidelity between two pure states: `F(a, b) = |<a|b>|^2`, used throughout
to check teleportation correctness (should be 1.0) and to quantify
channel disturbance.

## 2. Bell states and teleportation (`core/entanglement.py`, `core/teleportation.py`)

Starting from `|00>`, applying H to qubit 0 then CNOT(0→1) gives:

```
(|0, b1> + (-1)^b0 |1, NOT b1>) / sqrt(2)
```

for pre-flip bits `(b0, b1)` applied to `|00>` before the circuit. This
produces all four Bell states depending on `(b0, b1)`:

| (b0, b1) | Result |
|---|---|
| (0, 0) | `|Phi+> = (|00> + |11>)/sqrt(2)` |
| (1, 0) | `|Phi-> = (|00> - |11>)/sqrt(2)` |
| (0, 1) | `|Psi+> = (|01> + |10>)/sqrt(2)` |
| (1, 1) | `|Psi-> = (|01> - |10>)/sqrt(2)` |

**Teleportation correction order.** The by-product operator left on
Bharat's qubit before correction is `X^{m_B} Z^{m_A}` applied to the
original state, where `(m_A, m_B)` are Aditi's two measurement outcomes.
Undoing a product of two non-commuting self-inverse operators requires
applying their inverses in REVERSE order: the correct correction is
`Z^{m_A} X^{m_B}` — apply the X correction first, then Z. This was
verified empirically across all four `(m_A, m_B)` branches and 200+
random states in `tests/test_teleportation.py`, not just assumed from
the formula.

## 3. QDS protocol correctness (`core/qds_protocol.py`)

Each qubit in a key set is prepared as an eigenstate of a randomly
chosen Pauli basis `B ∈ {X, Y, Z}` with a randomly chosen eigenvalue
sign `e ∈ {0, 1}`. Preparing in basis `B` with eigenvalue `e`, then
measuring in `B`, is deterministic and returns `e` — this is what makes
honest verification exactly deterministic (mismatch_count = 0) in the
noiseless case (Phase 3).

Measuring a `B`-eigenstate in a DIFFERENT, mutually-unbiased basis
`B' ≠ B` (any pair among X, Y, Z) gives an outcome that is exactly
50/50, independent of `e`. This single fact is the basis for every
forgery-probability derivation in Section 5.

## 4. Depolarizing noise model (`core/noise.py`)

With total probability `p`, applies a uniformly random Pauli error (X,
Y, or Z, each with probability `p/3`) to the target qubit; otherwise
leaves it unchanged. This is a Monte-Carlo simulation of a depolarizing
channel using pure states — averaged over many trials it reproduces
standard depolarizing-channel measurement statistics without needing a
density-matrix simulator.

For a qubit measured in its OWN preparation basis, the identity and the
matching Pauli error preserve the outcome; the two Pauli errors that
anticommute with the measurement basis flip it. Therefore the mismatch
probability is `2p/3`, so at `p=1.0` it is `2/3`, not 100% and not
`1/3`. This is distinct from mean pure-state fidelity: at `p=1.0`, a
Pauli eigenstate has fidelity 1 on the one matching-Pauli branch and 0
on the other two branches, for mean fidelity `1/3`.

Equivalently, in the alternative parameterization
`D_lambda(rho) = (1-lambda) rho + lambda I/2`, this channel has
`lambda = 4p/3`; the two parameter names must not be interchanged.

## 5. Intercept-resend eavesdropping (`attacks/intercept_resend.py`)

Esha measures each intercepted qubit in a basis guessed uniformly at
random from `{X, Y, Z}`, then resends a freshly prepared eigenstate of
her guessed basis with her measured eigenvalue.

- Esha's guessed basis matches the true basis (prob 1/3): her measurement
  is non-disturbing (she measured a true eigenstate in its own basis),
  and Bharat's later measurement in the same (true, disclosed) basis
  reproduces the true eigenvalue with certainty → **no mismatch**.
- Esha's guessed basis differs (prob 2/3): her resent state is a definite
  eigenstate of the WRONG basis, so Bharat's measurement in the true basis
  is exactly 50/50 → **mismatch with probability 1/2**.

```
Expected per-qubit mismatch rate = (2/3)(1/2) = 1/3 ≈ 33%
```

Confirmed empirically at 0.3374 over 30,000 trials
(`tests/test_attacks.py`), matching `expected_mismatch_rate()`'s
analytic value of exactly 1/3.

## 6. Forgery bounds (`attacks/forgery.py`)

### 6.1 Blind forger (no channel access, no private key)

**This corrects a bug in the original Phase 3 docstring, which claimed
1/6.** `verify_bit()` measures Bharat's REAL qubit in whatever basis the
forger's disclosure claims, and compares to whatever eigenvalue the
disclosure claims — it never checks the disclosure against Aditi's true
description directly. For one qubit:

- Forger's guessed basis matches the true basis (prob 1/3): measurement
  is deterministic, equal to the true eigenvalue. Success requires the
  guessed eigenvalue to ALSO match (prob 1/2, since eigen is an
  independent uniform bit) → contributes `(1/3)(1/2) = 1/6`.
- Forger's guessed basis does NOT match (prob 2/3): mismatched-basis
  measurement is exactly 50/50 REGARDLESS of the claimed eigenvalue —
  this is NOT an automatic failure → contributes `(2/3)(1/2) = 1/3`.

```
P(blind forgery succeeds, one qubit) = 1/6 + 1/3 = 1/2   (NOT 1/6)
P(blind forgery succeeds, L qubits, threshold=0) = (1/2)^L
```

Confirmed at 0.4991 over 200,000 single-qubit trials, and 0/4000 full
forgeries at L=24 (`tests/test_attacks.py`).

### 6.2 Intercepting forger (physical access to Bharat's real qubits)

**A second finding, also correcting an initial wrong draft** (which
first assumed a 2/3 success rate, using the same flawed "checked
against the true basis" reasoning the original Phase 3 bug used).
`verify_bit()` always measures in the DISCLOSED basis — never
independently against Aditi's true secret basis. So once the
intercepting forger measures a qubit in ANY basis `B` and truthfully
discloses `(B, her outcome)`, Bharat's "verification" is a SECOND
measurement of the SAME already-collapsed qubit in that SAME basis `B`
— and repeated measurement of an eigenstate in its own basis is
deterministic.

```
P(intercepting forgery succeeds) = 1.0, independent of L
```

Confirmed at 100% across 5,000+ trials, including at L=100. This is an
L-INDEPENDENT total break — see `results/security_analysis.md` Section
2.1 for the security implication.

### 6.3 Threshold/forgery tradeoff (`evaluation/security_analysis.py`)

A blind forger's mismatches are `Binomial(L, 0.5)`-distributed (each
qubit mismatches with probability exactly 1/2, by the symmetry of the
1/6+1/3 derivation above). Against a calibrated `mismatch_threshold`
(not the textbook `threshold=0`):

```
P(accept) = P(Binomial(L, 0.5) ≤ threshold) = Σ_{k=0}^{threshold} C(L,k) · 0.5^L
```

This closed form is validated against real `verify_bit` behavior across
several `(L, threshold)` pairs in `tests/test_security_analysis.py`
(all within statistical tolerance of the analytic prediction).

## 7. Impersonation and replay (qualitative, not probabilistic)

Neither `attacks/impersonation.py` nor `attacks/replay.py` admits a
meaningful "probability of success" the way blind forgery does — both
are total, certain breaks the instant their precondition is met (an
unauthenticated distribution channel; a captured signature; a reused
key material object). See `docs/architecture.md` and
`results/security_analysis.md` Sections 2.2–2.3 for the full reasoning;
there is no additional math to derive beyond "an honest run under a
false identity is indistinguishable from a genuine one" and "full
disclosure of a key set, twice, for two different bits, is full
disclosure of everything."

## 8. Operational threshold calibration (`detection/thresholds.py`)

The former operational rule, `ceil(mean + max(6 * std, 1))`, was an
empirical mean-plus-6-sigma heuristic. It did not state an honest
false-reject target and finite Monte Carlo estimates, integer rounding,
and clipping changed its tail behavior.

For the repository's independent Pauli-noise simulation, a qubit
measured in its own Pauli basis has mismatch probability `q = 2p/3`,
where `p` is `channel_noise_p`. For `L` independently affected qubits:

```
M ~ Binomial(L, q)
```

The operational policy uses `DEFAULT_FALSE_REJECT_ALPHA = 1e-6` and
chooses the smallest integer `t` in `[0, L]` satisfying:

```
P(M > t) <= alpha
```

The calibration reports that actual binomial false-reject probability,
along with `L`, `p`, `q`, `alpha`, and `t`. If `t == L`, the reported
tail is zero but every possible mismatch count is accepted, so a
mismatch-count detector cannot reject a trial on that signal alone.

The empirical baseline collection is retained to diagnose whether honest
simulation behavior agrees with the model; it no longer determines the
operational cutoff. This is an educational/demo statistical calibration
policy, not a cryptographic security parameter, QDS security proof, or
guarantee for hardware or correlated noise.

## 9. Performance scaling (`evaluation/performance_benchmark.py`)

Every per-qubit operation (state preparation, a fixed 8-dimensional
3-qubit teleportation circuit, one measurement) is constant-size,
independent of `L`. Total time for any protocol stage that loops over
`L` qubits is therefore expected to be `O(L)`:

```
time(L) ≈ a·L + b
```

fit via ordinary least squares (`numpy.polyfit`, degree 1) and checked
via `R²`. Measured `R² ≈ 0.99996` for total protocol time across
`L ∈ {10, 20, 40, 80, 160, 320}` — see `results/performance_benchmark.csv`
for the raw data and `results/security_analysis.md` Section 6 for a
summary table.
