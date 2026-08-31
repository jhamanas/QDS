# Final Report — Quantum-Inspired Threat Detection Framework

## What this project is

A from-scratch quantum statevector simulator, a teleportation-based
Quantum Digital Signature (QDS) scheme built on top of it, a
statistical detector for channel disturbance, four attack simulators,
and a full evaluation of what the detector can and can't catch — plus
performance characterization and complete documentation. Built across
nine phases (see `docs/architecture.md` for the module-by-module map),
0 through 8 in code, 9 in documentation.

## Headline results

**1. Two forgery-bound corrections, both empirically driven.**
The original design assumed a blind forger succeeds with probability
1/6 per qubit. Building the actual forgery simulator (Phase 5) revealed
this was wrong: the real per-qubit probability is **1/2**, because
`verify_bit` checks a disclosure's internal consistency against Bob's
physical qubit, not against Alice's true secret basis directly — a
wrong basis guess isn't an automatic failure, since a mismatched-basis
measurement is still 50/50. A second, more serious result followed from
the same reasoning error appearing in my own first draft of the
stronger "intercepting forger" simulator: an attacker with physical
access to Bob's stored qubits forges with **probability 1.0,
independent of L** — verification always measures in the *disclosed*
basis, so measuring once and reporting honestly always passes.

**2. Two more total breaks, found completing Phase 5.**
Impersonation (an attacker running the entire honest protocol under
Alice's name, since nothing binds the distribution session to her
identity) and replay/key-reuse (no freshness check exists, and
Lamport-style one-time-key violation exposes 100% of the private key)
are both certain, L-independent breaks — matching a warning already
present in the original Phase 3 docstring that hadn't yet been acted
on.

**3. The detector covers exactly one of five attack surfaces.**
`evaluation/validate_detection.py`'s `attack_detectability_summary()`
confirms empirically (not just by architectural argument) that only
intercept-resend produces the kind of ongoing channel disturbance a
QBER-based statistical test can see. The other four are unconditionally
invisible — each produces `mismatch_count == 0` by construction, every
time, regardless of L or calibration.

**4. Noise tolerance and forgery resistance trade off directly.**
Calibrating a detection threshold that tolerates realistic channel
noise (needed to avoid rejecting honest signatures) simultaneously
weakens the blind-forger bound by roughly ten orders of magnitude at a
representative configuration (L=64, noise=0.03: `(1/2)^64 ≈ 5.4×10⁻²⁰`
at threshold=0 vs. `2.8×10⁻¹⁰` at the actually-calibrated threshold=8).

**5. Recommended L is roughly double the naive estimate.**
Accounting for how the threshold itself grows with L under realistic
calibration, reaching 2⁻⁴⁰ blind-forgery resistance at p=0.03 channel
noise requires **L≈78–81**, not the L=40 the uncorrected `(1/2)^L`
bound alone would suggest.

**6. The implementation is fast and scales as expected.**
Every protocol stage is linear in L (R²≈0.9999+ fit quality), and
practical at the recommended L — tens of milliseconds per sign/verify
cycle.

## How the project was actually built

Every phase's headline finding came from writing the code and running
it against real simulated trials, not from deriving formulas on paper
first. Three examples worth naming explicitly, because they shaped how
much to trust any single analytic claim in this codebase:

- The 1/6→1/2 forgery correction was caught only because the forgery
  simulator's own test asserted the wrong bound and failed against real
  `verify_bit` output.
- My own first draft of the intercepting-forger docstring made the
  *same category of reasoning error* the original 1/6 bug did (assuming
  verification checks against Alice's secret basis), and was itself
  caught the same way — empirical trial, not re-reading the derivation
  more carefully.
- `evaluation/validate_detection.py`'s first version claimed blind
  forgery should be *invisible* to the QBER detector like the other
  three non-channel attacks; the actual test run showed a 100%
  detection rate, because most forgery attempts simply produce mismatch
  counts high enough to look like noise. The fix wasn't to adjust the
  assertion until it passed — it was to recognize that "detected" and
  "rejected" are the literal same check for forgery, and that this
  number therefore isn't independent evidence of anything the `(1/2)^L`
  bound didn't already say.

The pattern across all three: the empirical check is what corrects
analytic mistakes, including in explanatory text written to justify a
result that turned out to be the wrong result. Every claim in
`docs/protocol_math.md` and `results/security_analysis.md` has a
corresponding automated test that fails if the claim stops being true.

## What's NOT covered

- **No density-matrix simulation.** Noise is modeled via Monte-Carlo
  Pauli-error sampling on pure states (`core/noise.py`), not a true
  mixed-state formalism. Sufficient for this project's statistics, but
  not a substitute for a density-matrix treatment if finer-grained
  channel models are ever needed.
- **No multi-bit message signing.** `core/qds_protocol.py` signs one
  bit at a time; a real message would need this composed bit-by-bit
  (or replaced with a multi-bit generalization), which was out of scope
  here.
- **No defenses were implemented for intercepting forgery,
  impersonation, or replay/key-reuse** — only characterized. Each
  requires a mechanism outside this codebase's scope (physical channel
  security, an authenticated distribution channel, and deployment-level
  key/session tracking, respectively) — see `results/security_analysis.md`
  Section 5 for the explicit list.
- **`evaluation/security_analysis.py`'s realistic-calibration L search
  uses an approximation** (a binomial scaling model fit from one real
  baseline), not a re-simulation at every candidate L — validated once
  against real calibration at two L values, not continuously.

## Where to look for more detail

| Question | See |
|---|---|
| How is the code organized? | `docs/architecture.md` |
| Where do the formulas come from? | `docs/protocol_math.md` |
| What are the actual security numbers? | `results/security_analysis.md` |
| Raw sweep/detectability data | `results/detection_results.json` |
| Raw timing data | `results/performance_benchmark.csv` |
| How do I run it? | `README.md` |
