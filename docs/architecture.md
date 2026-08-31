# Architecture

## Overview

This project simulates a teleportation-based Quantum Digital Signature
(QDS) scheme end-to-end, on top of a from-scratch statevector quantum
simulator, then attacks it, detects what can be detected, and
quantifies what can't. It was built in nine phases, each depending only
on the ones before it:

```
Phase 0  core/primitives.py        gates, states, measurement
Phase 1  core/entanglement.py      Bell pair generation
Phase 2  core/teleportation.py     3-qubit teleportation circuit
Phase 3  core/qds_protocol.py      sign/verify (honest path)
Phase 4  detection/                statistical disturbance detector
Phase 5  attacks/                  4 attack simulators
Phase 6  evaluation/validate_detection.py   TPR/FPR against attacks
Phase 7  evaluation/security_analysis.py    forgery bounds, tradeoffs
Phase 8  evaluation/performance_benchmark.py  runtime/complexity scaling
Phase 9  docs/, README.md, requirements.txt   this documentation
```

## Module map

```
qds_threat_detection/
│
├── core/                    Protocol building blocks (Phases 0-3)
│   ├── primitives.py        Statevector representation, gates, measurement,
│   │                        Pauli eigenstate prep -- everything else in the
│   │                        project is built out of these functions.
│   ├── entanglement.py      Bell pair generation (all 4 Bell states),
│   │                        used by teleportation.py as the shared resource.
│   ├── teleportation.py     Standard 3-qubit teleportation circuit --
│   │                        delivers an unknown qubit state without
│   │                        physically transmitting it.
│   └── qds_protocol.py      The QDS scheme itself: key generation,
│                            teleportation-based "quantum public key"
│                            distribution, signing (disclosure), and
│                            verification (measurement + comparison).
│
├── detection/                Phase 4: statistical anomaly detection
│   ├── baseline.py           Collects the honest-run mismatch-count
│   │                         distribution under a configurable noise model.
│   ├── thresholds.py         Turns that distribution into a calibrated
│   │                         accept/reject mismatch_threshold.
│   └── detector.py           Thin wrapper: calls qds_protocol.verify_bit
│                             with the calibrated threshold, one decision
│                             point in the whole codebase.
│
├── attacks/                  Phase 5: four attack simulators
│   ├── intercept_resend.py   Eavesdropping on the distribution channel --
│   │                         the ONE attack that disturbs the channel.
│   ├── forgery.py            Blind forger (no channel access, (1/2)^L
│   │                         bound) and intercepting forger (physical
│   │                         qubit access, succeeds with certainty).
│   ├── impersonation.py      Mallory runs the entire honest protocol
│   │                         herself under Alice's name -- no crypto
│   │                         broken, just no identity binding to break.
│   └── replay.py             Naive signature resubmission, and the
│                             one-time-key-reuse total-exposure exploit.
│
├── evaluation/                Phases 6-8: validation, security, performance
│   ├── validate_detection.py  TPR/FPR of the Phase 4 detector against
│   │                          every Phase 5 attack; the key empirical
│   │                          result is WHICH of the five are even
│   │                          detectable in principle (only one is).
│   ├── security_analysis.py   Forgery-probability formulas, the
│   │                          threshold/forgery tradeoff, and a parameter
│   │                          recommendation engine tying Phase 4's real
│   │                          calibration behavior to Phase 5's bounds.
│   └── performance_benchmark.py  Wall-clock timing and linear-scaling
│                                 fit for every protocol/detection stage.
│
├── tests/                     Mirrors core/ + detection/ + attacks/ +
│                               evaluation/ 1:1 (one file per module, except
│                               attacks/ and evaluation/ which each get one
│                               test file covering their whole package).
│
├── results/                   Generated OUTPUT data, not code:
│   ├── detection_results.json     raw sweep + detectability numbers
│   ├── security_analysis.md       the full security writeup with numbers
│   └── performance_benchmark.csv  raw per-stage timing data
│
└── docs/                      This documentation (Phase 9).
```

## Data flow (honest path)

```
generate_key_material(L)
        │  Alice privately picks L random (basis, eigen) pairs
        │  for EACH of two key sets (key_set_0, key_set_1)
        ▼
distribute_public_key(key_material)
        │  Each of the 2L qubits is teleported to Bob, one fresh
        │  Bell pair per qubit (core/teleportation.py + entanglement.py)
        │  Bob ends up holding 2L qubits with NO idea what basis/eigen
        │  any of them represent -- this is the "quantum public key"
        ▼
sign_bit(key_material, message_bit)
        │  Alice discloses the FULL (basis, eigen) description of
        │  key_set_{message_bit} ONLY -- total transparency of one
        │  whole key set, nothing more, nothing less
        ▼
verify_bit(key_material, signature, mismatch_threshold)
        │  Bob measures his stored qubits (for the disclosed key set)
        │  each in its disclosed basis, compares to the disclosed
        │  eigenvalue, counts mismatches, accepts iff
        │  mismatch_count <= mismatch_threshold
        ▼
     ACCEPT / REJECT
```

`detection/` sits entirely on the Bob side of this: it calibrates what
`mismatch_threshold` should be (Phase 4), given that real channel noise
means honest runs no longer produce exactly 0 mismatches. `attacks/`
intervenes at different points in this same pipeline -- intercept_resend
tampers with the qubits in transit (between distribute_public_key and
verify_bit); forgery and impersonation skip legitimate distribution
entirely; replay/key-reuse operates one level up, on the
(key_material, signature) pairs themselves.

## Design principles that shaped the codebase

- **Statevectors, not density matrices.** Phases 0-3 model everything as
  pure states; Phase 4's noise model (core/noise.py) is a Monte-Carlo
  depolarizing channel simulated by randomly applying a Pauli error,
  not a true mixed-state simulation. This keeps every function a
  simple vector/matrix operation, at the cost of needing to average
  over many trials to see channel statistics (rather than reading them
  off a single density matrix).
- **One decision point.** detection/detector.py and every attack
  simulator call core.qds_protocol.verify_bit directly rather than
  reimplementing the accept/reject comparison -- there is exactly one
  place in the codebase that decides accept/reject, so nothing can
  silently diverge from it.
- **Attacks call the real honest-path functions where possible.**
  attacks/impersonation.py and attacks/replay.py's key_reuse_attack
  deliberately call generate_key_material / distribute_public_key /
  sign_bit -- the same functions Alice uses -- rather than a parallel
  implementation. This is a design choice, not laziness: it makes the
  point that these two attacks require no cleverness or protocol
  violation at all, just a missing assumption (identity binding,
  one-time-key discipline) that the honest-path code was never asked
  to enforce.
- **Every analytic claim is empirically checked.** Every probability
  bound in evaluation/security_analysis.py and attacks/forgery.py's
  docstrings is verified against real simulated trials in the test
  suite, not just derived on paper -- this is how the original (1/6)
  docstring bug and the intercepting-forger docstring's own
  first-draft error (see attacks/forgery.py's module docstring) were
  both caught.
