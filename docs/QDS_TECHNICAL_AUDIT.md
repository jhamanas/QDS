# Current implementation note

The findings below preserve the original audit trail. Since that audit, the
secure wrapper has been remediated with high-entropy per-qubit opening nonces,
signer-issued verifier authorization (identity, expiry, HMAC integrity, and
one-time use), optional SQLite replay state, Wilson acceptance intervals,
alpha/beta parameter search, and benchmark memory/measurement reporting. The
simulator remains educational and is not a formally proven or publicly
verifiable QDS implementation.

# 1. Executive Summary

**Scope.** This is a read-only consolidation of the completed repository audit and deep theory/security validation. It is not a new audit. No source code was changed. The requested earlier file `docs/INITIAL_COMPLETE_AUDIT.md` was not present when the deep-validation pass began.

**Overall verdict: PARTIALLY VERIFIED educational quantum-state simulation; UNSUPPORTED as a secure, deployable Quantum Digital Signature (QDS) system.**

The repository contains a Python/NumPy pure-state statevector simulator, Bell-state and ideal teleportation demonstrations, a one-bit Lamport-style QDS-inspired disclosure model, stochastic Pauli noise, a mismatch-count detector, attack simulations, a benchmark/results set, and a dashboard. The ideal linear-algebra core is largely correct for its stated narrow model. The security/deployment claims are not defensible without major qualification.

Most important established findings:

- **VERIFIED:** Statevector primitives, Pauli eigenstates, Bell-state construction, and the default `phi+` ideal teleportation circuit are consistent with standard theory.
- **VERIFIED:** Ideal X/Y/Z intercept-resend disturbance is `1/3` for this exact idealized attack model.
- **CONTRADICTED:** The documentation claim that the implemented Pauli noise has a maximum mismatch rate near `1/3` is false. The actual mismatch probability is `2p/3`, hence `2/3` at `p=1`.
- **CRITICAL / CONTRADICTED:** The secure-wrapper SHA-256 "commitments" are enumerable: each secret `(basis, eigen)` has only six possible values. This is a low-entropy enumeration failure, not a SHA-256 break.
- **HIGH:** `verify_bit()` measures `bharat_state.copy()` and discards the collapsed state; repeated verification does not model quantum-state consumption.
- **HIGH:** Detection sweeps calibrate with `channel_noise_p` but do not apply that noise in attack trials. Reported attack detection at `p=0.03` is therefore a methodology mismatch.
- **UNSUPPORTED:** The legacy and secure-wrapper models do not establish a recognized complete QDS construction, information-theoretic QDS security, public verification, transferability, repudiation resistance, or non-repudiation.
- **UNVERIFIED:** Tests, empirical figures, and timing benchmarks could not be rerun because this environment has no runnable Python interpreter.

# 2. Repository Structure & Architecture

## Architecture

```text
NumPy statevector primitives
  -> Bell-pair generation
  -> ideal three-qubit teleportation
  -> legacy one-bit disclosure/verification model
  ├-> Pauli-noise baseline and threshold detector
  ├-> attack simulators
  └-> security/detection/performance evaluations

Dashboard/API path:
dashboard.html -> /api/run -> scenario_runner.py
  -> SecureSession / SecureVerifier wrapper
```

## Module map

| Area | Files | Established purpose |
|---|---|---|
| Quantum primitives | `core/primitives.py` | Complex pure-state vectors, gates, measurement, Pauli eigenstates, fidelity. |
| Entanglement | `core/entanglement.py` | Creates and checks four Bell states. |
| Teleportation | `core/teleportation.py` | Ideal 3-qubit teleportation using a Bell pair and conditional Pauli corrections. |
| Legacy QDS model | `core/qds_protocol.py` | Generates two `L`-element sets of Pauli descriptions, teleports states, discloses one set, and compares measurement outcomes. |
| Secure wrapper | `core/secure_protocol.py` | HMAC-authenticated distribution record, hash commitments, payload digest, in-memory signature-ID replay set, one-use signing flag. |
| Noise/detection | `core/noise.py`, `detection/` | Stochastic Pauli noise, honest baseline collection, threshold calibration, decision wrapper. |
| Attacks | `attacks/` | Intercept-resend, blind/intercepting forgery, impersonation, replay/key reuse. |
| Evaluation | `evaluation/` | Detection sweeps, probability calculations, recommended `L`, timing fits. |
| Demo/API | `scenario_runner.py`, `run_scenario.py`, `dashboard.py`, `dashboard.html`, `api/run.py`, `vercel.json` | Local/Vercel interactive demonstration. |
| Results/docs/tests | `results/`, `docs/`, `tests/` | Checked-in outputs, narrative documentation, script-style assertions. |

## Data flow

1. `generate_key_material(L, rng)` creates two independent sets of `L` pairs: `basis in {X,Y,Z}`, `eigen in {0,1}`.
2. `distribute_public_key()` prepares each corresponding Pauli eigenstate and calls `teleport_qubit()`.
3. `sign_bit()` discloses all descriptions in the set selected by one message bit.
4. `verify_bit()` measures Bharat's stored corresponding state in each **disclosed** basis and accepts when mismatch count is at most a threshold.
5. The detector calibrates a threshold from sampled honest mismatch counts.
6. Attack/evaluation modules operate on this same model.
7. Dashboard scenarios use the separate `SecureSession` / `SecureVerifier` wrapper.

**Model limitation:** Aditi’s secret fields and Bharat’s `bharat_state` share `KeyQubit` objects in one process. The simulation intentionally models separation by convention; it is not an access-control boundary or real distributed state ownership.

# 3. Technology and Concept Inventory

| Item | Repository use | Why used / problem solved | Assessment and realistic alternatives |
|---|---|---|---|
| Python 3.10+ | Entire project | Simple implementation and CLI/API. | Appropriate for an educational simulator; environment/version is not pinned. |
| NumPy | Complex arrays, gates, random simulation, regression | Efficient numerical operations for fixed small statevectors. | Appropriate for simulation. Official NumPy guidance says `Generator` is not cryptographic randomness. Alternatives: Qiskit Aer, Cirq, QuTiP, density-matrix simulation. |
| Pure statevectors | `core/primitives.py` | Models ideal 1–3-qubit circuits. | Good for ideal demonstrations; insufficient for generic mixed noise/hardware behavior. |
| Bell states and teleportation | `core/entanglement.py`, `core/teleportation.py` | Demonstrates an EPR resource and state transfer. | Theory sound in ideal form; teleportation alone does not provide digital signatures. |
| Pauli X/Y/Z bases | Key descriptions, measurements, attack model | Three mutually unbiased qubit bases yield a simple intercept-resend calculation. | Appropriate educational choice. BB84-style two bases or a published QDS distribution protocol are alternatives. |
| Stochastic Pauli channel | `core/noise.py` | Samples one Pauli trajectory per qubit. | Correct as a Pauli trajectory model, but excludes loss, correlated noise, detector/readout errors, and coherent attacks. |
| Threshold heuristic | `detection/thresholds.py` | Uses sampled mean plus six standard deviations. | Interpretable educational heuristic; exact binomial-tail thresholds, confidence intervals, ROC/power analysis are stronger alternatives. |
| SHA-256/HMAC-SHA-256 | `core/secure_protocol.py` | Record integrity/authentication and descriptions labeled as commitments. | SHA-256/HMAC are standard primitives, but low-entropy hash inputs make the commitment use unsafe. HMAC is not a public signature. |
| `secrets`, UUID | Secure-session identifiers | Better classical randomness for tokens/IDs. | Reasonable, but state is in-memory only. |
| HTTP server/Vercel function | Demo | Serves dashboard scenarios. | Demonstration layer, not hardened service architecture. |

# 4. Theory ↔ Implementation Validation

## Quantum state simulation

| Theory -> expected behavior | Implementation | Verdict |
|---|---|---|
| An `n`-qubit pure state is a normalized vector in `C^(2^n)`. | `zero_state()` and statevector convention in `core/primitives.py:76`. | **VERIFIED** for intended pure-state inputs. |
| Unitary gates preserve norm. | Standard Pauli/H/CNOT matrices; `apply_single_qubit_gate()` and `apply_two_qubit_gate()`. | **VERIFIED** for used dimensions and valid inputs. |
| Born rule samples probabilities from squared amplitudes. | `measurement_probabilities()` and `measure_qubit()` at `core/primitives.py:206` and `:211`. | **VERIFIED.** |
| Projective measurement must collapse and normalize. | `measure_qubit()` zeros incompatible amplitudes and calls `normalize()`. | **VERIFIED** at primitive level. |
| Same-basis Pauli eigenstate measurement is deterministic; mutually unbiased distinct Pauli bases are uniform. | `prepare_pauli_eigenstate()` / `measure_qubit_in_basis()` at `core/primitives.py:95` and `:235`. | **VERIFIED.** |
| Pure-state fidelity is `abs(<a|b>)^2`. | `state_fidelity()` at `core/primitives.py:270`. | **VERIFIED** for normalized pure states only. |

Input shape/range validation is limited; teleportation does not universally reject a non-normalized input. This is a robustness limitation, not a demonstrated wrong result for tested intended inputs.

## Bell states

`generate_bell_pair()` in `core/entanglement.py:65` uses pre-CNOT X flips, then H(q0), CNOT(q0 -> q1). It produces:

| State | Vector | Verdict |
|---|---|---|
| `phi+` | `(|00> + |11>) / sqrt(2)` | **VERIFIED** |
| `phi-` | `(|00> - |11>) / sqrt(2)` | **VERIFIED** |
| `psi+` | `(|01> + |10>) / sqrt(2)` | **VERIFIED** |
| `psi-` | `(|01> - |10>) / sqrt(2)` | **VERIFIED** |

All are normalized and have expected Z-basis same/opposite correlations. The `verify_entanglement()` helper is a Monte-Carlo correlation check; it is not a general entanglement witness for arbitrary two-qubit states.

## Quantum teleportation

`teleport_qubit()` at `core/teleportation.py:59` constructs `|psi>_A tensor |Phi+>_BC`, applies CNOT(A->B), H(A), measures A/B, and applies X if `m_B=1`, then Z if `m_A=1`.

For the default `phi+` resource, the uncorrected C state is `X^m_B Z^m_A |psi>`. The code’s X-then-Z sequence supplies `Z^m_A X^m_B`, its inverse up to global phase.

**Verdict: VERIFIED for ideal normalized one-qubit inputs and default `bell_kind="phi+"`.** Other Bell resources are not accompanied by corresponding altered corrections, so they are disturbance experiments rather than standard perfect teleportation runs.

## QDS model

The legacy model at `core/qds_protocol.py` is a one-bit, one-recipient disclosure model. It does not instantiate the Gottesman–Chuang quantum one-way-function construction and omits essential QDS security structure.

| Property expected of a complete QDS analysis | Repository support | Verdict |
|---|---|---|
| Defined multi-recipient public-key distribution | One verifier/state holder only. | **UNSUPPORTED** |
| Bounded public-key copies | Not modeled. | **UNSUPPORTED** |
| Transferability | Not modeled. | **UNSUPPORTED** |
| Repudiation resistance | Not modeled. | **UNSUPPORTED** |
| Public verification | HMAC registry is symmetric/private. | **UNSUPPORTED** |
| Formal forgery game / security proof | Limited toy attack simulation only. | **UNSUPPORTED** |

**Conclusion:** Calling it a “QDS-inspired educational model” is defensible. Calling it a complete or information-theoretically secure QDS implementation is not.

## Intercept-resend

The exact implementation in `attacks/intercept_resend.py` selects Esha’s basis uniformly from X/Y/Z, measures, and resends the corresponding eigenstate. Under the model:

`P(wrong basis) = 2/3`, `P(mismatch | wrong basis) = 1/2`, therefore `P(mismatch) = 1/3`.

**Verdict: VERIFIED** for independently prepared ideal Pauli eigenstates, uniformly random bases, one Esha measurement/resend, and no simultaneous ordinary noise or side channels. It is not a universal QDS/QKD result.

## Depolarizing noise

`apply_depolarizing_noise()` at `core/noise.py:24` implements:

`E_p(rho) = (1-p)rho + (p/3)(XrhoX + YrhoY + ZrhoZ)`.

For a state prepared/measured in Pauli basis `B`, identity and `B` preserve its eigenvalue; the other two Pauli operators flip it. Hence:

`P(mismatch) = 2p/3`.

At `p=1`, mismatch is `2/3`, not `1/3`. Equivalently:

`E_p(rho) = (1 - 4p/3)rho + (4p/3) I/2`.

**VERIFIED:** The code implements a valid stochastic Pauli-channel trajectory model.  
**CONTRADICTED:** `docs/protocol_math.md:82-89` and the high-noise explanatory text in `tests/test_detector.py` state that mismatch caps near `1/3`. They confuse mean state fidelity (`1/3` for a Z eigenstate at `p=1`) with measurement mismatch (`2/3`).

# 5. Research Validation

| Claim | Source and relevant location | What the source establishes | Scope of validation |
|---|---|---|---|
| Standard teleportation architecture | Bennett, Brassard, Crépeau, Jozsa, Peres & Wootters, “Teleporting an unknown quantum state via dual classical and Einstein–Podolsky–Rosen channels,” *PRL* 70, 1895–1899 (1993), DOI [10.1103/PhysRevLett.70.1895](https://doi.org/10.1103/PhysRevLett.70.1895), abstract and pp. 1895–1899. | EPR sharing, Aditi joint measurement/classical result, and Bharat conditional reconstruction. | Underlying theory; supports default teleportation design, not repository security. |
| QDS requirements and quantum public keys | Daniel Gottesman & Isaac Chuang, “Quantum Digital Signatures” (2001), [arXiv:quant-ph/0105032](https://arxiv.org/abs/quant-ph/0105032), abstract and §§1–2. | Multiple recipients, quantum public keys known exactly only to signer, limited copies, secure distribution discussion. | Contradicts any inference that the repository alone is a complete QDS construction. |
| QDS security goals | D. J. Wallden, V. Dunjko, A. Kent & E. Andersson, “Quantum digital signatures with quantum-key-distribution components,” *PRA* 91, 042304 (2015), DOI [10.1103/PhysRevA.91.042304](https://doi.org/10.1103/PhysRevA.91.042304). | Authenticity, transferability, and security against forgery are QDS concerns. | Underlying QDS criteria only; does not validate repository code. |
| No-cloning | W. K. Wootters & W. H. Zurek, “A single quantum cannot be cloned,” *Nature* 299, 802–803 (1982), DOI [10.1038/299802a0](https://doi.org/10.1038/299802a0). | Unknown quantum states cannot be universally cloned. | Supports high-level attack motivation, not the repository protocol/security proof. |
| Exact Pauli channel | John Preskill, Ph/CS 219A, “Qubit Channels,” Lecture 5 (2020), [official slides](https://www.preskill.caltech.edu/ph219/Ph-CS-219A-Slides-2020/Ph-CS-219A-Lecture-5-Qubit-Channels.pdf). | Identity with `1-p`; X/Y/Z each `p/3`. | Validates channel theory used by code. |
| Alternative depolarizing parameterization | IBM Quantum, [`depolarizing_error`](https://eu-de.quantum.cloud.ibm.com/docs/api/qiskit/0.29/qiskit.providers.aer.noise.depolarizing_error). | `E(rho)=(1-lambda)rho+lambda I/2`; uniform nonidentity-Pauli channel occurs at `lambda=4/3` for one qubit. | Validates the `lambda=4p/3` conversion, not code results. |
| HMAC | NIST FIPS 198-1 (2008), DOI [10.6028/NIST.FIPS.198-1](https://doi.org/10.6028/NIST.FIPS.198-1), abstract/§1. | HMAC is shared-secret keyed message authentication. | Supports primitive classification only. |
| Digital-signature properties | NIST FIPS 186-5 (2023), DOI [10.6028/NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5), abstract. | Digital signatures provide integrity, identity authentication, and third-party evidence/non-repudiation. | Establishes contrast with HMAC. |
| Commitment properties | Luca Trevisan, *Cryptography and Computational Complexity*, Ch. 20.3, [official lecture text](https://theory.stanford.edu/~trevisan/books/crypto.pdf). | Commitments require hiding and binding; hiding prevents learning the committed value before opening. | Validates low-entropy enumeration analysis conceptually. |
| NumPy RNG boundary | NumPy, [Random sampling](https://numpy.org/doc/stable/reference/random/), warning section. | `Generator` is intended for simulation/statistics, not cryptographic security. | Validates scope limitation. |

No source above validates the repository implementation merely because it explains the same theoretical concept.

# 6. Result Validation

| Reported result | What is measured / expected | Verdict | Evidence boundary |
|---|---|---|---|
| Teleportation fidelity 1 | Pure-state overlap after default ideal circuit. | **CONSISTENT WITH THEORY** | Algebra/code support it; not rerun here. |
| Intercept-resend mismatch about `1/3` | Ideal three-basis Esha model. | **VALIDATED mathematically** | Runtime output remains unverified in this environment. |
| Blind legacy forgery `(1/2)^L` at threshold zero | Attacker chooses random basis/eigen disclosure; verifier uses attacker-disclosed basis. | **PARTIALLY VERIFIED** | Valid only for legacy toy verifier/threat game. |
| Intercepting legacy forger success 1 | Attacker collapses Bharat’s modeled state and honestly reports outcome/basis. | **VALIDATED for simulator model** | Demonstrates insecurity, not QDS strength. |
| Detection rates at `p=0.03` | Threshold calibrated with noise; attacks should be evaluated under same noise. | **CONTRADICTED as labeled methodology** | Attack trials omit `apply_depolarizing_noise`. |
| Threshold around 8 | Sampled `ceil(mu + max(6 sigma,1))`. | **PLAUSIBLE BUT INSUFFICIENTLY VALIDATED** | No independent rerun; heuristic has no specified alpha. |
| Recommended `L≈78–81` | Approximate threshold/forgery search. | **PLAUSIBLE BUT INSUFFICIENTLY VALIDATED** | Depends on legacy model, sampled rate, heuristic and approximation. |
| Linear timing / high R² | Repeating fixed-size work per qubit should be O(L). | **CONSISTENT WITH THEORY** | Checked-in benchmark not independently rerun; environment metadata absent. |

Results in `results/` should not be called “proven.” They are code-generated outputs with limited validation scope.

# 7. Security / Quantum Validation

## Commitment enumeration failure

`_commitment()` at `core/secure_protocol.py:29` hashes public `session_id`, set/index, and one secret pair `(basis,eigen)`. Because there are only `3 x 2 = 6` candidate secret pairs, a public-record observer computes six SHA-256 values per position and identifies the exact pair.

This is a **low-entropy commitment / enumeration attack**, not an attack on SHA-256.

| Property | Verdict |
|---|---|
| Commitment hiding | **CONTRADICTED:** fails completely. |
| Key-description secrecy | **CONTRADICTED:** descriptions recoverable from public record. |
| Secure-wrapper unforgeability | **CONTRADICTED:** recovered descriptions allow fresh forged signature IDs/payload digest. |
| Replay protection | **PARTIALLY VERIFIED:** same ID is rejected in one verifier process; a fresh forged ID is not stopped by ID tracking. |
| Record integrity | **PARTIALLY VERIFIED:** HMAC protects record mutation only if shared key/registry is secure. |

A public salt would not solve six-way enumeration. A high-entropy secret opening nonce can make a hash commitment computationally hiding until opening, but would not by itself establish QDS security, public verification, transferability, or non-repudiation.

## HMAC properties

HMAC authentication of the public record at `core/secure_protocol.py:85` is valid only under a shared-secret registry assumption. It provides integrity and peer authentication among key holders. It does **not** provide public verification, transferability, or non-repudiation.

## State consumption

`verify_bit()` at `core/qds_protocol.py:219` measures `key_qubit.bharat_state.copy()` and discards the post-measurement state. The primitive measurement itself is correct, but verification does not update stored state.

**Theory:** physical measurement consumes/collapses the actual state.  
**Simulator behavior:** cloned classical array is measured; original vector survives.  
**Consequence:** repeated/incompatible verification behavior and quantum-key consumption are not faithfully modeled. This is a simulator-model divergence, not a claim that real hardware can copy unknown states.

## Security claim matrix

| Security claim | Code location | Required assumptions | Verdict | Confidence |
|---|---|---|---|---|
| Legacy unforgeability | `attacks/forgery.py` | No state access; random guessing; legacy semantics. | **PARTIALLY VERIFIED** | High |
| Secure-wrapper unforgeability | `core/secure_protocol.py:29` | Public commitments visible. | **CONTRADICTED** | High |
| Impersonation resistance | Legacy: none; wrapper: HMAC registry. | Secure pre-provisioned registry. | **Legacy fails; wrapper partial** | High |
| Repudiation resistance | No recipient comparison/thresholds. | Multi-recipient protocol. | **UNSUPPORTED** | High |
| Transferability | No forwarding/multi-recipient operation. | Multi-recipient protocol. | **UNSUPPORTED** | High |
| Public verifiability | HMAC registry. | Asymmetric/public verification. | **UNSUPPORTED** | High |
| Replay resistance | `SecureVerifier.verify()` | Durable shared verifier state. | **PARTIALLY VERIFIED** | High |
| One-time signing | `SecureSession.sign()` | Same live session object. | **PARTIALLY VERIFIED** | High |
| Key secrecy | Public commitments. | Hiding commitment. | **CONTRADICTED** | High |
| Quantum-state security | `bharat_state.copy()` | Physical destructive measurements/bounded copies. | **UNSUPPORTED** | High |

# 8. Alternative Technology Analysis

| Chosen approach | Alternative | Comparative finding |
|---|---|---|
| Pure statevectors | Density matrices/Kraus operators; Qiskit Aer; QuTiP | Statevectors are simple and fast for ideal 1–3 qubit demonstrations. Density/Kraus models are more suitable for mixed noise and realistic channels. |
| Three Pauli bases | Two-basis BB84-style setup; published QDS distribution schemes | Three bases make the ideal intercept-resend mismatch `1/3`; this does not make the protocol a standard QDS. |
| Pauli trajectory noise | Device-calibrated readout/loss/damping/correlated-noise model | Current approach is educationally reasonable but not sufficient for hardware/security conclusions. |
| Exact binomial-tail threshold (`alpha=1e-6`) | Confidence intervals; ROC/power analysis | The simulation now declares an independent-Pauli-model false-reject target; this remains a statistical calibration policy, not a hardware/security guarantee. |
| Hash “commitment” to six-value secret | Proper randomized commitment with secret high-entropy opening; formal protocol | Current approach is not hiding. A commitment alone still does not implement a QDS. |
| HMAC record authentication | Public-key signatures for public evidence; well-defined authenticated-channel protocol | HMAC is suitable for two-party shared-secret authentication, not public verification/non-repudiation. |
| In-memory replay state | Durable database/transactional session registry | Existing protection disappears on a new process/request and is unsuitable for deployed replay security. |

# 9. Evidence Matrix

| Claim | Repository evidence | Theoretical basis | Validation status | Confidence | Notes |
|---|---|---|---|---|---|
| Ideal default teleportation works | `core/teleportation.py:59` | Bennett et al. (1993) | **VERIFIED** | High | Default `phi+`, ideal normalized inputs. |
| Bell vectors are correct | `core/entanglement.py:65` | Standard Bell-state algebra | **VERIFIED** | High | Circuit and target vectors agree. |
| X/Y/Z intercept-resend gives `1/3` mismatch | `attacks/intercept_resend.py` | Mutually unbiased Pauli bases | **VERIFIED** | High | Ideal attack only. |
| Noise mismatch cap is `1/3` | `docs/protocol_math.md:82-89` | Exact Pauli algebra | **CONTRADICTED** | High | Actual rate is `2p/3`. |
| Blind legacy forgery is `(1/2)^L` | `attacks/forgery.py`, `evaluation/security_analysis.py` | Independent Bernoulli positions | **PARTIALLY VERIFIED** | High | Legacy toy threat model only. |
| Intercepting legacy forger has probability 1 | `attacks/forgery.py` | Re-measuring attacker-collapsed state in same basis | **VERIFIED** | High | Demonstrates legacy scheme failure. |
| Detector operates under stated noisy attack setting | `evaluation/validate_detection.py` | Experiment trace | **CONTRADICTED** | High | Noise only in calibration, not attack trials. |
| Secure commitments hide descriptions | `core/secure_protocol.py:29` | Commitment hiding definition | **CONTRADICTED** | High | Six-value enumeration. |
| HMAC enables public signatures | `core/secure_protocol.py` | NIST FIPS 198-1 / 186-5 | **CONTRADICTED** | High | HMAC is symmetric. |
| Complete QDS security | `core/qds_protocol.py`, `core/secure_protocol.py` | Gottesman–Chuang/QDS literature | **UNSUPPORTED** | High | Missing fundamental properties. |
| Runtime is linear in L | `evaluation/performance_benchmark.py` | Fixed work per key element | **CONSISTENT WITH THEORY** | Medium | Benchmark data unverified here. |

# 10. Problems, Weaknesses and Limitations

## CRITICAL

1. **Enumerable commitments defeat secure-wrapper key secrecy and unforgeability.**  
   Location: `core/secure_protocol.py:29`, `:80`, `:139-146`.  
   Why: only six candidate `(basis,eigen)` values per commitment.  
   Required action category: security design and code change.

2. **The repository is not a complete recognized QDS implementation.**  
   Location: `core/qds_protocol.py`, `core/secure_protocol.py`.  
   Why: no multi-recipient transferability, repudiation model, bounded-copy treatment, public verification, formal proof, or recognized construction.  
   Required action category: protocol redesign, formal security work, and documentation correction.

## HIGH

3. **Noise/calibration versus attack-trial mismatch.**  
   Location: `evaluation/validate_detection.py:74-126`.  
   Why: attack trials do not receive `channel_noise_p`.  
   Required action category: experiment/code revision and regenerated results.

4. **Verification does not consume stored quantum states.**  
   Location: `core/qds_protocol.py:219`.  
   Why: statevector copy is measured and collapse discarded.  
   Required action category: simulator/model redesign.

5. **Incorrect noise documentation.**  
   Location: `docs/protocol_math.md:82-89`; related test narrative.  
   Why: fidelity is confused with mismatch probability.  
   Required action category: documentation and test correction.

## MEDIUM

6. **Threshold is a heuristic, not a security-calibrated test.**  
   Location: `detection/thresholds.py:26`.  
   Required action category: statistical methodology/experiment revision.

7. **Replay and one-time controls are only in-memory.**  
   Location: `core/secure_protocol.py`, `scenario_runner.py`.  
   Required action category: deployment architecture change.

8. **HMAC presentation risks being interpreted as public-signature security.**  
   Location: `core/secure_protocol.py`.  
   Required action category: threat-model/documentation clarification.

## LOW

9. **Duplicate/stale-looking names reduce auditability.**  
   Locations: `attacks/attacks_forgery.py`, `attacks/attacks_intercept_resend.py`, `tests/tests_test_attacks.py`, `tests/tests_test_validation.py`.  
   Required action category: repository hygiene.

# 11. Reproducibility and Testing

The repository includes script-style test files under `tests/` and checked-in data in `results/`. Those scripts provide useful internal assertions but are not an independently reproduced validation record.

**UNVERIFIED in this audit environment:** `python` and the Windows `py` launcher could not find an installed interpreter. Therefore the claimed passing test count, numerical outputs, and timing results were not executed during this audit.

Known reproducibility limitations:

- `requirements.txt` only declares `numpy>=1.24`; no locked NumPy/Python versions.
- No environment/hardware/OS metadata for timing results.
- No CI evidence, coverage report, or property-based test suite.
- Results do not provide complete generation provenance for every checked-in figure.
- NumPy RNG is appropriate for statistical simulation, not cryptographic secrets; official NumPy documentation explicitly states this boundary.
- Benchmark results should be treated as machine-specific observations, not portable performance guarantees.

**Pending Deep Verification:** empirical rerun of tests, result-generation scripts, numerical confidence intervals, and benchmark replication require a functioning pinned Python environment.

# 12. Final Technical Conclusions

## VERIFIED

- Ideal pure-state simulation primitives are substantially correct for their intended small-system scope.
- Bell-state construction is correct.
- Default ideal `phi+` teleportation is correct.
- Three-basis ideal intercept-resend mismatch is `1/3`.
- The code implements the stated stochastic Pauli channel.
- HMAC is correctly identifiable as shared-secret record authentication.

## PARTIALLY VERIFIED

- Legacy blind-forgery and intercepting-forgery conclusions are valid only in the repository’s explicit toy models.
- Thresholding is an understandable educational heuristic, not a calibrated security test.
- In-memory replay and one-time session controls work only within one live process/session.
- Linear complexity is theoretically expected but benchmark measurements remain unverified here.

## CONTRADICTED

- The `1/3` noise mismatch cap claim.
- Hiding/security of the low-entropy SHA-256 commitments.
- Any implication that HMAC gives public verification or non-repudiation.
- Any statement that reported detection sweeps tested attacks under the same configured channel noise used for calibration.

## UNSUPPORTED

- Complete QDS classification.
- Information-theoretic QDS security.
- Transferability, repudiation resistance, public verification, and non-repudiation.
- Production readiness.

## UNVERIFIED

- Test-suite pass count.
- Exact result tables, rates, performance values, and R² figures.
- Reproducibility of checked-in experimental results in the current environment.

The defensible project framing is: **an educational quantum-inspired threat-detection simulation that correctly demonstrates several ideal quantum-information concepts and also exposes important weaknesses in its own legacy signing model.** It is not defensible to frame it as a secure deployable QDS implementation without addressing the critical findings above.

# 13. References

1. Charles H. Bennett, Gilles Brassard, Claude Crépeau, Richard Jozsa, Asher Peres, and William K. Wootters. “Teleporting an unknown quantum state via dual classical and Einstein–Podolsky–Rosen channels.” *Physical Review Letters* 70, 1895–1899 (1993). DOI: [10.1103/PhysRevLett.70.1895](https://doi.org/10.1103/PhysRevLett.70.1895).
2. Daniel Gottesman and Isaac Chuang. “Quantum Digital Signatures.” 2001. [arXiv:quant-ph/0105032](https://arxiv.org/abs/quant-ph/0105032). DOI: [10.48550/arXiv.quant-ph/0105032](https://doi.org/10.48550/arXiv.quant-ph/0105032).
3. D. J. Wallden, V. Dunjko, A. Kent, and E. Andersson. “Quantum digital signatures with quantum-key-distribution components.” *Physical Review A* 91, 042304 (2015). DOI: [10.1103/PhysRevA.91.042304](https://doi.org/10.1103/PhysRevA.91.042304).
4. W. K. Wootters and W. H. Zurek. “A single quantum cannot be cloned.” *Nature* 299, 802–803 (1982). DOI: [10.1038/299802a0](https://doi.org/10.1038/299802a0).
5. John Preskill. “Qubit Channels,” Ph/CS 219A Lecture 5 (2020). [Caltech official slides](https://www.preskill.caltech.edu/ph219/Ph-CS-219A-Slides-2020/Ph-CS-219A-Lecture-5-Qubit-Channels.pdf).
6. IBM Quantum. [`depolarizing_error` API documentation](https://eu-de.quantum.cloud.ibm.com/docs/api/qiskit/0.29/qiskit.providers.aer.noise.depolarizing_error).
7. National Institute of Standards and Technology. FIPS 198-1, *The Keyed-Hash Message Authentication Code (HMAC)* (2008). DOI: [10.6028/NIST.FIPS.198-1](https://doi.org/10.6028/NIST.FIPS.198-1).
8. National Institute of Standards and Technology. FIPS 186-5, *Digital Signature Standard (DSS)* (2023). DOI: [10.6028/NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5).
9. National Institute of Standards and Technology. FIPS 180-4, *Secure Hash Standard* (2015). DOI: [10.6028/NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4).
10. Luca Trevisan. *Cryptography and Computational Complexity*, Chapter 20.3, “Commitment Scheme.” [Stanford-hosted text](https://theory.stanford.edu/~trevisan/books/crypto.pdf).
11. NumPy Developers. [Random sampling documentation](https://numpy.org/doc/stable/reference/random/).
