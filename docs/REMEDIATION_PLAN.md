# 1. Critical Issues

## 1.1 Enumerable commitments expose the purported secret descriptions

- **Problem:** The secure-wrapper commitment hashes public session/set/index values plus `(basis, eigen)`. Each committed secret has only `3 x 2 = 6` possible values, so an observer can enumerate all candidates and recover every description.
- **Exact file/location:** `core/secure_protocol.py:29` (`_commitment()`), `:80` (commitment construction), and `:139-146` (verification).
- **Why it matters:** The wrapper publishes a value intended to bind descriptions while keeping them hidden, but the value is not hiding.
- **Security/theoretical consequence:** Key-description secrecy and commitment hiding fail. A recovered true description can be used in a fresh `SecureSignature`, so the secure-wrapper unforgeability claim fails. This is a low-entropy enumeration attack, not a weakness in SHA-256.
- **Required fix:** Redesign the commitment and signature/authentication protocol before making any secure-wrapper claim. If commitments are retained, use a formally specified randomized commitment with a high-entropy secret opening value that is not publicly available before opening. Separately specify how an authentic signature is issued and verified; a commitment alone is not a signature scheme.
- **Fix category:** Code change; architecture/model change; documentation change.
- **How to verify later:**
  1. Add a negative test that enumerates all six `(basis,eigen)` values against each public commitment.
  2. The redesigned construction must make that test fail to recover unrevealed descriptions under its stated threat model.
  3. Define and test a complete forgery game using a public record and a newly generated signature ID.
  4. Obtain a separate theory/security review before claiming unforgeability.

## 1.2 The protocol is not a complete recognized QDS implementation

- **Problem:** The code is a one-bit, one-recipient, disclosure-based educational model, not an implementation of the Gottesman-Chuang construction or another complete documented QDS protocol.
- **Exact file/location:** `core/qds_protocol.py`; `core/secure_protocol.py`.
- **Why it matters:** Presenting the model as a complete QDS can mislead judges about the level of established security.
- **Security/theoretical consequence:** No established transferability, repudiation resistance, public verification, bounded public-key-copy treatment, multi-recipient distribution, or formal QDS security proof.
- **Required fix:** Make an explicit project-scope decision before changing code:
  - retain an educational QDS-inspired simulator and revise all security claims accordingly; or
  - adopt a named published QDS protocol and implement its required roles, distribution, thresholds, adversary model, and proof assumptions.
- **Fix category:** Architecture/model change; documentation change; potentially major code change.
- **How to verify later:** Map every required property of the selected protocol to implementation, tests, and a source reference. Do not claim a property without a defined game/threat model and a test or proof boundary.

# 2. High-Priority Issues

## 2.1 Calibration noise is omitted from attack trials

- **Problem:** Detection sweeps calibrate with `channel_noise_p` but call attack trials that do not apply the same ordinary Pauli noise.
- **Exact file/location:** `evaluation/validate_detection.py:74-126`, especially `run_intercept_resend_trial()` and `sweep_intercept_resend_detection()`.
- **Why it matters:** A result labeled as detection at `p=0.03` is not an attack-plus-noise result.
- **Security/theoretical consequence:** Detection rates are not valid estimates of detector performance under the stated noisy channel configuration and may be optimistic.
- **Required fix:** Ensure the experimental path applies the defined baseline noise to attack trials as well as calibration trials, with the ordering and independence assumptions documented.
- **Fix category:** Code change; experiment change; documentation change.
- **How to verify later:** Add tests showing the exact attack-trial path receives the configured `channel_noise_p`. Regenerate all detection tables with recorded seed, parameters, number of trials, false-reject rate, and confidence intervals.

## 2.2 Verification does not model quantum-state consumption

- **Problem:** `verify_bit()` measures `key_qubit.bob_state.copy()` and discards the collapsed output.
- **Exact file/location:** `core/qds_protocol.py:219`.
- **Why it matters:** The primitive correctly implements collapse, but the protocol-level verifier does not update Bob’s stored state.
- **Security/theoretical consequence:** Repeated verification and incompatible-basis measurement behavior do not model a physical quantum state. Conclusions involving reuse, state consumption, or multiple verification attempts are limited to the simulator model.
- **Required fix:** Decide and document the intended physical lifecycle of a received key state. If verification is meant to consume it, persist the returned collapsed state or mark the state/session consumed; if it is not meant to model this, restrict the project claim to a nonphysical idealized abstraction.
- **Fix category:** Architecture/model change; code change; documentation change.
- **How to verify later:** Add tests for repeated verification in the same basis and an incompatible basis, asserting behavior against the explicitly selected model. Include a lifecycle test proving consumed states cannot silently support unsupported verification semantics.

## 2.3 Depolarizing-noise mismatch documentation is wrong

- **Problem:** Documentation says the implemented channel’s mismatch rate caps near `1/3`; for the actual Pauli trajectory it is `2p/3`, so it is `2/3` at `p=1`.
- **Exact file/location:** `docs/protocol_math.md:82-89`; explanatory high-noise text in `tests/test_detector.py:145-153`.
- **Why it matters:** The claim confuses mean fidelity of a Z eigenstate with same-basis measurement mismatch probability.
- **Security/theoretical consequence:** Incorrect theory can invalidate parameter interpretation and mislead judges about detector/noise behavior.
- **Required fix:** Correct the derivation, distinguish fidelity from mismatch probability, and update tests/results/comments that use the incorrect cap.
- **Fix category:** Documentation change; test change; potentially result regeneration.
- **How to verify later:** For several `p` values including `0`, `0.03`, `0.5`, and `1`, simulate enough trials and compare observed mismatch rate with `2p/3` using stated statistical tolerance.

# 3. Medium-Priority Issues

## 3.1 Threshold calibration is a heuristic rather than a security-calibrated statistical test

- **Problem:** The detector threshold is `ceil(mu + max(6 sigma, 1))`, estimated from a finite sampled baseline.
- **Exact file/location:** `detection/thresholds.py:26`; baseline source `detection/baseline.py`.
- **Why it matters:** The underlying model is naturally a discrete binomial mismatch count, especially at low expected mismatch counts, rather than an exactly normal statistic.
- **Security/theoretical consequence:** The threshold has no explicit false-reject target, finite-sample uncertainty, power analysis, or stated confidence bound. It is reasonable as an educational heuristic but insufficient for security performance claims.
- **Required fix:** Preserve the current heuristic only if it is labeled as such, or define a target false-reject rate and choose a threshold from an exact/appropriate binomial-tail calculation. Record finite-sample uncertainty and detector power.
- **Fix category:** Statistical methodology change; experiment change; documentation change; potentially code change.
- **How to verify later:** Compare held-out false-reject rates with the specified target over repeated seeded runs. Report confidence intervals and detection rates under the same noise-plus-attack conditions.

## 3.2 Replay and one-time controls are in-memory only

- **Problem:** Replay IDs, registered distribution records, and `_used` status exist only in Python process memory. Dashboard/API scenario execution creates a fresh session per request.
- **Exact file/location:** `core/secure_protocol.py:63-154`; `scenario_runner.py`.
- **Why it matters:** Controls that disappear after restart or per request cannot support deployment-level replay or one-time-signing guarantees.
- **Security/theoretical consequence:** Replay and one-time claims are limited to a single live object/process, not a durable multi-request service.
- **Required fix:** Either explicitly keep this as a nonpersistent demonstration or design durable, authenticated state management before claiming replay protection in deployment.
- **Fix category:** Architecture/model change; code change; documentation change.
- **How to verify later:** Restart/recreate the verifier/session boundary in a controlled test and verify the documented expected behavior. If durable protection is later implemented, test replay across requests and restarts.

## 3.3 HMAC must not be presented as public-signature security

- **Problem:** HMAC authenticates a distribution record using a shared secret, but may be interpreted as giving digital-signature properties.
- **Exact file/location:** `core/secure_protocol.py:85`, `:112-121`; related README/dashboard claims.
- **Why it matters:** HMAC gives peer authentication/integrity among key holders, not public verification, transferability, or non-repudiation.
- **Security/theoretical consequence:** Claims beyond shared-secret record authentication are unsupported.
- **Required fix:** State the HMAC trust model explicitly and remove any implication of public verification/non-repudiation. If public verification is a goal, select and formally integrate a suitable asymmetric mechanism or a fully specified QDS protocol.
- **Fix category:** Documentation change; architecture/model change; potentially code change.
- **How to verify later:** Add a requirements-level security matrix distinguishing the HMAC record-authentication claim from public digital-signature claims. Ensure demo wording matches that matrix.

# 4. Low-Priority Issues

## 4.1 Duplicate/stale-looking attack and test files reduce auditability

- **Problem:** Duplicate-looking names create ambiguity about active code and test coverage.
- **Exact file/location:** `attacks/attacks_forgery.py`, `attacks/attacks_intercept_resend.py`, `attacks/attacks___init__.py`, `tests/tests_test_attacks.py`, `tests/tests_test_validation.py`.
- **Why it matters:** Auditors and judges may inspect an inactive or divergent copy; future fixes can be applied inconsistently.
- **Security/theoretical consequence:** No direct cryptographic consequence, but it weakens reproducibility and review confidence.
- **Required fix:** Inventory imports and test invocation paths, identify canonical files, then remove/archive duplicates only after confirming they are unused and tests are consolidated.
- **Fix category:** Repository hygiene; documentation change; potentially code/test change.
- **How to verify later:** Run the complete test suite and static import checks after cleanup; document the canonical module/test map.

# 5. Recommended Fix Order

1. **Freeze unsafe security claims and relabel the project immediately.** Reword public-facing material to an educational QDS-inspired simulation until the critical issues are resolved. This prevents overclaiming while work proceeds.
2. **Resolve the commitment/unforgeability design failure.** The current wrapper cannot be called secure because the published commitments expose every description. No security experiment is meaningful as a secure-wrapper claim until this design is addressed.
3. **Make the protocol-scope decision.** Decide whether the goal is a defensible educational simulator or a named published QDS implementation. This prevents piecemeal fixes from being mistaken for a security proof.
4. **Correct the Pauli-noise theory/documentation.** The `2p/3` mismatch result is a direct established mathematical correction; subsequent threshold and experiment interpretation must use it.
5. **Repair noise-plus-attack experimental methodology.** Apply the same declared ordinary-noise model in relevant attack trials, then rerun affected detection/security results.
6. **Define the quantum-state lifecycle and state-consumption model.** This determines valid semantics for repeated verification, replay modeling, and key reuse before further security claims or experiments.
7. **Strengthen the statistical methodology.** Only after the channel and experiment paths are defined can threshold false-reject/detection analyses be interpreted reliably.
8. **Establish reproducibility.** Install/pin Python and NumPy, capture run metadata/seeds, rerun all scripts, and preserve generated results. This is needed before asserting numerical claims.
9. **Address persistence and deployment boundaries.** Either add durable state only if deployment is in scope, or explicitly preserve the dashboard as a stateless demonstration.
10. **Perform repository hygiene and presentation polish.** Remove duplicate ambiguity, update diagrams/results/references, and keep the final SIH presentation aligned with established evidence.

This order follows dependency: a flawed security design and incorrect theoretical model must be resolved before interpreting detector statistics or presenting regenerated numerical results. Repository cleanup and polish are valuable but do not repair security or methodology.

# 6. Experiments That Must Be Re-run

All existing empirical outputs remain **UNVERIFIED** in the audit environment because no Python interpreter was available. Experiments below should be rerun only after a pinned, recorded environment exists and after prerequisite model/experiment corrections are made.

| Experiment | Existing script/file | Parameters to record | Expected theoretical result | What must change before rerun | Record | Successful validation |
|---|---|---|---|---|---|---|
| Teleportation fidelity | `tests/test_teleportation.py`; `core/teleportation.py` | Input states, RNG seed, `bell_kind`, trial count, tolerance | Fidelity 1 for normalized inputs with default `phi+` resource and correct correction. | No established algorithmic correction required; add environment metadata and retain default-resource scope. | Per-input fidelity, classical bits, tolerance, Python/NumPy versions. | All defined default-`phi+` cases meet stated numerical tolerance. |
| Intercept-resend mismatch | `tests/test_attacks.py`; `attacks/intercept_resend.py` | `L`, basis pool, intercept probability, seed, trials, ordinary-noise setting | Full ideal interception gives mismatch `1/3`. | Clearly separate ideal result from noisy result; if claiming noisy performance, apply ordinary noise. | Mean, confidence interval, actual trial count, seed/configuration. | Ideal estimate is statistically consistent with `1/3`; noisy condition is separately labeled. |
| Depolarizing-noise mismatch | `tests/test_detector.py`; `core/noise.py`; `detection/baseline.py` | `p in {0,0.03,0.5,1}`, `L`, trials, basis distribution, seed | Same-preparation-basis mismatch is `2p/3`. | Correct theory/comments/tests that assert or describe a `1/3` mismatch cap. | Observed mismatch, expected `2p/3`, fidelity separately, confidence interval. | Measurements are statistically consistent with `2p/3`; fidelity and mismatch are not conflated. |
| Detection with noise applied to attack trials | `evaluation/validate_detection.py`; `results/detection_results.json` | `L=64`, `p=0.03` where used, threshold policy, intercept probabilities, calibration and attack trial counts, seeds | Detection depends on the combined ordinary-noise-plus-attack distribution. | Apply `channel_noise_p` in attack trials and document noise/attack ordering and independence. | Baseline/attack definitions, FPR, TPR, confidence intervals, threshold, raw counts. | Results explicitly correspond to their stated noise setting and include uncertainty. |
| Threshold evaluation | `detection/thresholds.py`; `tests/test_detector.py`; `evaluation/security_analysis.py` | `L`, `p`, baseline size, holdout size, target alpha if adopted, seeds | Under independent Pauli noise, mismatch count follows a binomial model with rate `2p/3`. | Define whether `mean+6sigma` remains heuristic or replace/compare it with an exact tail threshold. | Threshold, empirical holdout false-reject rate, target rate, confidence interval. | A stated statistical target is met or heuristic status is transparently retained. |
| Blind forgery | `attacks/forgery.py`; `evaluation/security_analysis.py`; `tests/test_attacks.py` | `L`, threshold, trials, seed, protocol version | Legacy threshold-zero toy model gives per-position acceptance `1/2`, whole acceptance `(1/2)^L`. | Keep results explicitly confined to legacy toy model; do not apply it to redesigned wrapper unless a new proof/game exists. | Threat model, threshold, analytic probability, observed rate/CI. | Observations agree with the stated legacy-model calculation within declared uncertainty. |
| Intercepting forger | `attacks/forgery.py`; `tests/test_attacks.py` | `L`, attacker basis selection, trials, seed, state-lifecycle model | Existing legacy simulator model accepts after attacker collapses Bob’s state and reports it. | Define/fix state-consumption model first; label outcome as legacy-model insecurity, not general QDS behavior. | Exact attacker access assumption, state mutation behavior, outcome counts. | Result matches the explicitly selected simulator lifecycle model. |
| Timing benchmark | `evaluation/performance_benchmark.py`; `results/performance_benchmark.csv` | Python/NumPy versions, OS, CPU, load conditions, `L` values, repeats, seed, timing method | Fixed-size per-qubit work suggests O(L). | Pin environment and improve provenance; no established algorithmic correction required. | Raw timings, repetitions/variance, hardware, fitted slope/intercept/R². | Timing trend is reproducible on stated environment; reported result is labeled machine-specific. |

The existing recommended-length search and checked-in security report also require rerun after the noise correction, corrected noise-plus-attack methodology, and explicit decision about the legacy versus redesigned security model. Until then, `L≈78–81` remains **PLAUSIBLE BUT INSUFFICIENTLY VALIDATED**, not a deployment recommendation.

# 7. Security Claims That Must Be Removed or Reworded

| Current implication | Why unsupported/incorrect | Safer technically accurate wording |
|---|---|---|
| “This is a secure/deployable QDS implementation.” | Audit found missing complete-QDS properties and a critical commitment enumeration failure. | “This is an educational quantum-inspired signature/threat-detection simulation; it is not presented as a secure or production-ready QDS implementation.” |
| “The SHA-256 commitments protect key descriptions.” | Each description has six candidates and is recoverable by enumeration. | “The current hash commitments are binding labels but do not hide the low-entropy descriptions; they must not be relied on for secrecy.” |
| “The secure wrapper is unforgeable.” | Enumerated descriptions permit fresh forged disclosures/IDs under the established model. | “The current secure wrapper does not establish unforgeability and contains a known low-entropy commitment-design failure.” |
| “HMAC provides public verification/non-repudiation.” | HMAC is shared-secret authentication, not an asymmetric public signature. | “HMAC authenticates an enrolled distribution record between shared-key parties; it does not provide public verification or non-repudiation.” |
| “The QDS protocol has transferability/repudiation resistance.” | No multi-recipient mechanism, forwarding model, or repudiation analysis exists. | “Transferability and repudiation resistance are outside the implemented model and have not been established.” |
| “Detector results are at `p=0.03` channel noise.” | Calibration uses `p`; attack trials omit it. | “Existing detection sweeps use a threshold calibrated from an honest `p=0.03` baseline but do not yet model that noise during attack trials.” |
| “Noise mismatch caps at `1/3`.” | Exact implemented-channel result is `2p/3`; `1/3` refers to a different quantity in the noted case. | “For the implemented stochastic Pauli channel, same-basis measurement mismatch is `2p/3`; at `p=1` it is `2/3`.” |
| “Results are proven/fully validated.” | Tests/results were not rerun in the audit environment; several experimental limits remain. | “The listed results are code-generated and theory-consistent where noted; independent reproduction and uncertainty reporting remain pending.” |
| “Replay protection is deployment ready.” | State is in-memory and dashboard runs fresh sessions per request. | “Replay-ID checks operate only within the live verifier process/model and do not establish durable deployment replay protection.” |

# 8. Final SIH-Safe Position

The project is currently an **educational quantum-inspired threat-detection simulation**. It demonstrates verified ideal statevector operations, Bell states, default quantum teleportation, an ideal three-basis intercept-resend disturbance calculation, and attack/detector modeling. It also usefully exposes weaknesses in its own legacy disclosure-based signing model.

It is **not** currently a secure, production-ready, or complete QDS implementation. In particular, secure-wrapper key descriptions are exposed by low-entropy commitment enumeration; transferability, repudiation resistance, public verification, and durable replay protection are not established; and some experimental results require methodology correction and rerun. Future changes should be presented as proposed remediation until independently implemented and verified.
