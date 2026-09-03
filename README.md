# Quantum-Inspired Threat Detection Framework

A quantum-inspired, statevector-simulator security-evaluation framework:
a teleportation-based QDS *model*, a statistical detector for channel
disturbance, attack simulators, and performance evaluation. It is not a
production authentication service, a standardized QDS construction, a formal
security proof, or an implementation tested on quantum hardware.

**Start here:** `docs/final_report.md` for the project summary and
`results/security_analysis.json` plus `results/reproducibility.json` for the
latest machine-readable evaluation and its provenance. The older Markdown
security report is retained as historical narrative, not a replacement for
the reproducible result files.

## Setup

```bash
pip install -r requirements.txt
```

Python 3.10+ (uses `X | None` union type syntax and `math.comb`).

## Running the tests

Each phase has its own test file under `tests/`, meant to be run in
order — later phases assume earlier ones pass:

```bash
python3 tests/test_primitives.py          # Phase 0
python3 tests/test_entanglement.py        # Phase 1
python3 tests/test_teleportation.py       # Phase 2
python3 tests/test_qds_protocol.py        # Phase 3
python3 tests/test_detector.py            # Phase 4
python3 tests/test_attacks.py             # Phase 5
python3 tests/test_validate_detection.py  # Phase 6
python3 tests/test_security_analysis.py   # Phase 7
python3 tests/test_performance_benchmark.py  # Phase 8
python3 tests/test_secure_protocol.py         # Hardened session controls
```

All run from the project root (each test file adjusts `sys.path`
itself). Record the test output with the commit under review rather than
relying on a historical pass count.

Note: `tests/test_attacks.py`, `test_validate_detection.py`,
`test_security_analysis.py`, and `test_performance_benchmark.py` run
real teleportation simulations hundreds to tens of thousands of times
and can take from several seconds to a couple of minutes each.

## Project structure

```
core/            Phases 0-3: gates, entanglement, teleportation, QDS protocol
detection/       Phase 4: statistical baseline, calibration, decision engine
attacks/         Phase 5: intercept-resend, forgery, impersonation, replay
evaluation/      Phases 6-8: detection validation, security analysis, perf
tests/           One test file per module (or per package for attacks/evaluation)
results/         Generated output data (JSON, CSV, MD) -- not code
docs/            Architecture, protocol math, and final report
```

See `docs/architecture.md` for the full module-by-module breakdown and
data-flow diagram.

## Hardened secure-session layer

`core/secure_protocol.py` adds the deployment controls deliberately absent
from the original attack-study model: authenticated distribution records,
commitments to Alice's pre-distributed Pauli descriptions, payload binding,
replay tracking, and strict one-time session keys. The HMAC-authenticated
record is a classical stand-in for the authenticated channel a deployable QDS
system requires; it is not a claim of information-theoretic authentication.

Run a configurable scenario:

```bash
python run_scenario.py --attack intercept-resend --intensity 0.5 --length 64 --noise 0.03 --threshold 8
```

Available attacks: `honest`, `intercept-resend`, `blind-forgery`,
`intercepting-forgery`, `impersonation`, `replay`, `key-reuse`,
`payload-tamper`, and `unauthorized-verification`. Run
`python run_scenario.py --help` for parameters.

### Click-and-slider dashboard

Run this local dashboard and open the address it prints (normally
`http://127.0.0.1:8000`). It lets you select attacks and adjust key length,
intensity, noise, threshold, message bit, payload, and seed without entering
a separate command for every experiment.

```bash
python dashboard.py
```

### Publish on GitHub and deploy online

Vercel is the simplest fit for this project because it serves
`dashboard.html` as a static page and runs `api/run.py` as a Python Function.
The repository now includes the required adapter and `vercel.json`.

1. Create a Vercel project and import this existing GitHub repository.
2. If the repository has not been pushed yet, connect its existing Git remote
   and push the current branch:

```bash
git remote -v
git add .
git commit -m "Prepare QDS dashboard deployment"
git push
```

3. Sign in at [Vercel](https://vercel.com), choose **New Project**, import the
   GitHub repository, and click **Deploy**. Leave Framework Preset as
   **Other**, leave Build Command empty, and use the repository root as the
   project root.
4. Open the generated Vercel URL. The dashboard calls `/api/run` on the same
   deployment, so no localhost URL change is needed.

After this one-time connection, push changes with:

```bash
git add .
git commit -m "Describe the change"
git push
```

Vercel automatically creates a new deployment for pushes and pull requests;
merges to the configured production branch update the live domain. You do not
manually relaunch the site. Existing browser tabs may need a refresh to load a
new frontend bundle. See [Vercel Git deployments](https://vercel.com/docs/git)
and [Vercel Python Functions](https://vercel.com/docs/functions/functions-api-reference/vercel-sdk-python).

Important production limitation: the API now injects `core.state_store.SQLiteStateStore`
using `QDS_STATE_DB` (default `/tmp/qds_state.sqlite3`) for atomic replay and
authorization consumption. Vercel's `/tmp` filesystem is ephemeral, so configure
a durable mounted volume or a hosted database adapter before treating the public
site as a security system. The simulation still creates a fresh demonstration
session per request and does not provide real user authentication.

### SOC audit and reporting endpoints

Each dashboard API scenario now appends a redacted audit event: verdict, attack
type, mismatch evidence, correlation IDs, and a SHA-256 payload digest. Payload
contents and private key material are never stored. Events are hash chained and
become HMAC-authenticated when `QDS_AUDIT_KEY` is configured.

For a durable deployment, point `QDS_STATE_DB` at mounted or managed storage.
The same ephemeral-Vercel warning applies to the audit chain. Available
endpoints are `GET /api/health`, `GET /api/audit?limit=50`,
`GET /api/analytics`, and `GET /api/reports/export?format=json|csv`.

`POST /api/admin/reset` clears audit records only. It remains disabled until
`QDS_ADMIN_TOKEN` is set and requires that value in `X-QDS-Admin-Token`.
Cross-origin browser access is disabled by default; configure an exact
`QDS_ALLOWED_ORIGIN` only for a separate trusted frontend.

## Delivery Table (Expected Deliverables)

| Deliverable | Location | Status |
|---|---|---|
| Quantum state, Bell-pair, and teleportation simulator | `core/` | Complete |
| QDS signing and verification model | `core/qds_protocol.py` | Complete |
| Hardened authenticated session design | `core/secure_protocol.py` | Complete |
| Selectable attack simulator with variables | `scenario_runner.py`, `run_scenario.py` | Complete |
| Click-and-slider presentation dashboard (attack intensity and noise model controls) | `dashboard.py`, `dashboard.html` | Complete |
| Statistical QBER detector | `detection/` | Complete |
| Signer-issued verifier authorization | `core/secure_protocol.py` | Complete |
| Unauthorized-verifier attack and tests | `attacks/unauthorized_verification.py`, `tests/test_unauthorized_verification.py` | Complete |
| Durable replay/authorization consumption | `core/state_store.py` (configure `QDS_STATE_DB`) | Complete locally; Vercel needs durable storage |
| Acceptance confidence intervals | `evaluation/metrics.py`, `evaluation/acceptance_matrix.py` | Complete |
| Memory-tamper fail-closed path | `attacks/memory_tamper.py`, `core/secure_protocol.py` | Complete |
| Attack, security, and performance evaluation | `attacks/`, `evaluation/`, `results/` | Complete |
| Automated verification suite | `tests/` | Complete |

## Headline findings (see `docs/final_report.md` for detail)

- The original blind-forgery bound was `(1/6)^L`; the corrected bound
  is `(1/2)^L` — verification doesn't check a disclosure against
  Alice's true secret basis, only against Bob's physical qubit.
- An attacker with physical access to Bob's stored qubits forges with
  probability 1.0, independent of L.
- Impersonation and replay/key-reuse are both total, L-independent
  breaks requiring deployment-level mitigations outside this codebase's
  scope (authenticated channel, freshness tracking, one-time-key
  enforcement).
- The statistical QBER detector catches exactly one of five attack
  surfaces (intercept-resend); the other four are unconditionally
  invisible to it.
- The recorded evaluation recommends **L=81** for the illustrative 2⁻⁴⁰
  blind-forgery target at 3% channel noise, under its stated threshold policy.
- The implementation scales linearly in L (R²≈0.9999+) and is fast in
  practice (tens of milliseconds per sign/verify cycle at the
  recommended L).

## Regenerating `results/`

```bash
python3 -c "
import json, numpy as np
from evaluation.validate_detection import sweep_intercept_resend_detection, attack_detectability_summary
rng = np.random.default_rng(0)
points = sweep_intercept_resend_detection(L=64, channel_noise_p=0.03,
    intercept_probs=(0.05,0.1,0.25,0.5,0.75,1.0), rng=rng,
    n_calibration_trials=200, n_attack_trials=100)
summary = attack_detectability_summary(L=64, channel_noise_p=0.03, rng=rng,
    n_calibration_trials=200, n_trials_per_attack=80)
print(json.dumps({'sweep': [p.__dict__ for p in points], 'summary': summary}, indent=2))
"
```

and similarly for `evaluation.performance_benchmark.write_benchmark_csv`
— see that module's docstrings for the full function signatures.

For the supported, deterministic regeneration command and environment record,
see `docs/reproducibility.md`.

## State lifecycle and security scope

The base protocol is a reusable simulator abstraction: its stored statevector
can be copied and measured during an experiment and therefore does not model
physical qubit consumption. The hardened session layer instead consumes both
the signature ID and verifier authorization before measurement, so a captured
signature cannot be retried. This operational replay protection must not be
mistaken for a physical quantum-memory model.

QBER measures channel disturbance and reliably helps detect intercept-resend
in this simulator. It does not detect attacks that leave no measurement
disturbance, such as an authenticated replay or an attacker who controls the
stored state. HMAC is only a classical authenticated-channel stand-in, not a
public digital signature. A deployment needs real identity/authentication,
durable state storage, key management, and an appropriate threat model.
