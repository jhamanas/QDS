# Canonical modules

The active implementation and tests use the following paths:

- Attacks: `attacks/forgery.py`, `attacks/intercept_resend.py`,
  `attacks/impersonation.py`, `attacks/replay.py`,
  `attacks/unauthorized_verification.py`, and `attacks/memory_tamper.py`.
- Tests: `tests/test_qds_protocol.py`, `tests/test_detector.py`,
  `tests/test_secure_protocol.py`, `tests/test_unauthorized_verification.py`,
  `tests/test_state_store.py`, `tests/test_metrics.py`, and
  `tests/test_memory_tamper.py`.

The former `attacks_*.py` and `tests_test_*.py` copies were removed. They were
not imported by the dashboard or API and had drifted from the canonical tests.
New changes must use the paths listed above.
