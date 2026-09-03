# Canonical modules

The active implementation and tests use the following paths:

- Attacks: `attacks/forgery.py`, `attacks/intercept_resend.py`,
  `attacks/impersonation.py`, `attacks/replay.py`,
  `attacks/unauthorized_verification.py`, and `attacks/memory_tamper.py`.
- Tests: `tests/test_qds_protocol.py`, `tests/test_detector.py`,
  `tests/test_secure_protocol.py`, `tests/test_unauthorized_verification.py`,
  `tests/test_state_store.py`, `tests/test_metrics.py`, and
  `tests/test_memory_tamper.py`.

Files with the older `attacks_*.py` or `tests_test_*.py` naming are retained for
historical compatibility and are not imported by the dashboard or API. New
changes should be made only in the canonical paths above.
