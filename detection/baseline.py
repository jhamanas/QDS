"""
detection/baseline.py

Phase 4: Statistical baseline collection.

Purpose
-------
Characterizes what "normal" (honest, non-attacked) verification looks like
once we admit a small amount of realistic channel/storage noise between
key distribution (Phase 3, teleportation delivers fidelity 1.0) and
verification. In the fully noiseless case, honest verification is always
mismatch_count == 0 (confirmed by tests/test_qds_protocol.py) -- there is
nothing to calibrate a statistical threshold against. This module
introduces a configurable channel-noise probability, runs many honest
sign/verify cycles under it, and records the resulting mismatch_count /
mismatch_rate distribution. detection/thresholds.py turns this
distribution into an actual accept/reject cutoff.

Collected BEFORE any attack simulators exist (Phase 5), so calibration is
not tuned to fit attacks in hindsight -- it reflects only honest-protocol
behavior under a chosen, fixed noise level.
"""

from __future__ import annotations
import numpy as np

from core.qds_protocol import generate_key_material, distribute_public_key, sign_bit, verify_bit
from core.noise import apply_depolarizing_noise


def run_honest_trial(L: int, channel_noise_p: float, rng: np.random.Generator) -> dict:
    """
    Runs one full honest protocol cycle -- key generation, quantum public
    key distribution, signing a random message bit -- then applies
    `channel_noise_p` depolarizing noise independently to each of Bob's
    disclosed-key-set qubits (modeling storage/channel imperfection
    between distribution and verification) before calling verify_bit with
    mismatch_threshold=0, so the raw (uncalibrated) mismatch_count for
    this trial is observed directly, not masked by any threshold.

    Returns a dict with message_bit, mismatch_count, total_checked, and
    mismatch_rate (QBER) for this single trial.
    """
    key_material = generate_key_material(L, rng)
    distribute_public_key(key_material, rng)

    message_bit = int(rng.integers(0, 2))
    signature = sign_bit(key_material, message_bit)

    key_set = key_material.key_set_0 if message_bit == 0 else key_material.key_set_1
    for kq in key_set:
        kq.bob_state = apply_depolarizing_noise(
            kq.bob_state, channel_noise_p, target=0, n_qubits=1, rng=rng
        )

    result = verify_bit(key_material, signature, rng, mismatch_threshold=0)

    return {
        "message_bit": message_bit,
        "mismatch_count": result.mismatch_count,
        "total_checked": result.total_checked,
        "mismatch_rate": result.mismatch_count / result.total_checked,
    }


def collect_baseline(L: int, n_trials: int, channel_noise_p: float,
                      rng: np.random.Generator) -> dict:
    """
    Runs n_trials honest protocol executions under `channel_noise_p` and
    summarizes the resulting mismatch_count / mismatch_rate distribution.
    This summary is what detection/thresholds.py calibrates a decision
    threshold from.
    """
    trials = [run_honest_trial(L, channel_noise_p, rng) for _ in range(n_trials)]
    mismatch_counts = np.array([t["mismatch_count"] for t in trials])
    mismatch_rates = np.array([t["mismatch_rate"] for t in trials])

    return {
        "trials": trials,
        "L": L,
        "n_trials": n_trials,
        "channel_noise_p": channel_noise_p,
        "mean_mismatch_count": float(mismatch_counts.mean()),
        "std_mismatch_count": float(mismatch_counts.std()),
        "max_mismatch_count": int(mismatch_counts.max()),
        "mean_mismatch_rate": float(mismatch_rates.mean()),
        "std_mismatch_rate": float(mismatch_rates.std()),
    }
