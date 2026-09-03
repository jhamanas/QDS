"""Deterministically regenerate presentation evaluation outputs.

Run with ``python -m evaluation.regenerate_results`` from the repository root.
The script deliberately records provenance instead of relying on README claims
about results produced by an unspecified checkout or machine.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from evaluation.performance_benchmark import (
    benchmark_detection_pipeline,
    benchmark_qds_protocol,
    write_benchmark_csv,
)
from evaluation.security_analysis import generate_security_report
from evaluation.validate_detection import (
    attack_detectability_summary,
    sweep_intercept_resend_detection,
)


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
SEED = 20_260_903
LENGTH = 64
CHANNEL_NOISE = 0.03
CALIBRATION_TRIALS = 200
ATTACK_TRIALS = 100


def _commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _worktree_dirty() -> bool | None:
    try:
        return bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip())
    except (OSError, subprocess.CalledProcessError):
        return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    rng = np.random.default_rng(SEED)
    sweep = sweep_intercept_resend_detection(
        L=LENGTH,
        channel_noise_p=CHANNEL_NOISE,
        intercept_probs=(0.05, 0.1, 0.25, 0.5, 0.75, 1.0),
        rng=rng,
        n_calibration_trials=CALIBRATION_TRIALS,
        n_attack_trials=ATTACK_TRIALS,
    )
    detection = {
        "config": {
            "L": LENGTH,
            "channel_noise_p": CHANNEL_NOISE,
            "per_qubit_mismatch_probability": 2 * CHANNEL_NOISE / 3,
            "seed": SEED,
            "n_calibration_trials": CALIBRATION_TRIALS,
            "n_attack_trials": ATTACK_TRIALS,
            "methodology": "Independent Pauli channel noise is applied to both honest calibration and attack trials.",
        },
        "intercept_resend_sweep": [dataclasses.asdict(point) for point in sweep],
        "attack_detectability_summary": attack_detectability_summary(
            L=LENGTH,
            channel_noise_p=CHANNEL_NOISE,
            rng=rng,
            n_calibration_trials=CALIBRATION_TRIALS,
            n_trials_per_attack=80,
        ),
    }
    detection_path = RESULTS / "detection_results.json"
    detection_path.write_text(json.dumps(detection, indent=2) + "\n", encoding="utf-8")

    report = generate_security_report(
        L=LENGTH,
        channel_noise_p=CHANNEL_NOISE,
        rng=rng,
        n_calibration_trials=CALIBRATION_TRIALS,
        n_holdout_trials=150,
        n_attack_trials=ATTACK_TRIALS,
    )
    security_path = RESULTS / "security_analysis.json"
    security_path.write_text(json.dumps(dataclasses.asdict(report), indent=2) + "\n", encoding="utf-8")

    benchmark_rng = np.random.default_rng(SEED)
    timings = benchmark_qds_protocol((10, 20, 40, 80, 160), benchmark_rng, n_repeats=3)
    pipeline = benchmark_detection_pipeline((10, 20, 40, 80, 160), CHANNEL_NOISE, benchmark_rng, n_baseline_trials=30)
    benchmark_path = RESULTS / "performance_benchmark.csv"
    write_benchmark_csv(timings, pipeline, str(benchmark_path))

    provenance = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _commit(),
        "git_worktree_dirty": _worktree_dirty(),
        "python_version": sys.version,
        "numpy_version": np.__version__,
        "operating_system": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "seed": SEED,
        "artifacts": {
            path.name: {"sha256": _sha256(path)}
            for path in (detection_path, security_path, benchmark_path)
        },
    }
    (RESULTS / "reproducibility.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )
    print("Regenerated results with seed", SEED)


if __name__ == "__main__":
    main()
