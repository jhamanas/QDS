"""
evaluation/performance_benchmark.py

Phase 8: Performance Benchmarking -- runtime/complexity scaling.

Purpose
-------
Every phase so far has measured CORRECTNESS and SECURITY properties.
None has measured whether the implementation is actually practical to
run at the L values Phase 7 recommends (L ~ 80-120 for realistic
forgery-resistance targets, per evaluation/security_analysis.py). This
module benchmarks wall-clock runtime of the protocol's core operations
and the detection pipeline across a range of L, and fits a simple
linear model to confirm the expected complexity class.

Expected scaling
-----------------
Every per-qubit operation in this codebase (state prep, a 3-qubit
teleportation circuit, a single-qubit measurement) is CONSTANT-SIZE
work, independent of L -- core/teleportation.py always builds an 8-
dimensional (2^3) statevector regardless of how many key qubits exist
overall. generate_key_material, distribute_public_key, sign_bit, and
verify_bit all loop over L independent qubits doing this fixed-size
work each time. So wall-clock time for each of these should scale
LINEARLY in L: time(L) ~= a * L + b. This module fits exactly that
model and reports the fit quality (R^2) as a sanity check that nothing
accidentally became quadratic (e.g. an accidental O(L^2) list
operation) as the codebase grew across Phases 0-7.

detection.baseline.collect_baseline additionally multiplies by
n_trials (each trial itself does one full key generation + distribution
+ signing + verification cycle), so its time scales as
O(L * n_trials) -- linear in L at fixed n_trials, which this module
also confirms.
"""

from __future__ import annotations
from dataclasses import dataclass
import time
import csv
import tracemalloc
import numpy as np

from core.qds_protocol import generate_key_material, distribute_public_key, sign_bit, verify_bit
from detection.baseline import collect_baseline
from detection.thresholds import calibrate_threshold


@dataclass
class ProtocolTiming:
    L: int
    key_gen_seconds: float
    distribution_seconds: float
    sign_seconds: float
    verify_seconds: float
    total_seconds: float
    peak_memory_bytes: int = 0
    measurement_count: int = 0


def benchmark_qds_protocol(L_values: tuple[int, ...], rng: np.random.Generator,
                            n_repeats: int = 3) -> list[ProtocolTiming]:
    """
    Times each core protocol stage separately (key generation,
    distribution/teleportation, signing, verification) at each L in
    L_values, averaged over n_repeats independent runs to smooth out
    system-level timing noise. Distribution (teleportation) is expected
    to dominate total time, since it is the only stage doing real
    linear-algebra work (state tensor products and gate application)
    rather than simple bookkeeping.
    """
    results = []
    for L in L_values:
        key_gen_times, dist_times, sign_times, verify_times = [], [], [], []
        peak_memory = 0
        for _ in range(n_repeats):
            tracemalloc.start()
            t0 = time.perf_counter()
            km = generate_key_material(L, rng)
            t1 = time.perf_counter()
            distribute_public_key(km, rng)
            t2 = time.perf_counter()
            sig = sign_bit(km, message_bit=0)
            t3 = time.perf_counter()
            verify_bit(km, sig, rng, mismatch_threshold=0)
            t4 = time.perf_counter()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            key_gen_times.append(t1 - t0)
            dist_times.append(t2 - t1)
            sign_times.append(t3 - t2)
            verify_times.append(t4 - t3)
            peak_memory = max(peak_memory, peak)

        key_gen = float(np.mean(key_gen_times))
        dist = float(np.mean(dist_times))
        sign = float(np.mean(sign_times))
        verify = float(np.mean(verify_times))
        results.append(ProtocolTiming(
            L=L, key_gen_seconds=key_gen, distribution_seconds=dist,
            sign_seconds=sign, verify_seconds=verify,
            total_seconds=key_gen + dist + sign + verify,
            peak_memory_bytes=int(peak_memory), measurement_count=L,
        ))
    return results


@dataclass
class DetectionPipelineTiming:
    L: int
    n_trials: int
    baseline_collection_seconds: float
    calibration_seconds: float


def benchmark_detection_pipeline(L_values: tuple[int, ...], channel_noise_p: float,
                                  rng: np.random.Generator,
                                  n_baseline_trials: int = 30) -> list[DetectionPipelineTiming]:
    """
    Times detection.baseline.collect_baseline (which itself runs
    n_baseline_trials full honest protocol cycles) and
    detection.thresholds.calibrate_threshold at each L. Calibration
    itself evaluates exact binomial tails over the possible mismatch counts,
    so it is small at the demonstration sizes used here but is not assumed
    to be constant-time. It is included mainly as a contrast to baseline
    collection's expected linear growth.
    """
    results = []
    for L in L_values:
        t0 = time.perf_counter()
        baseline = collect_baseline(L=L, n_trials=n_baseline_trials,
                                     channel_noise_p=channel_noise_p, rng=rng)
        t1 = time.perf_counter()
        calibrate_threshold(baseline)
        t2 = time.perf_counter()

        results.append(DetectionPipelineTiming(
            L=L, n_trials=n_baseline_trials,
            baseline_collection_seconds=t1 - t0,
            calibration_seconds=t2 - t1,
        ))
    return results


@dataclass
class ScalingFit:
    slope: float
    intercept: float
    r_squared: float


def fit_linear_scaling(L_values: tuple[int, ...], times: tuple[float, ...]) -> ScalingFit:
    """
    Fits time(L) ~= slope * L + intercept via ordinary least squares
    (numpy.polyfit, degree 1), and reports R^2 as a goodness-of-fit
    check. A high R^2 (close to 1.0) confirms the measured runtime is
    well-explained by a linear model in L -- i.e. no hidden superlinear
    behavior. A poor fit would be a signal to investigate for an
    accidental O(L^2) operation somewhere in the pipeline.
    """
    L_arr = np.array(L_values, dtype=float)
    t_arr = np.array(times, dtype=float)
    slope, intercept = np.polyfit(L_arr, t_arr, deg=1)

    predicted = slope * L_arr + intercept
    ss_res = float(np.sum((t_arr - predicted) ** 2))
    ss_tot = float(np.sum((t_arr - np.mean(t_arr)) ** 2))
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 1.0

    return ScalingFit(slope=float(slope), intercept=float(intercept), r_squared=r_squared)


def write_benchmark_csv(protocol_timings: list[ProtocolTiming],
                         detection_timings: list[DetectionPipelineTiming],
                         path: str) -> None:
    """
    Writes a single combined CSV of both benchmark results, one row per
    (L, stage) pair, to `path`. Column layout is intentionally flat
    (stage name + seconds) rather than one column per stage, so the
    file stays easy to load and plot with any spreadsheet or plotting
    tool without needing to know this module's dataclass shapes.
    """
    detection_by_L = {dt.L: dt for dt in detection_timings}

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["L", "stage", "seconds"])
        for pt in protocol_timings:
            writer.writerow([pt.L, "key_generation", f"{pt.key_gen_seconds:.6f}"])
            writer.writerow([pt.L, "distribution_teleportation", f"{pt.distribution_seconds:.6f}"])
            writer.writerow([pt.L, "signing", f"{pt.sign_seconds:.6f}"])
            writer.writerow([pt.L, "verification", f"{pt.verify_seconds:.6f}"])
            writer.writerow([pt.L, "protocol_total", f"{pt.total_seconds:.6f}"])
            dt = detection_by_L.get(pt.L)
            if dt is not None:
                writer.writerow([pt.L, f"baseline_collection_n{dt.n_trials}",
                                  f"{dt.baseline_collection_seconds:.6f}"])
                writer.writerow([pt.L, "threshold_calibration", f"{dt.calibration_seconds:.6f}"])
