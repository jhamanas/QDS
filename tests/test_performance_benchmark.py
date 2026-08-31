"""
tests/test_performance_benchmark.py

Phase 8 validation. Run after tests/test_security_analysis.py passes.
If anything here fails, do not trust results/performance_benchmark.csv
or docs/architecture.md's performance claims -- fix
evaluation/performance_benchmark.py first.
"""

import numpy as np
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.performance_benchmark import (
    benchmark_qds_protocol, benchmark_detection_pipeline, fit_linear_scaling,
    write_benchmark_csv, ProtocolTiming, DetectionPipelineTiming,
)

rng = np.random.default_rng(8888)
failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        failures.append(name)


L_VALUES = (10, 20, 40, 80, 160)

# ---------------------------------------------------------------------------
# 1. benchmark_qds_protocol: well-formed results, one per L, all
#    non-negative and total = sum of stages.
# ---------------------------------------------------------------------------
protocol_timings = benchmark_qds_protocol(L_VALUES, rng, n_repeats=5)

check("benchmark_qds_protocol returns a list of ProtocolTiming instances",
      all(isinstance(pt, ProtocolTiming) for pt in protocol_timings))

check(f"benchmarked all {len(L_VALUES)} L values",
      len(protocol_timings) == len(L_VALUES))
check("timings are recorded in the order L_VALUES was given",
      [pt.L for pt in protocol_timings] == list(L_VALUES))
check("all timing fields are non-negative",
      all(pt.key_gen_seconds >= 0 and pt.distribution_seconds >= 0
          and pt.sign_seconds >= 0 and pt.verify_seconds >= 0
          for pt in protocol_timings))
check("total_seconds equals the sum of its four stages",
      all(np.isclose(pt.total_seconds,
                      pt.key_gen_seconds + pt.distribution_seconds
                      + pt.sign_seconds + pt.verify_seconds)
          for pt in protocol_timings))

# ---------------------------------------------------------------------------
# 2. Distribution (teleportation) should dominate total time -- it's the
#    only stage doing real linear-algebra work rather than bookkeeping.
# ---------------------------------------------------------------------------
largest = protocol_timings[-1]  # L=160, most stable measurement
check(f"distribution time dominates total time at L={largest.L} "
      f"(distribution={largest.distribution_seconds:.4f}s, "
      f"total={largest.total_seconds:.4f}s)",
      largest.distribution_seconds > 0.5 * largest.total_seconds)

# ---------------------------------------------------------------------------
# 3. Total protocol time should grow with L (monotonically, allowing
#    for a LITTLE timing noise at the smallest L values).
# ---------------------------------------------------------------------------
totals = [pt.total_seconds for pt in protocol_timings]
check(f"total protocol time increases from smallest to largest L "
      f"(L={L_VALUES[0]}: {totals[0]:.4f}s -> L={L_VALUES[-1]}: {totals[-1]:.4f}s)",
      totals[-1] > totals[0])

# ---------------------------------------------------------------------------
# 4. Linear scaling fit: total time vs. L should be well-explained by a
#    straight line (per-qubit work is constant-size, so overall time is
#    O(L)) -- a poor fit would flag an accidental superlinear regression.
# ---------------------------------------------------------------------------
fit = fit_linear_scaling(L_VALUES, tuple(totals))
check(f"linear fit slope is positive (time grows with L) (got {fit.slope:.6f})",
      fit.slope > 0)
check(f"linear fit R^2 indicates good linear explanation (got {fit.r_squared:.4f})",
      fit.r_squared > 0.9)

# ---------------------------------------------------------------------------
# 5. benchmark_detection_pipeline: well-formed, and baseline collection
#    time also grows with L (it runs n_trials full protocol cycles).
# ---------------------------------------------------------------------------
N_BASELINE_TRIALS = 20
detection_timings = benchmark_detection_pipeline(
    L_VALUES, channel_noise_p=0.03, rng=rng, n_baseline_trials=N_BASELINE_TRIALS
)

check(f"benchmarked detection pipeline at all {len(L_VALUES)} L values",
      len(detection_timings) == len(L_VALUES))
check("benchmark_detection_pipeline returns a list of DetectionPipelineTiming instances",
      all(isinstance(dt, DetectionPipelineTiming) for dt in detection_timings))
check("all detection timings are non-negative",
      all(dt.baseline_collection_seconds >= 0 and dt.calibration_seconds >= 0
          for dt in detection_timings))
check("every detection timing recorded the requested n_trials",
      all(dt.n_trials == N_BASELINE_TRIALS for dt in detection_timings))

baseline_times = [dt.baseline_collection_seconds for dt in detection_timings]
check(f"baseline collection time increases from smallest to largest L "
      f"(L={L_VALUES[0]}: {baseline_times[0]:.4f}s -> L={L_VALUES[-1]}: {baseline_times[-1]:.4f}s)",
      baseline_times[-1] > baseline_times[0])

detection_fit = fit_linear_scaling(L_VALUES, tuple(baseline_times))
check(f"baseline collection time also scales roughly linearly in L "
      f"(got slope={detection_fit.slope:.6f}, R^2={detection_fit.r_squared:.4f})",
      detection_fit.r_squared > 0.85)

# Calibration itself is O(1) arithmetic on summary stats -- should stay
# small and NOT scale up anywhere near as steeply as baseline collection.
calib_times = [dt.calibration_seconds for dt in detection_timings]
check(f"threshold calibration stays fast even at the largest L "
      f"(got {calib_times[-1]:.6f}s at L={L_VALUES[-1]}, expect well under 0.01s)",
      calib_times[-1] < 0.01)

# ---------------------------------------------------------------------------
# 6. write_benchmark_csv: produces a readable, well-formed CSV file.
# ---------------------------------------------------------------------------
import tempfile
import csv as csv_module

with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
    tmp_path = tmp.name

write_benchmark_csv(protocol_timings, detection_timings, tmp_path)

with open(tmp_path) as f:
    reader = csv_module.reader(f)
    rows = list(reader)

check("CSV has a header row plus at least 5 rows per L (5 stages)",
      len(rows) - 1 >= 5 * len(L_VALUES))
check("CSV header matches expected columns",
      rows[0] == ["L", "stage", "seconds"])

os.unlink(tmp_path)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{len(failures)} FAILURE(S): {failures}")
    sys.exit(1)
else:
    print("ALL PHASE 8 TESTS PASSED")
