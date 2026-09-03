from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.metrics import wilson_interval, rate_summary
from evaluation.acceptance_matrix import evaluate_honest_acceptance


def run():
    low, high = wilson_interval(10, 10)
    assert 0.7 < low < 1 and high > 0.99
    summary = rate_summary(0, 10)
    assert summary["rate"] == 0 and summary["ci_high"] > 0
    result = evaluate_honest_acceptance(length=4, trials=5)
    assert result["acceptance"]["rate"] == 1


if __name__ == "__main__":
    run()
    print("METRICS TESTS PASSED")
