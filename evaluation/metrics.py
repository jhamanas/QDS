"""Statistical reporting helpers for acceptance and attack experiments."""
from __future__ import annotations

import math


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    """Return a Wilson score interval for a Bernoulli rate."""
    if trials < 1 or successes < 0 or successes > trials or not 0 < confidence < 1:
        raise ValueError("successes/trials/confidence are out of range")
    # z values needed by the dashboard/report defaults without scipy.
    z = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}.get(confidence)
    if z is None:
        # Inverse normal CDF approximation (Peter John Acklam, compact form).
        p = 1 - (1 - confidence) / 2
        a = [2.50662823884, -18.61500062529, 41.39119773534, -25.44106049637]
        b = [-8.47351093090, 23.08336743743, -21.06224101826, 3.13082909833]
        q = p - 0.5
        if abs(q) <= 0.42:
            r = q * q
            z = q * (((a[3] * r + a[2]) * r + a[1]) * r + a[0]) / ((((b[3] * r + b[2]) * r + b[1]) * r + b[0]) * r + 1)
        else:
            r = p if q < 0 else 1 - p
            z = math.log(-math.log(r))
            z = (2.3212127685 + z * (0.9742308161 + z * 0.001228024642)) / (1 + z * (0.999 + z * 0.001))
            if q < 0:
                z = -z
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rate_summary(successes: int, trials: int, confidence: float = 0.95) -> dict[str, float]:
    low, high = wilson_interval(successes, trials, confidence)
    return {"successes": successes, "trials": trials, "rate": successes / trials,
            "ci_low": low, "ci_high": high, "confidence": confidence}
