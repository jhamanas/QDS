from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
from core.noise import apply_noise


def run():
    state = np.array([1, 0], dtype=complex)
    rng = np.random.default_rng(1)
    assert np.allclose(apply_noise(state, 0, 0, 1, rng, "bit-flip"), state)
    try:
        apply_noise(state, .1, 0, 1, rng, "unknown")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown noise model was accepted")


if __name__ == "__main__":
    run()
    print("NOISE MODEL TESTS PASSED")
