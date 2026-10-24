import random

import numpy as np

SEED = 7


def shuffled(xs: list) -> list:
    rng = random.Random(SEED)
    out = list(xs)
    rng.shuffle(out)
    return out


def noise(n: int) -> np.ndarray:
    return np.random.default_rng(SEED).normal(size=n)
