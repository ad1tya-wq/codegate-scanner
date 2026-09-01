from __future__ import annotations
import numpy as np
from scipy.stats import beta


def empirical_risk(scores: np.ndarray, labels: np.ndarray, t: float) -> float:
    """R_hat(t) = fraction of vulnerable samples with score >= t (auto-approved)."""
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    vuln = scores[labels == 1]
    if len(vuln) == 0:
        return float("nan")
    return float(np.mean(vuln >= t))


def clopper_pearson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Exact binomial confidence interval for k successes out of n trials."""
    if n == 0:
        return (0.0, 1.0)
    alpha_ci = 1 - confidence
    lo = 0.0 if k == 0 else float(beta.ppf(alpha_ci / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha_ci / 2, k + 1, n - k))
    return lo, hi
