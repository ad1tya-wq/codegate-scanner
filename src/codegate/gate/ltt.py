from __future__ import annotations
from dataclasses import dataclass, field
import numpy as np
from scipy.stats import binom


@dataclass(frozen=True)
class LTTResult:
    t_hat: float | None      # None means no threshold could be certified: escalate everything
    alpha: float
    delta: float
    n_vuln_calib: int
    coverage: float          # fraction of ALL calibration samples auto-approved at t_hat
    trace: list[tuple[float, int, float, bool]] = field(default_factory=list)
    # trace entries: (threshold, k_vuln_auto_approved, p_value, certified)


def calibrate_threshold(
    scores: np.ndarray,
    labels: np.ndarray,
    alpha: float,
    delta: float,
    thresholds: np.ndarray | None = None,
) -> LTTResult:
    """
    Learn-Then-Test via fixed-sequence testing on the monotone risk
    R(t) = P(score >= t | label == 1)  ["auto-approved given vulnerable"].

    Auto-approval rule downstream is `score >= t_hat`. Higher score = safer.

    Certifies: P(R(t_hat) <= alpha) >= 1 - delta, under calibration/deployment
    exchangeability (see spec, threat-model section).
    """
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    if scores.shape != labels.shape:
        raise ValueError("scores and labels must be the same shape")

    vuln_scores = scores[labels == 1]
    n = len(vuln_scores)
    if n == 0:
        raise ValueError("calibrate_threshold requires at least one vulnerable calibration sample")

    if thresholds is None:
        thresholds = np.unique(scores)

    # Grid ordered from most conservative (largest t, smallest auto-approve region,
    # trivially low risk) to least conservative (smallest t, largest auto-approve
    # region, highest risk). We also prepend +inf as the trivial always-valid
    # zero-coverage starting point so t_hat is never None purely due to grid gaps.
    grid = np.sort(np.unique(np.asarray(thresholds, dtype=float)))[::-1]
    grid = np.concatenate([[np.inf], grid])

    t_hat: float | None = None
    trace: list[tuple[float, int, float, bool]] = []

    for t in grid:
        k = int(np.sum(vuln_scores >= t))
        # p-value for H0: true risk R(t) >= alpha. Small p-value => reject H0 =>
        # certify R(t) <= alpha. p = P(Binomial(n, alpha) <= k).
        p = float(binom.cdf(k, n, alpha))
        certified = p <= delta
        trace.append((float(t), k, p, certified))
        if certified:
            t_hat = float(t)
        else:
            break  # fixed-sequence testing: stop at first failure, monotonicity
                    # guarantees every less-conservative t also fails

    coverage = 0.0 if t_hat is None else float(np.mean(scores >= t_hat))
    return LTTResult(
        t_hat=t_hat, alpha=alpha, delta=delta, n_vuln_calib=n, coverage=coverage, trace=trace
    )
