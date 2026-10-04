from __future__ import annotations
from dataclasses import dataclass, field
import math
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
    method: str = "sample-binomial"      # or "cluster-hb" (see calibrate_threshold)
    n_vuln_groups: int | None = None     # groups holding a vulnerable sample, when grouped


def hoeffding_bentkus_p_value(risk_hat: float, n: int, alpha: float) -> float:
    """
    p-value for H0: "the true mean loss is at least alpha", given the mean
    `risk_hat` of n independent losses bounded in [0, 1]. The minimum of the
    Hoeffding bound (in its KL form) and Bentkus' bound,
    e * P(Binomial(n, alpha) <= ceil(n * risk_hat)) -- the p-value Learn then
    Test uses for bounded, non-binary losses (Angelopoulos et al., 2021).
    """
    if risk_hat >= alpha:
        return 1.0
    r = max(risk_hat, 0.0)
    if r == 0.0:
        hoeffding = (1.0 - alpha) ** n          # exp(-n * KL(0 || alpha))
    else:
        kl = r * math.log(r / alpha) + (1 - r) * math.log((1 - r) / (1 - alpha))
        hoeffding = math.exp(-n * kl)
    bentkus = math.e * float(binom.cdf(math.ceil(n * r - 1e-9), n, alpha))
    return min(hoeffding, bentkus, 1.0)


def calibrate_threshold(
    scores: np.ndarray,
    labels: np.ndarray,
    alpha: float,
    delta: float,
    thresholds: np.ndarray | None = None,
    groups: np.ndarray | None = None,
) -> LTTResult:
    """
    Learn-Then-Test via fixed-sequence testing on the monotone risk
    R(t) = P(score >= t | label == 1)  ["auto-approved given vulnerable"].

    Auto-approval rule downstream is `score >= t_hat`. Higher score = safer.

    Certifies: P(R(t_hat) <= alpha) >= 1 - delta, under calibration/deployment
    exchangeability (see spec, threat-model section).

    Without `groups`, each vulnerable calibration sample is one independent
    Bernoulli draw, tested with the exact binomial tail.

    With `groups` (one label per sample, e.g. its task group), the group is
    the unit of evidence instead. A group's loss is the fraction of its
    vulnerable samples scoring >= t, the risk is the mean of that loss over
    the groups holding a vulnerable sample, and each threshold is tested
    with the Hoeffding-Bentkus p-value. That assumes only that *groups* are
    exchangeable; samples inside a group may be arbitrarily correlated, as
    several models answering the same task are. Under such correlation the
    binomial test is optimistic: copying evidence within a group buys it a
    looser threshold, and in simulation it certified thresholds that really
    missed more than alpha far more often than delta allows.
    docs/cluster-aware-certificate/README.md.
    """
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    if scores.shape != labels.shape:
        raise ValueError("scores and labels must be the same shape")
    if groups is not None:
        groups = np.asarray(groups)
        if groups.shape != scores.shape:
            raise ValueError("groups must give one group label per score")

    vuln_scores = scores[labels == 1]
    n = len(vuln_scores)
    if n == 0:
        raise ValueError("calibrate_threshold requires at least one vulnerable calibration sample")

    n_groups: int | None = None
    if groups is not None:
        _, group_index = np.unique(groups[labels == 1], return_inverse=True)
        n_groups = int(group_index.max()) + 1
        group_sizes = np.bincount(group_index, minlength=n_groups)

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
        approved = vuln_scores >= t
        k = int(np.sum(approved))
        if n_groups is None:
            # p-value for H0: true risk R(t) >= alpha. Small p-value => reject H0 =>
            # certify R(t) <= alpha. p = P(Binomial(n, alpha) <= k).
            p = float(binom.cdf(k, n, alpha))
        else:
            k_by_group = np.bincount(group_index, weights=approved, minlength=n_groups)
            p = hoeffding_bentkus_p_value(float(np.mean(k_by_group / group_sizes)), n_groups, alpha)
        certified = p <= delta
        trace.append((float(t), k, p, certified))
        if certified:
            t_hat = float(t)
        else:
            break  # fixed-sequence testing: stop at first failure, monotonicity
                    # guarantees every less-conservative t also fails

    coverage = 0.0 if t_hat is None else float(np.mean(scores >= t_hat))
    return LTTResult(
        t_hat=t_hat, alpha=alpha, delta=delta, n_vuln_calib=n, coverage=coverage, trace=trace,
        method="sample-binomial" if n_groups is None else "cluster-hb",
        n_vuln_groups=n_groups,
    )
