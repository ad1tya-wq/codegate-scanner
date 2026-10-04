import numpy as np
import pytest
from codegate.gate.ltt import calibrate_threshold, LTTResult


def test_perfect_separation_certifies_full_coverage():
    rng = np.random.default_rng(0)
    n = 300
    n_vuln = 60  # realistic-ish 20% vulnerable prevalence, not 50/50
    labels = np.array([0] * (n - n_vuln) + [1] * n_vuln)
    # safe (0) always scores high, vulnerable (1) always scores low: perfect separator
    scores = np.where(labels == 0, rng.uniform(0.8, 1.0, n), rng.uniform(0.0, 0.2, n))
    result = calibrate_threshold(scores, labels, alpha=0.05, delta=0.05)
    assert result.t_hat is not None
    # under perfect separation, coverage is bounded by (fraction safe) plus a thin
    # alpha-budget slice of vulnerable samples let through near the boundary —
    # with 80% safe prevalence that ceiling is comfortably above 0.75
    assert result.coverage > 0.75


def test_no_signal_gives_low_or_zero_coverage():
    rng = np.random.default_rng(1)
    n = 300
    labels = rng.integers(0, 2, n)
    scores = rng.uniform(0, 1, n)  # scores independent of label: no usable signal
    result = calibrate_threshold(scores, labels, alpha=0.05, delta=0.05)
    assert result.coverage < 0.3


def test_insufficient_vulnerable_samples_raises():
    scores = np.array([0.1, 0.2, 0.3])
    labels = np.array([0, 0, 0])  # zero vulnerable samples
    with pytest.raises(ValueError, match="vulnerable"):
        calibrate_threshold(scores, labels, alpha=0.05, delta=0.05)


def test_result_independent_of_grid_input_order():
    rng = np.random.default_rng(2)
    n = 200
    labels = np.array([0] * 100 + [1] * 100)
    scores = np.where(labels == 0, rng.uniform(0.6, 1.0, n), rng.uniform(0.0, 0.5, n))
    grid_sorted = np.unique(scores)
    grid_shuffled = grid_sorted.copy()
    rng.shuffle(grid_shuffled)
    r1 = calibrate_threshold(scores, labels, 0.05, 0.05, thresholds=grid_sorted)
    r2 = calibrate_threshold(scores, labels, 0.05, 0.05, thresholds=grid_shuffled)
    assert r1.t_hat == r2.t_hat


def test_realized_risk_respects_certificate_empirically():
    # Monte Carlo: calibrate on one draw, measure realized risk on a fresh large draw,
    # repeat many times — realized risk should exceed alpha only rarely (~<= delta rate
    # in the long run, but a single trial run just needs to usually hold; we use a
    # generous large n_test and a loose per-trial pass criterion to avoid flakiness).
    rng = np.random.default_rng(3)
    alpha, delta = 0.05, 0.05
    violations = 0
    trials = 20
    for trial in range(trials):
        n_calib = 400
        labels_c = np.array([0] * (n_calib // 2) + [1] * (n_calib // 2))
        scores_c = np.where(
            labels_c == 0, rng.beta(5, 2, n_calib), rng.beta(2, 5, n_calib)
        )
        result = calibrate_threshold(scores_c, labels_c, alpha, delta)
        if result.t_hat is None:
            continue
        n_test = 5000
        labels_t = np.array([0] * (n_test // 2) + [1] * (n_test // 2))
        scores_t = np.where(
            labels_t == 0, rng.beta(5, 2, n_test), rng.beta(2, 5, n_test)
        )
        vuln_t = scores_t[labels_t == 1]
        realized_risk = float(np.mean(vuln_t >= result.t_hat))
        if realized_risk > alpha + 0.05:  # generous slack for finite-sample noise
            violations += 1
    # certificate should hold in the large majority of trials
    assert violations <= trials * 0.25


# --- Cluster-aware certificate --------------------------------------------------
# LTT's binomial test treats every vulnerable calibration sample as an
# independent draw. Ours cluster: several models answer the same task, so
# samples from one task group are correlated and the binomial certificate is
# optimistic. Grouped calibration makes the task group the unit of evidence:
# the risk is each group's fraction of vulnerable samples auto-approved,
# averaged over groups, certified with the Hoeffding-Bentkus bound for
# bounded losses (Angelopoulos et al., "Learn then Test", 2021).
# docs/cluster-aware-certificate/README.md.

from codegate.gate.ltt import hoeffding_bentkus_p_value


def test_hb_p_value_at_zero_observed_risk_is_the_hoeffding_kl_bound():
    # KL(0 || a) = -ln(1 - a), so Hoeffding gives exactly (1 - a)^m, which is
    # below Bentkus' e * (1 - a)^m.
    assert hoeffding_bentkus_p_value(0.0, 66, 0.10) == pytest.approx(0.9 ** 66)


def test_hb_p_value_is_one_when_observed_risk_reaches_alpha():
    assert hoeffding_bentkus_p_value(0.10, 66, 0.10) == 1.0
    assert hoeffding_bentkus_p_value(0.30, 66, 0.10) == 1.0


def test_hb_p_value_grows_with_observed_risk():
    ps = [hoeffding_bentkus_p_value(r, 66, 0.10) for r in (0.0, 0.01, 0.03, 0.06, 0.09)]
    assert ps == sorted(ps)


def _grouped_data(rng, n_groups=80, size=3, rho=0.0):
    """Vulnerable samples in groups of `size` plus as many safe samples;
    scores share a per-group effect with weight rho."""
    effects = rng.standard_normal(n_groups)
    vuln = np.concatenate([np.sqrt(rho) * e + np.sqrt(1 - rho) * rng.standard_normal(size) for e in effects])
    groups = np.repeat([f"g{j}" for j in range(n_groups)], size)
    safe = rng.standard_normal(n_groups * size) + 3.0
    scores = np.concatenate([vuln, safe])
    labels = np.array([1] * len(vuln) + [0] * len(safe))
    all_groups = np.concatenate([groups, [f"s{j}" for j in range(len(safe))]])
    return scores, labels, all_groups


def test_grouped_calibration_records_its_method_and_group_count():
    scores, labels, groups = _grouped_data(np.random.default_rng(10))
    r = calibrate_threshold(scores, labels, 0.10, 0.05, groups=groups)
    assert r.method == "cluster-hb"
    assert r.n_vuln_calib == 240 and r.n_vuln_groups == 80
    assert r.t_hat is not None
    certified = [row for row in r.trace if row[3]]
    assert certified[-1][0] == r.t_hat and certified[-1][2] <= 0.05


def test_ungrouped_calibration_is_unchanged():
    scores, labels, _ = _grouped_data(np.random.default_rng(11))
    r = calibrate_threshold(scores, labels, 0.10, 0.05)
    assert r.method == "sample-binomial" and r.n_vuln_groups is None


def test_duplicating_samples_inside_a_group_buys_no_looser_threshold():
    """The flaw being fixed: copying every vulnerable sample four times in
    its own group adds no independent evidence. The binomial certificate
    is fooled into a looser threshold; the grouped one is not."""
    rng = np.random.default_rng(12)
    vuln = rng.standard_normal(70)
    safe = rng.standard_normal(70) + 3.0
    once_scores = np.concatenate([vuln, safe])
    once_labels = np.array([1] * 70 + [0] * 70)
    once_groups = np.array([f"g{j}" for j in range(70)] + [f"s{j}" for j in range(70)])
    four_scores = np.concatenate([np.repeat(vuln, 4), safe])
    four_labels = np.array([1] * 280 + [0] * 70)
    four_groups = np.array([f"g{j}" for j in range(70) for _ in range(4)] + [f"s{j}" for j in range(70)])

    grid = np.unique(once_scores)
    g1 = calibrate_threshold(once_scores, once_labels, 0.10, 0.05, thresholds=grid, groups=once_groups)
    g4 = calibrate_threshold(four_scores, four_labels, 0.10, 0.05, thresholds=grid, groups=four_groups)
    assert g1.t_hat == g4.t_hat

    b1 = calibrate_threshold(once_scores, once_labels, 0.10, 0.05, thresholds=grid)
    b4 = calibrate_threshold(four_scores, four_labels, 0.10, 0.05, thresholds=grid)
    assert b4.t_hat < b1.t_hat   # the binomial certificate takes the bait


def test_groups_must_align_with_scores():
    with pytest.raises(ValueError, match="groups"):
        calibrate_threshold(np.array([0.1, 0.9]), np.array([1, 0]), 0.1, 0.05, groups=np.array(["a"]))


def test_grouped_certificate_keeps_its_promise_under_strong_correlation():
    """Seeded simulation. Scores are standard normal marginally, so the true
    miss rate at t is 1 - Phi(t). With within-group correlation 0.9 the
    binomial certificate certifies a threshold whose true miss rate exceeds
    alpha more often than delta allows; the grouped one does not."""
    from scipy.stats import norm
    rng = np.random.default_rng(20261004)
    alpha, delta, reps = 0.10, 0.05, 150
    violations = {"grouped": 0, "binomial": 0}
    for _ in range(reps):
        scores, labels, groups = _grouped_data(rng, n_groups=66, size=3, rho=0.9)
        for name, g in (("grouped", groups), ("binomial", None)):
            r = calibrate_threshold(scores, labels, alpha, delta, groups=g)
            if r.t_hat is not None and 1 - norm.cdf(r.t_hat) > alpha:
                violations[name] += 1
    assert violations["grouped"] / reps <= delta
    assert violations["binomial"] / reps > delta
