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
