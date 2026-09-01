import numpy as np
from codegate.gate.risk import empirical_risk, clopper_pearson_ci


def test_empirical_risk_all_vulnerable_below_threshold_is_zero():
    scores = np.array([0.1, 0.2, 0.3, 0.9])
    labels = np.array([1, 1, 1, 0])
    assert empirical_risk(scores, labels, t=0.5) == 0.0


def test_empirical_risk_all_vulnerable_above_threshold_is_one():
    scores = np.array([0.6, 0.7, 0.8, 0.1])
    labels = np.array([1, 1, 1, 0])
    assert empirical_risk(scores, labels, t=0.5) == 1.0


def test_empirical_risk_no_vulnerable_samples_is_nan():
    scores = np.array([0.1, 0.9])
    labels = np.array([0, 0])
    assert np.isnan(empirical_risk(scores, labels, t=0.5))


def test_clopper_pearson_ci_widens_with_fewer_samples():
    lo_small, hi_small = clopper_pearson_ci(k=1, n=20)
    lo_large, hi_large = clopper_pearson_ci(k=10, n=200)
    assert (hi_small - lo_small) > (hi_large - lo_large)


def test_clopper_pearson_ci_bounds_are_valid_probabilities():
    lo, hi = clopper_pearson_ci(k=0, n=10)
    assert lo == 0.0
    assert 0.0 <= hi <= 1.0
    lo, hi = clopper_pearson_ci(k=10, n=10)
    assert hi == 1.0
    assert 0.0 <= lo <= 1.0
