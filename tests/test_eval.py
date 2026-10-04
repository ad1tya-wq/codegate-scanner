import numpy as np
import pandas as pd
from codegate.research.eval.frontier import compute_frontier
from codegate.research.eval.shift import run_shift_experiment, ShiftResult


def _separable(n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    labels = np.array([0] * (n // 2) + [1] * (n // 2))
    scores = np.where(labels == 0, rng.beta(6, 2, n), rng.beta(2, 6, n))
    return scores, labels


def test_compute_frontier_returns_one_row_per_alpha():
    scores, labels = _separable(400, seed=0)
    df = compute_frontier(scores, labels, alphas=[0.01, 0.05, 0.1, 0.2], delta=0.05)
    assert len(df) == 4
    assert set(df["alpha"]) == {0.01, 0.05, 0.1, 0.2}


def test_compute_frontier_coverage_increases_with_alpha():
    scores, labels = _separable(400, seed=1)
    df = compute_frontier(scores, labels, alphas=[0.01, 0.05, 0.2], delta=0.05).sort_values("alpha")
    coverages = df["coverage"].to_list()
    # looser certified miss-rate budget should never certify LESS coverage
    assert coverages == sorted(coverages)


def test_run_shift_experiment_certificate_holds_on_matched_distribution():
    rng = np.random.default_rng(2)
    scores_by_gen, labels_by_gen = {}, {}
    for gen in ["a", "b", "c", "d"]:
        n = 300
        labels = np.array([0] * (n // 2) + [1] * (n // 2))
        scores = np.where(labels == 0, rng.beta(6, 2, n), rng.beta(2, 6, n))
        scores_by_gen[gen], labels_by_gen[gen] = scores, labels

    result = run_shift_experiment(scores_by_gen, labels_by_gen, held_out="d", alpha=0.05, delta=0.05)
    assert isinstance(result, ShiftResult)
    assert result.held_out_generator == "d"
    # same distribution for every generator -> certificate should typically hold
    assert result.certificate_held or result.realized_risk_on_held_out <= 0.15


def test_run_shift_experiment_detects_certificate_break_under_severe_shift():
    rng = np.random.default_rng(3)
    scores_by_gen, labels_by_gen = {}, {}
    for gen in ["a", "b", "c"]:
        n = 300
        labels = np.array([0] * (n // 2) + [1] * (n // 2))
        scores = np.where(labels == 0, rng.beta(8, 2, n), rng.beta(2, 8, n))  # easy, well-separated
        scores_by_gen[gen], labels_by_gen[gen] = scores, labels
    # held-out generator "d" has an inverted, badly-separated distribution:
    # vulnerable code scores HIGH (looks safe) -> should break the certificate
    n = 300
    labels_d = np.array([0] * (n // 2) + [1] * (n // 2))
    scores_d = np.where(labels_d == 0, rng.beta(2, 8, n), rng.beta(8, 2, n))
    scores_by_gen["d"], labels_by_gen["d"] = scores_d, labels_d

    result = run_shift_experiment(scores_by_gen, labels_by_gen, held_out="d", alpha=0.05, delta=0.05)
    assert result.certificate_held is False
    assert result.realized_risk_on_held_out > 0.05


def test_compute_frontier_records_the_grouped_method_when_given_groups():
    scores, labels = _separable(400, seed=4)
    groups = np.array([f"g{i // 2}" for i in range(400)])   # pairs share a group
    df = compute_frontier(scores, labels, alphas=[0.1, 0.2], delta=0.05, groups=groups)
    assert list(df["n_vuln_groups"]) == [100, 100]


def test_shift_experiment_calibrates_with_groups_and_judges_separate_held_out_data():
    rng = np.random.default_rng(5)
    scores_by_gen, labels_by_gen, groups_by_gen = {}, {}, {}
    for gen in ["a", "b", "c", "d"]:
        n = 300
        labels = np.array([0] * (n // 2) + [1] * (n // 2))
        scores_by_gen[gen] = np.where(labels == 0, rng.beta(6, 2, n), rng.beta(2, 6, n))
        labels_by_gen[gen] = labels
        groups_by_gen[gen] = np.array([f"task{i % 150}" for i in range(n)])  # shared across generators
    # The held-out generator is judged on data passed separately (in the
    # pipeline: its samples the ranker never trained on), here rigged so
    # every vulnerable sample would be approved.
    held_scores = np.array([0.99, 0.99, 0.01])
    held_labels = np.array([1, 1, 0])
    r = run_shift_experiment(scores_by_gen, labels_by_gen, held_out="d", alpha=0.10, delta=0.05,
                             groups_by_generator=groups_by_gen,
                             held_out_scores=held_scores, held_out_labels=held_labels)
    assert r.realized_risk_on_held_out == 1.0 and r.certificate_held is False
