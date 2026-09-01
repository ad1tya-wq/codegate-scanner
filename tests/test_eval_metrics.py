from pathlib import Path

import pandas as pd
import pytest

from codegate.research.eval.metrics import (
    corpus_label_distribution,
    oracle_accuracy_on_fixtures,
    ranker_score_frame,
    ranker_separation_metrics,
    scan_ground_truth_eval,
)
from codegate.research.pipeline import LABEL_ABSTAIN
from codegate.scan.findings import Finding
from codegate.scan.pipeline import ScanResult

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures"


def test_oracle_accuracy_on_fixtures_matches_ground_truth_for_every_fixture():
    # Real, unchanging ground truth (filename encodes the answer) --
    # tests/test_oracles.py already asserts each oracle individually gets
    # these right, so this should always be 6/6. If it isn't, an oracle
    # regressed and this eval-report metric is exactly what should catch it.
    df = oracle_accuracy_on_fixtures(FIXTURES_DIR)
    assert len(df) == 6
    assert df["oracle_correct"].all(), df[~df["oracle_correct"]]


def test_oracle_accuracy_on_fixtures_has_one_row_per_cwe_pair():
    df = oracle_accuracy_on_fixtures(FIXTURES_DIR)
    assert set(df["cwe"]) == {"CWE-89", "CWE-78", "CWE-798"}
    assert (df.groupby("cwe").size() == 2).all()


def test_corpus_label_distribution_counts_by_cwe_and_outcome():
    labeled_df = pd.DataFrame({
        "sample_id": ["s1", "s2", "s3", "s4"],
        "cwe": ["CWE-89", "CWE-89", "CWE-89", "CWE-78"],
        "label": [1, 0, LABEL_ABSTAIN, 0],
    })
    dist = corpus_label_distribution(labeled_df)
    lookup = {(r.cwe, r.outcome): r.count for r in dist.itertuples()}
    assert lookup[("CWE-89", "vulnerable")] == 1
    assert lookup[("CWE-89", "safe")] == 1
    assert lookup[("CWE-89", "abstained")] == 1
    assert lookup[("CWE-78", "safe")] == 1


def test_ranker_score_frame_drops_abstentions_and_joins_on_sample_id():
    labeled_df = pd.DataFrame({
        "sample_id": ["s1", "s2", "s3"],
        "cwe": ["CWE-89", "CWE-89", "CWE-89"],
        "label": [1, 0, LABEL_ABSTAIN],
    })
    scores_df = pd.DataFrame({
        "sample_id": ["s1", "s2", "s3"],
        "ranker_id": ["R2", "R2", "R2"],
        "score": [0.2, 0.9, 0.5],
    })
    frame = ranker_score_frame(labeled_df, scores_df)
    assert len(frame) == 2  # s3 (abstained) dropped
    assert set(frame["sample_id"]) == {"s1", "s2"}


def test_ranker_separation_metrics_gives_high_auc_for_well_separated_scores():
    # Higher score == safer (label 0); a perfectly separating ranker gives
    # every label-1 (vulnerable) sample a lower score than every label-0.
    score_frame = pd.DataFrame({
        "sample_id": ["s1", "s2", "s3", "s4"],
        "cwe": ["CWE-89"] * 4,
        "label": [1, 1, 0, 0],
        "score": [0.1, 0.2, 0.8, 0.9],
    })
    metrics = ranker_separation_metrics(score_frame)
    assert metrics["roc_auc"] == pytest.approx(1.0)
    assert metrics["n_vulnerable"] == 2
    assert metrics["n_safe"] == 2
    assert metrics["mean_score_safe"] > metrics["mean_score_vulnerable"]


def test_ranker_separation_metrics_gives_low_auc_for_inverted_scores():
    score_frame = pd.DataFrame({
        "sample_id": ["s1", "s2", "s3", "s4"],
        "cwe": ["CWE-89"] * 4,
        "label": [1, 1, 0, 0],
        "score": [0.9, 0.8, 0.1, 0.2],  # vulnerable scored HIGHER (safer) -- backwards
    })
    metrics = ranker_separation_metrics(score_frame)
    assert metrics["roc_auc"] == pytest.approx(0.0)


def _finding(file: str, func_name: str, cwe: str = "CWE-89", source: str = "semgrep") -> Finding:
    return Finding(
        file=Path(file), line=1, func_name=func_name, cwe=cwe, severity="ERROR",
        source=source, confidence=1.0, message="x", fix_hint="",
    )


def test_scan_ground_truth_eval_perfect_scan_scores_precision_recall_1():
    ground_truth = {("a.py", "vuln"): True, ("a.py", "safe"): False}
    result = ScanResult(
        findings=[_finding("a.py", "vuln")],
        n_units=2, n_auto_approved=1, n_escalated=0, skipped=[],
    )
    metrics = scan_ground_truth_eval(result, ground_truth)
    assert metrics == {
        "true_positive": 1, "false_positive": 0, "true_negative": 1, "false_negative": 0,
        "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0,
    }


def test_scan_ground_truth_eval_counts_false_positives_and_false_negatives():
    ground_truth = {
        ("a.py", "vuln1"): True,
        ("a.py", "vuln2"): True,   # missed by the scan -> false negative
        ("a.py", "safe1"): False,  # flagged anyway -> false positive
    }
    result = ScanResult(
        findings=[_finding("a.py", "vuln1"), _finding("a.py", "safe1")],
        n_units=3, n_auto_approved=0, n_escalated=0, skipped=[],
    )
    metrics = scan_ground_truth_eval(result, ground_truth)
    assert metrics["true_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["true_negative"] == 0
    assert metrics["precision"] == pytest.approx(0.5)
    assert metrics["recall"] == pytest.approx(0.5)


def test_scan_ground_truth_eval_module_level_finding_matches_module_key():
    ground_truth = {("config.py", "<module>"): True}
    result = ScanResult(
        findings=[_finding("config.py", "<module>", cwe="CWE-798")],
        n_units=0, n_auto_approved=0, n_escalated=0, skipped=[],
    )
    metrics = scan_ground_truth_eval(result, ground_truth)
    assert metrics["true_positive"] == 1
    assert metrics["accuracy"] == 1.0


def test_scan_ground_truth_eval_multiple_findings_on_same_unit_count_once():
    # get_user_by_name-style case: both semgrep AND model findings map to
    # the same (file, func_name). It should count as one flagged unit, not two.
    ground_truth = {("a.py", "vuln"): True}
    result = ScanResult(
        findings=[_finding("a.py", "vuln", source="semgrep"), _finding("a.py", "vuln", source="model")],
        n_units=1, n_auto_approved=0, n_escalated=1, skipped=[],
    )
    metrics = scan_ground_truth_eval(result, ground_truth)
    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 0
