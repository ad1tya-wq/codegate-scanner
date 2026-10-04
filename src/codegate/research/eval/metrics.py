from __future__ import annotations
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from codegate.oracles.cmdi_oracle import check_cmdi
from codegate.oracles.creds_oracle import check_creds
from codegate.oracles.semgrep_oracle import run_semgrep
from codegate.oracles.sqli_oracle import check_sqli
from codegate.research.pipeline import LABEL_ABSTAIN
from codegate.scan.pipeline import ScanResult

# (filename, cwe, function_name, ground_truth) -- ground truth is encoded in
# the filename itself (data/fixtures/*_vuln.py vs *_safe.py), same convention
# tests/test_oracles.py already relies on. function_name is None for
# check_creds, which doesn't need one.
_FIXTURE_SPECS: list[tuple[str, str, str | None, bool]] = [
    ("sqli_vuln.py", "CWE-89", "get_user", True),
    ("sqli_safe.py", "CWE-89", "get_user", False),
    ("cmdi_vuln.py", "CWE-78", "ping_host", True),
    ("cmdi_safe.py", "CWE-78", "ping_host", False),
    ("creds_vuln.py", "CWE-798", None, True),
    ("creds_safe.py", "CWE-798", None, False),
]


def oracle_accuracy_on_fixtures(fixtures_dir: str | Path) -> pd.DataFrame:
    """
    Runs each ground-truth oracle (dynamic sqli/cmdi, static creds) and
    semgrep against `data/fixtures/`'s six hand-labeled fixtures, one
    vulnerable/safe pair per tracked CWE. This is real, unchanging ground
    truth today -- unlike every ranker/gate metric below, which is still
    trained on the simulated corpus (see docs/ENGINEERING_LOG.md section 6).

    Deliberately small (n=2 per CWE): this checks "does the oracle still
    agree with its own textbook example," not statistical accuracy --
    broader parametrized coverage (7+ table-name variants, etc.) lives in
    tests/test_oracle_robustness.py, which is a test suite concern, not an
    eval-report one.
    """
    fixtures_dir = Path(fixtures_dir)
    rows = []
    for filename, cwe, function_name, truth in _FIXTURE_SPECS:
        code = (fixtures_dir / filename).read_text()
        if cwe == "CWE-89":
            oracle_verdict = check_sqli(code, function_name)
        elif cwe == "CWE-78":
            oracle_verdict = check_cmdi(code, function_name)
        else:
            oracle_verdict = check_creds(code)
        rows.append({
            "cwe": cwe,
            "fixture": filename,
            "truth": truth,
            "oracle_verdict": oracle_verdict,
            "oracle_correct": oracle_verdict == truth,
            "semgrep_hit": run_semgrep(code)["hit"],
            "semgrep_correct": run_semgrep(code)["hit"] == truth,
        })
    return pd.DataFrame(rows)


def corpus_label_distribution(labeled_df: pd.DataFrame) -> pd.DataFrame:
    """
    Counts samples by (cwe, outcome) where outcome is "vulnerable",
    "safe", or "abstained" -- the shape `research/pipeline.py::label_row`
    produces for any corpus, simulated or real. Works unchanged on
    `data/model/labeled.parquet` today and on Track A's real-corpus
    equivalent later; only the input file changes.
    """
    def _outcome(label: int) -> str:
        if label == LABEL_ABSTAIN:
            return "abstained"
        return "vulnerable" if label == 1 else "safe"

    df = labeled_df.copy()
    df["outcome"] = df["label"].map(_outcome)
    return df.groupby(["cwe", "outcome"]).size().reset_index(name="count")


def ranker_score_frame(
    labeled_df: pd.DataFrame,
    scores_df: pd.DataFrame,
    generations_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """
    Joins a labeled corpus with a ranker's per-sample scores on
    `sample_id`, dropping abstentions (they were excluded from training
    and calibration upstream, so they shouldn't count as "safe" here
    either). Input shape matches `data/model/labeled.parquet` +
    `data/model/scores_r2.parquet`.

    Given `generations_df` (the `generations.parquet` written beside them),
    each row also carries its `split`, which is what lets
    `ranker_separation_metrics` report a held-out figure. The split is
    joined here rather than written into `scores_r2.parquet` so the `scores`
    schema stays the ranker's own contract, and so artifacts written before
    this change can still be evaluated held-out.
    """
    merged = labeled_df.merge(scores_df, on="sample_id", how="inner")
    columns = ["sample_id", "cwe", "label", "score"]
    if generations_df is not None:
        extra = ["split"] + (["prompt_id"] if "prompt_id" in generations_df.columns else [])
        merged = merged.merge(generations_df[["sample_id", *extra]], on="sample_id", how="left")
        columns.append("split")
        if "prompt_id" in extra:
            merged["task_group"] = merged["prompt_id"].str.rsplit("-", n=1).str[0]
            columns.append("task_group")
    return merged[merged["label"] != LABEL_ABSTAIN][columns]


def ranker_separation_metrics(score_frame: pd.DataFrame, *, split: str | None = None) -> dict:
    """
    How well the ranker's score separates vulnerable from safe code,
    independent of any particular threshold: ROC-AUC (0.5 = no better
    than random, 1.0 = perfect separation -- R2Ranker's score is oriented
    so *higher* means *safer*, i.e. label 0, so AUC is computed against
    `1 - label`), plus the raw mean score per class for a sanity check
    AUC alone can't give (e.g. two classes could have equal means and
    opposite variance and still show AUC > 0.5).

    Pass `split="test"` for the figure to quote: the ranker never saw the
    test split, in training or in calibration. Without a split filter the
    frame includes the training samples, so the result is a memorization
    figure -- on the templated simulated corpus it read as a perfect 1.0.
    It is kept only for comparison. Filtering needs a frame built with
    `generations_df`; asking for a split without one raises rather than
    silently returning the full-corpus number under a held-out name.
    """
    if split is not None:
        if "split" not in score_frame.columns:
            raise ValueError(
                "ranker_separation_metrics: split filter requested but the frame has no "
                "'split' column -- build it with ranker_score_frame(..., generations_df=...)"
            )
        score_frame = score_frame[score_frame["split"] == split]
    labels = score_frame["label"].to_numpy()
    scores = score_frame["score"].to_numpy()
    return {
        "n_samples": len(score_frame),
        "n_vulnerable": int((labels == 1).sum()),
        "n_safe": int((labels == 0).sum()),
        "roc_auc": float(roc_auc_score(1 - labels, scores)) if len(set(labels)) > 1 else float("nan"),
        "mean_score_vulnerable": float(score_frame.loc[labels == 1, "score"].mean()),
        "mean_score_safe": float(score_frame.loc[labels == 0, "score"].mean()),
    }


def heldout_miss_rate(
    score_frame: pd.DataFrame, t_hat: float, split: str = "test",
    n_boot: int = 2000, seed: int = 0,
) -> dict:
    """
    The certificate checked against data it never saw: of the vulnerable
    samples in `split`, the share scoring >= t_hat (auto-approved).

    Reported two ways. `per_sample` pools every vulnerable sample.
    `per_group` averages each task group's fraction, which is the quantity
    the cluster-aware certificate bounds. `ci_low`/`ci_high` are a 95%
    bootstrap interval for `per_group` that resamples whole task groups:
    samples within a group are correlated, so resampling samples would
    understate the uncertainty.
    """
    vuln = score_frame[(score_frame["split"] == split) & (score_frame["label"] == 1)]
    approved = (vuln["score"] >= t_hat).astype(float)
    by_group = approved.groupby(vuln["task_group"]).mean().to_numpy()
    rng = np.random.default_rng(seed)
    boots = [by_group[rng.integers(0, len(by_group), len(by_group))].mean() for _ in range(n_boot)]
    low, high = np.percentile(boots, [2.5, 97.5])
    return {
        "n_vulnerable": int(len(vuln)),
        "n_groups": int(len(by_group)),
        "per_sample": float(approved.mean()),
        "per_group": float(by_group.mean()),
        "ci_low": float(low),
        "ci_high": float(high),
    }


def scan_ground_truth_eval(
    scan_result: ScanResult, ground_truth: dict[tuple[str, str], bool]
) -> dict:
    """
    Precision/recall/F1/accuracy of the scan AS A WHOLE (any finding at
    all, regardless of source -- semgrep, model, or verifier) against a
    hand-labeled ground truth of {(filename, func_name): is_vulnerable}.
    `func_name="<module>"` matches a module-level finding the same way
    `scan/pipeline.py::_semgrep_findings` itself falls back to it.

    This is the one metric in this module that evaluates the deployed
    pipeline end-to-end rather than one component in isolation, and the
    one whose ground truth is entirely real today (see
    examples/vulnerable_app/README.md's CWE table) -- not waiting on
    Track A at all.
    """
    predicted_positive = {(Path(f.file).name, f.func_name) for f in scan_result.findings}

    tp = fp = tn = fn = 0
    for key, is_vulnerable in ground_truth.items():
        flagged = key in predicted_positive
        if is_vulnerable and flagged:
            tp += 1
        elif is_vulnerable and not flagged:
            fn += 1
        elif not is_vulnerable and flagged:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) and precision == precision and recall == recall else float("nan")
    return {
        "true_positive": tp, "false_positive": fp,
        "true_negative": tn, "false_negative": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / len(ground_truth) if ground_truth else float("nan"),
    }
