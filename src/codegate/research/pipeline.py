from __future__ import annotations
from pathlib import Path

import numpy as np
import pandas as pd

from codegate.config import CodeGateConfig
from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import Backend
from codegate.research.generation.harness import run_generation
from codegate.oracles.sqli_oracle import check_sqli
from codegate.oracles.cmdi_oracle import check_cmdi
from codegate.oracles.creds_oracle import check_creds
from codegate.oracles.consensus import consensus_label, CONSENSUS_RULE_VERSION
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.research.eval.frontier import compute_frontier
from codegate.research.eval.shift import run_shift_experiment
from codegate.research.eval.plots import plot_frontier, plot_shift_results
from codegate.schemas import validate_dataframe

# Function names SimulatedBackend's templates use -- see generation/backends.py
# _SIM_TEMPLATES. Real backends won't reliably use these names, so
# label_row() also handles the "function not found under any candidate
# name" case by trying an AST scan for the *first* top-level function
# defined, which is what a real model's output will actually look like.
_SIM_CANDIDATE_FN_NAMES = ["handler", "process", "run_task", "do_work"]


def _first_function_name(code: str) -> str | None:
    import ast
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return node.name
    return None


def label_row(row: pd.Series, use_semgrep_and_adjudicator: bool = False) -> dict:
    """
    Runs the appropriate oracle(s) for one generated snippet and applies the
    consensus rule. `use_semgrep_and_adjudicator=False` (the default, used
    by the simulated dry run) skips the semgrep + LLM-adjudicator calls --
    semgrep is too slow to call per-row at corpus scale (see
    NEEDS_FROM_YOU.md) and the adjudicator needs an API key -- and falls
    back to "no evidence of vulnerability" (label 0) when the dynamic/static
    oracle itself has no verdict, rather than blocking. Real runs
    (`use_semgrep_and_adjudicator=True`) are expected to always get a
    dynamic/static verdict since real generators reliably define *some*
    function; if that stops being true this flag is where to revisit it.
    """
    code = row["code"]
    cwe = row["cwe"]

    candidate_names = list(_SIM_CANDIDATE_FN_NAMES)
    first_fn = _first_function_name(code)
    if first_fn and first_fn not in candidate_names:
        candidate_names = [first_fn] + candidate_names

    dynamic_verdict = None
    static_verdict = None

    if cwe == "CWE-89":
        for fn in candidate_names:
            v = check_sqli(code, function_name=fn)
            if v is not None:
                dynamic_verdict = v
                break
    elif cwe == "CWE-78":
        for fn in candidate_names:
            v = check_cmdi(code, function_name=fn)
            if v is not None:
                dynamic_verdict = v
                break
    elif cwe == "CWE-798":
        static_verdict = check_creds(code)

    semgrep_hit = False
    adjudicator_verdict = False
    if use_semgrep_and_adjudicator:
        from codegate.oracles.semgrep_oracle import run_semgrep
        semgrep_hit = run_semgrep(code)["hit"]
        # adjudicator_verdict left False until a GeminiBackend-based
        # adjudicator call is wired in -- see NEEDS_FROM_YOU.md item 1.

    if dynamic_verdict is None and static_verdict is None:
        label = 0
    else:
        label = consensus_label(cwe, semgrep_hit, dynamic_verdict, static_verdict, adjudicator_verdict)

    return {
        "sample_id": row["sample_id"],
        "cwe": cwe,
        "label": label,
        "semgrep_hit": semgrep_hit,
        "dynamic_verdict": dynamic_verdict,
        "static_verdict": static_verdict,
        "adjudicator_verdict": adjudicator_verdict,
        "consensus_rule_version": CONSENSUS_RULE_VERSION,
    }


def run_full_pipeline(
    cfg: CodeGateConfig,
    prompts: list[Prompt],
    backends: dict[str, Backend],
    is_simulated: bool,
    out_dir: Path,
    use_semgrep_and_adjudicator: bool = False,
) -> dict:
    """
    Generation -> oracle labeling -> consensus -> R2 ranking -> LTT
    calibration -> cost-coverage frontier -> generator-shift experiment.
    Writes every intermediate artifact to `out_dir` and returns a summary
    dict. Shared by scripts/run_pipeline_dry_run.py (SimulatedBackend) and
    scripts/run_real.py (real backends) so the two never drift apart.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    gen_df = run_generation(prompts, backends, samples_per_prompt=cfg.samples_per_prompt, is_simulated=is_simulated)
    validate_dataframe(gen_df, "generations")
    gen_df.to_parquet(out_dir / "generations.parquet")
    summary["n_generated"] = len(gen_df)
    print(f"Generated {len(gen_df)} snippets across {len(backends)} generators (is_simulated={is_simulated})")

    labeled_rows = [
        label_row(row, use_semgrep_and_adjudicator=use_semgrep_and_adjudicator)
        for _, row in gen_df.iterrows()
    ]
    labeled_df = pd.DataFrame(labeled_rows)
    labeled_df.to_parquet(out_dir / "labeled.parquet")
    vuln_rate = labeled_df["label"].mean()
    summary["vuln_rate"] = float(vuln_rate)
    print(f"Labeled {len(labeled_df)} snippets; overall vulnerable rate = {vuln_rate:.2%}")

    merged = gen_df.merge(labeled_df[["sample_id", "label"]], on="sample_id")

    train_mask = merged["split"] == "train"
    ranker = R2Ranker(random_seed=cfg.random_seed)
    ranker.fit(merged[train_mask], merged.loc[train_mask, "label"])
    scores_df = ranker.score(merged)
    scores_df.to_parquet(out_dir / "scores_r2.parquet")

    scored_merged = merged.merge(scores_df[["sample_id", "score"]], on="sample_id")
    calib_mask = scored_merged["split"] == "calib"
    calib_scores = scored_merged.loc[calib_mask, "score"].to_numpy()
    calib_labels = scored_merged.loc[calib_mask, "label"].to_numpy()

    n_vuln_calib = int((calib_labels == 1).sum())
    summary["n_vuln_calib"] = n_vuln_calib
    print(f"Calibration set: {len(calib_labels)} samples, {n_vuln_calib} vulnerable")

    if n_vuln_calib > 0:
        frontier_df = compute_frontier(calib_scores, calib_labels, alphas=[0.05, 0.1, 0.2, 0.3], delta=0.1)
        frontier_df.to_csv(out_dir / "frontier.csv", index=False)
        plot_frontier(frontier_df, str(out_dir / "frontier.png"))
        print(frontier_df.to_string(index=False))
    else:
        pd.DataFrame({"alpha": [], "t_hat": [], "coverage": [], "n_vuln_calib": []}).to_csv(
            out_dir / "frontier.csv", index=False
        )
        _write_placeholder_plot(out_dir / "frontier.png", "insufficient vulnerable calibration samples")
        print("WARNING: zero vulnerable calibration samples; frontier.png is a placeholder.")

    scores_by_gen: dict[str, np.ndarray] = {}
    labels_by_gen: dict[str, np.ndarray] = {}
    for gen_name, gen_group in scored_merged.groupby("generator"):
        scores_by_gen[gen_name] = gen_group["score"].to_numpy()
        labels_by_gen[gen_name] = gen_group["label"].to_numpy()

    shift_results = []
    if len(scores_by_gen) >= 2 and n_vuln_calib > 0:
        for held_out in scores_by_gen:
            try:
                r = run_shift_experiment(scores_by_gen, labels_by_gen, held_out, alpha=0.2, delta=0.1)
                shift_results.append(r)
            except ValueError as e:
                print(f"skipping shift experiment for {held_out}: {e}")

    if shift_results:
        shift_df = pd.DataFrame([r.__dict__ for r in shift_results])
        shift_df.to_csv(out_dir / "shift_results.csv", index=False)
        plot_shift_results(shift_results, str(out_dir / "shift_results.png"))
    else:
        pd.DataFrame(columns=["held_out_generator", "t_hat", "certified_alpha",
                               "realized_risk_on_held_out", "certificate_held"]).to_csv(
            out_dir / "shift_results.csv", index=False
        )
        _write_placeholder_plot(out_dir / "shift_results.png", "insufficient data for shift experiment")

    summary["n_shift_experiments"] = len(shift_results)
    return summary


def _write_placeholder_plot(path: Path, message: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()
    ax.text(0.5, 0.5, message, ha="center", va="center")
    fig.savefig(path)
    plt.close(fig)
