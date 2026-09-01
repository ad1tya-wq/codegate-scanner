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
from codegate.gate.ltt import calibrate_threshold
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

# Label vocabulary. 1 = vulnerable, 0 = safe, -1 = the oracle abstained.
# Abstention is a distinct third state on purpose: collapsing it into "safe"
# is a silent-failure path that corrupts both the trained ranker and the
# conformal certificate that depends on those labels.
LABEL_VULNERABLE = 1
LABEL_SAFE = 0
LABEL_ABSTAIN = -1


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
    consensus rule, returning one `labeled` row.

    `use_semgrep_and_adjudicator=False` (the default, used by the simulated
    dry run) skips the semgrep call, which is too slow to invoke per-row at
    corpus scale. Real runs pass True.

    Returns LABEL_ABSTAIN when no oracle reached a verdict. Callers must
    exclude those rows rather than treating them as safe.
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
        # The oracle could not reach a verdict (function not found, timeout,
        # harness error). This is NOT evidence of safety. Recording it as 0
        # silently poisons the corpus and biases the certificate in the
        # flattering direction -- it is what hid the CWE-89 table-name bug,
        # where 540/540 samples abstained and every one was labelled safe.
        # LABEL_ABSTAIN is excluded from training and calibration upstream.
        label = LABEL_ABSTAIN
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
    checkpoint_path: Path | None = None,
) -> dict:
    """
    Generation -> oracle labeling -> consensus -> R2 ranking -> LTT
    calibration -> cost-coverage frontier -> generator-shift experiment.
    Writes every intermediate artifact to `out_dir` and returns a summary
    dict. Shared by scripts/run_pipeline_dry_run.py (SimulatedBackend) and
    scripts/run_real.py (real backends) so the two never drift apart.

    `checkpoint_path` makes generation resumable -- essential for the
    multi-hour Ollama runs, harmless for the simulated dry run.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    gen_df = run_generation(
        prompts, backends,
        samples_per_prompt=cfg.samples_per_prompt,
        is_simulated=is_simulated,
        checkpoint_path=checkpoint_path,
    )
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

    # Abstentions are excluded from every downstream statistic. Reporting a
    # vulnerable rate over rows the oracle never actually judged would be
    # meaningless, and calibrating on them would invalidate the certificate.
    n_abstain = int((labeled_df["label"] == LABEL_ABSTAIN).sum())
    decided = labeled_df[labeled_df["label"] != LABEL_ABSTAIN]
    vuln_rate = float(decided["label"].mean()) if len(decided) else float("nan")
    summary["vuln_rate"] = vuln_rate
    summary["n_abstain"] = n_abstain
    print(
        f"Labeled {len(labeled_df)} snippets; {len(decided)} decided, "
        f"{n_abstain} abstained ({n_abstain / max(len(labeled_df), 1):.1%}); "
        f"vulnerable rate among decided = {vuln_rate:.2%}"
    )
    if n_abstain > 0.2 * len(labeled_df):
        print(
            f"[warn] {n_abstain}/{len(labeled_df)} oracle abstentions is high. "
            f"The oracle is likely failing to invoke the generated functions "
            f"(wrong entry-point name, or a fixture mismatch such as an "
            f"unexpected SQL table name) rather than genuinely finding them safe."
        )

    merged = gen_df.merge(labeled_df[["sample_id", "label"]], on="sample_id")
    merged = merged[merged["label"] != LABEL_ABSTAIN].reset_index(drop=True)

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
        # alpha/delta come from config.yaml -- they are the project's stated
        # statistical contract and must not be hardcoded here. The sweep
        # brackets the configured alpha so the frontier shows the trade-off
        # around the operating point actually being certified.
        alphas = sorted({cfg.alpha, 0.05, 0.10, 0.20, 0.30})
        frontier_df = compute_frontier(calib_scores, calib_labels, alphas=alphas, delta=cfg.delta)
        frontier_df.to_csv(out_dir / "frontier.csv", index=False)
        plot_frontier(frontier_df, str(out_dir / "frontier.png"))
        print(frontier_df.to_string(index=False))

        # Persist the threshold-search trace at the configured operating
        # point: it is the evidence behind t_hat, and a reviewer will ask.
        operating = calibrate_threshold(calib_scores, calib_labels, alpha=cfg.alpha, delta=cfg.delta)
        pd.DataFrame(
            operating.trace, columns=["threshold", "k_vuln_auto_approved", "p_value", "certified"]
        ).to_csv(out_dir / "ltt_trace.csv", index=False)
        summary["t_hat"] = operating.t_hat
        summary["coverage"] = operating.coverage
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
                r = run_shift_experiment(
                    scores_by_gen, labels_by_gen, held_out, alpha=cfg.alpha, delta=cfg.delta
                )
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
