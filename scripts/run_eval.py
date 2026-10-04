#!/usr/bin/env python
"""
Compute and plot every metric CodeGate can currently evaluate.

Reads whatever is at data/model/ -- the interim simulated-corpus
artifacts today, the real Track-A-trained artifacts once Phase 8 lands --
and examples/vulnerable_app/ (real, hand-labeled ground truth, not
provisional). Every function this script calls lives in
research/eval/metrics.py and research/eval/plots.py and works completely
unchanged before and after Phase 8; only the input data changes.

    python scripts/run_eval.py                # everything except the LLM verifier
    python scripts/run_eval.py --with-llm      # also scores WITH the verifier
                                                # (needs GROQ_API_KEY; cached by
                                                # content_hash, so a second run
                                                # costs zero further calls)

Writes PNGs and a metrics.json summary to data/eval/.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd

from codegate.research.artifacts import load_calibration
from codegate.research.eval.metrics import (
    corpus_label_distribution,
    oracle_accuracy_on_fixtures,
    heldout_miss_rate,
    ranker_score_frame,
    ranker_separation_metrics,
    scan_ground_truth_eval,
)
from codegate.research.eval.plots import (
    plot_corpus_label_distribution,
    plot_ltt_trace,
    plot_oracle_accuracy,
    plot_scan_ground_truth,
    plot_score_distribution_by_label,
)
from codegate.scan.pipeline import run_scan
from codegate.scan.verifier import build_verifier_backend

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "data" / "fixtures"
DEMO_APP_DIR = REPO_ROOT / "examples" / "vulnerable_app"
OUT_DIR = REPO_ROOT / "data" / "eval"

# Ground truth for examples/vulnerable_app/ -- mirrors its own README's CWE
# table exactly. "<module>" matches scan/pipeline.py's own fallback
# func_name for a finding that isn't inside any function (config.py's
# module-level DATABASE_PASSWORD literal).
DEMO_APP_GROUND_TRUTH: dict[tuple[str, str], bool] = {
    ("database.py", "get_user_by_name"): True,
    ("database.py", "get_user_by_id"): False,
    ("database.py", "list_active_users"): False,
    ("database.py", "seed_demo_data"): False,
    ("system_tasks.py", "ping_host"): True,
    ("system_tasks.py", "ping_host_safely"): False,
    ("system_tasks.py", "list_directory"): False,
    ("config.py", "<module>"): True,
    ("config.py", "get_api_key"): False,
    ("report_utils.py", "to_fahrenheit"): False,
    ("report_utils.py", "slugify"): False,
    ("report_utils.py", "average"): False,
    ("app.py", "handle_login"): False,
    ("app.py", "handle_diagnostics"): False,
    ("app.py", "connect_to_upstream"): False,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model-dir", default="data/model")
    parser.add_argument(
        "--with-llm", action="store_true",
        help="Also run the scan-ground-truth eval WITH the LLM verifier. "
             "Opt-in, not the default -- an eval script shouldn't spend API "
             "calls just by being run.",
    )
    args = parser.parse_args()
    model_dir = Path(args.model_dir)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    print("[1/5] Oracle accuracy on data/fixtures/ (real ground truth) ...")
    acc_df = oracle_accuracy_on_fixtures(FIXTURES_DIR)
    plot_oracle_accuracy(acc_df, str(OUT_DIR / "oracle_accuracy.png"))
    summary["oracle_accuracy"] = {
        "n_correct": int(acc_df["oracle_correct"].sum()),
        "n_total": len(acc_df),
    }
    print(f"      {summary['oracle_accuracy']['n_correct']}/{summary['oracle_accuracy']['n_total']} oracle verdicts correct")

    labeled_path = model_dir / "labeled.parquet"
    if labeled_path.exists():
        print("[2/5] Corpus label distribution ...")
        labeled_df = pd.read_parquet(labeled_path)
        dist_df = corpus_label_distribution(labeled_df)
        plot_corpus_label_distribution(dist_df, str(OUT_DIR / "corpus_label_distribution.png"))
        summary["corpus_label_distribution"] = dist_df.to_dict(orient="records")
    else:
        labeled_df = None
        print(f"      skipped -- {labeled_path} not found (run `codegate calibrate` first)")

    scores_path = model_dir / "scores_r2.parquet"
    if labeled_df is not None and scores_path.exists():
        print("[3/5] Ranker score distribution + separation metrics ...")
        scores_df = pd.read_parquet(scores_path)
        gens_path = model_dir / "generations.parquet"
        gens_df = pd.read_parquet(gens_path) if gens_path.exists() else None
        score_frame = ranker_score_frame(labeled_df, scores_df, generations_df=gens_df)
        plot_score_distribution_by_label(score_frame, str(OUT_DIR / "score_distribution.png"))
        # The held-out figure is the one to quote. The full-corpus figure
        # includes the ranker's own training samples and is printed only so
        # the gap between the two is visible.
        sep = ranker_separation_metrics(score_frame)
        summary["ranker_separation_full_corpus"] = sep
        print(f"      ROC-AUC (full corpus, includes training data) = {sep['roc_auc']:.4f}  n={sep['n_samples']}")
        if gens_df is not None:
            held = ranker_separation_metrics(score_frame, split="test")
            summary["ranker_separation_heldout"] = held
            print(f"      ROC-AUC (held-out test split -- quote this)  = {held['roc_auc']:.4f}  n={held['n_samples']}")
            calib_for_check = model_dir / "calibration.json"
            if "task_group" in score_frame.columns and calib_for_check.exists():
                shipped = load_calibration(calib_for_check)
                if shipped.t_hat is not None:
                    miss = heldout_miss_rate(score_frame, shipped.t_hat, split="test")
                    summary["heldout_miss_rate"] = {**miss, "alpha": shipped.alpha}
                    print(f"      held-out miss rate at t_hat (alpha={shipped.alpha}): "
                          f"{miss['per_group']:.3f} per task group "
                          f"(95% cluster bootstrap {miss['ci_low']:.3f}-{miss['ci_high']:.3f}), "
                          f"{miss['per_sample']:.3f} per sample, over {miss['n_vulnerable']} vulnerable "
                          f"samples in {miss['n_groups']} groups")
        else:
            print(f"      held-out AUC skipped -- {gens_path} not found, so splits are unknown")
    else:
        print(f"      skipped -- {scores_path} not found")

    trace_path = model_dir / "ltt_trace.csv"
    calib_path = model_dir / "calibration.json"
    if trace_path.exists() and calib_path.exists():
        print("[4/5] LTT threshold search trace ...")
        trace_df = pd.read_csv(trace_path)
        calib = load_calibration(calib_path)
        plot_ltt_trace(trace_df, calib.alpha, calib.t_hat, str(OUT_DIR / "ltt_trace.png"))
        summary["ltt_trace"] = {"alpha": calib.alpha, "t_hat": calib.t_hat, "n_candidates": len(trace_df)}
    else:
        print(f"      skipped -- {trace_path} or {calib_path} not found")

    print("[5/5] Scan vs. ground truth on examples/vulnerable_app/ (real ground truth) ...")
    result_static = run_scan(DEMO_APP_DIR, model_dir=model_dir)
    eval_static = scan_ground_truth_eval(result_static, DEMO_APP_GROUND_TRUTH)
    plot_scan_ground_truth(eval_static, str(OUT_DIR / "scan_ground_truth_static.png"))
    summary["scan_ground_truth_static_gate_only"] = eval_static
    print(
        f"      static+gate only: precision={eval_static['precision']:.2f} "
        f"recall={eval_static['recall']:.2f} f1={eval_static['f1']:.2f}"
    )

    if args.with_llm:
        verifier = build_verifier_backend("llama-3.3-70b-groq")
        if verifier is None:
            print("      --with-llm given but no GROQ_API_KEY found; skipping")
        else:
            result_llm = run_scan(DEMO_APP_DIR, model_dir=model_dir, verifier=verifier)
            eval_llm = scan_ground_truth_eval(result_llm, DEMO_APP_GROUND_TRUTH)
            plot_scan_ground_truth(eval_llm, str(OUT_DIR / "scan_ground_truth_with_verifier.png"))
            summary["scan_ground_truth_with_verifier"] = eval_llm
            print(
                f"      with LLM verifier: precision={eval_llm['precision']:.2f} "
                f"recall={eval_llm['recall']:.2f} f1={eval_llm['f1']:.2f}"
            )

    (OUT_DIR / "metrics.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nWrote plots + metrics.json to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
