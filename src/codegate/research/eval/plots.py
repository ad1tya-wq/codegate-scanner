from __future__ import annotations
import matplotlib
matplotlib.use("Agg")  # headless -- no display needed for saving PNGs
import matplotlib.pyplot as plt
import pandas as pd


def plot_frontier(frontier_df: pd.DataFrame, out_path: str) -> None:
    df = frontier_df.sort_values("alpha")
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(df["alpha"], df["coverage"], marker="o")
    ax.set_xlabel("Certified max miss-rate (alpha)")
    ax.set_ylabel("Auto-approval coverage (fraction, LLM-free)")
    ax.set_title("CodeGate certified cost-coverage frontier")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_shift_results(results: list, out_path: str) -> None:
    names = [r.held_out_generator for r in results]
    realized = [r.realized_risk_on_held_out for r in results]
    alpha = results[0].certified_alpha if results else 0.05

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(names, realized, color=["#2e7d32" if r.certificate_held else "#c62828" for r in results])
    ax.axhline(alpha, color="black", linestyle="--", label=f"certified alpha={alpha}")
    ax.set_xlabel("Held-out generator")
    ax.set_ylabel("Realized risk on held-out generator")
    ax.set_title("Certificate decay under generator shift")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_oracle_accuracy(accuracy_df: pd.DataFrame, out_path: str) -> None:
    """One bar per fixture, green if the oracle's verdict matched ground
    truth, red if not -- see research/eval/metrics.py::oracle_accuracy_on_fixtures."""
    fig, ax = plt.subplots(figsize=(6, 4))
    labels = [f"{row.cwe}\n{row.fixture}" for row in accuracy_df.itertuples()]
    colors = ["#2e7d32" if c else "#c62828" for c in accuracy_df["oracle_correct"]]
    ax.bar(labels, [1] * len(accuracy_df), color=colors)
    ax.set_yticks([])
    ax.set_title("Oracle verdict vs. ground truth (data/fixtures/)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_corpus_label_distribution(dist_df: pd.DataFrame, out_path: str) -> None:
    """Stacked bar of vulnerable/safe/abstained counts per CWE -- see
    research/eval/metrics.py::corpus_label_distribution."""
    pivot = dist_df.pivot(index="cwe", columns="outcome", values="count").fillna(0)
    colors = {"vulnerable": "#c62828", "safe": "#2e7d32", "abstained": "#9e9e9e"}
    fig, ax = plt.subplots(figsize=(6, 4))
    bottom = None
    for outcome in ["vulnerable", "safe", "abstained"]:
        if outcome not in pivot.columns:
            continue
        values = pivot[outcome]
        ax.bar(pivot.index, values, bottom=bottom, label=outcome, color=colors[outcome])
        bottom = values if bottom is None else bottom + values
    ax.set_xlabel("CWE")
    ax.set_ylabel("Sample count")
    ax.set_title("Corpus label distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_score_distribution_by_label(score_frame: pd.DataFrame, out_path: str) -> None:
    """Overlapping histograms of the ranker's score, vulnerable vs. safe --
    the ranker is doing its job if these two distributions barely overlap.
    See research/eval/metrics.py::ranker_score_frame."""
    fig, ax = plt.subplots(figsize=(6, 4))
    vuln = score_frame.loc[score_frame["label"] == 1, "score"]
    safe = score_frame.loc[score_frame["label"] == 0, "score"]
    ax.hist(safe, bins=20, alpha=0.6, label=f"safe (n={len(safe)})", color="#2e7d32")
    ax.hist(vuln, bins=20, alpha=0.6, label=f"vulnerable (n={len(vuln)})", color="#c62828")
    ax.set_xlabel("Ranker score (higher = safer)")
    ax.set_ylabel("Sample count")
    ax.set_title("Score distribution by true label")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_ltt_trace(trace_df: pd.DataFrame, alpha: float, t_hat: float | None, out_path: str) -> None:
    """The LTT threshold search itself: p-value at every candidate
    threshold, with the certified region and the winning t_hat marked.
    Input matches data/model/ltt_trace.csv's columns exactly."""
    df = trace_df.replace([float("inf")], float("nan")).dropna(subset=["threshold"]).sort_values("threshold")
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(df["threshold"], df["p_value"], marker=".", color="#1565c0", label="p-value")
    ax.axhline(alpha, color="black", linestyle="--", label=f"alpha={alpha}")
    if t_hat is not None:
        ax.axvline(t_hat, color="#2e7d32", linestyle=":", label=f"t_hat={t_hat:.4f}")
    ax.set_xlabel("Candidate threshold t")
    ax.set_ylabel("p-value")
    ax.set_title("LTT threshold search")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_scan_ground_truth(eval_dict: dict, out_path: str) -> None:
    """Confusion-matrix-style bar chart for
    research/eval/metrics.py::scan_ground_truth_eval's TP/FP/TN/FN counts,
    plus precision/recall/F1 as text."""
    fig, ax = plt.subplots(figsize=(6, 4))
    keys = ["true_positive", "false_positive", "true_negative", "false_negative"]
    colors = ["#2e7d32", "#c62828", "#2e7d32", "#c62828"]
    ax.bar(keys, [eval_dict[k] for k in keys], color=colors)
    ax.set_ylabel("Count")
    ax.set_title(
        f"Scan vs. ground truth -- precision {eval_dict['precision']:.2f}, "
        f"recall {eval_dict['recall']:.2f}, F1 {eval_dict['f1']:.2f}"
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
