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
