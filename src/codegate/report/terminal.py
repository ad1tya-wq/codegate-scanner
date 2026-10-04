from __future__ import annotations
from pathlib import Path

from rich.console import Console
from rich.table import Table

from codegate.report.accounting import compute_cost_summary
from codegate.scan.pipeline import ScanResult


def render_terminal(result: ScanResult, target: Path, console: Console, verifier_model: str | None = None) -> None:
    """
    Prints a human-readable scan summary to `console` -- the default
    `codegate scan` output when no --format is given. Deterministic, no
    LLM involvement in composing any of this text.
    """
    cost = compute_cost_summary(result, verifier_model)

    console.print(f"[bold]CodeGate scan[/bold] -- {target}")

    summary = Table(title="Summary", show_header=False, box=None)
    summary.add_row("Units scanned", str(result.n_units))
    summary.add_row("Auto-approved", str(result.n_auto_approved))
    summary.add_row("Escalated", str(result.n_escalated))
    summary.add_row("Findings", str(len(result.findings)))
    summary.add_row("Skipped files", str(len(result.skipped)))
    console.print(summary)

    if result.findings:
        # overflow="fold" everywhere, not the rich default ("ellipsis"):
        # the default truncation marker is a Unicode ellipsis character
        # that renders as mojibake on a default-codepage Windows terminal
        # (same class of issue as the "section symbol" fix elsewhere in
        # this CLI) -- folding wraps long values onto extra lines instead.
        table = Table(title="Findings")
        table.add_column("File:Line", overflow="fold")
        table.add_column("Function", overflow="fold")
        table.add_column("CWE", overflow="fold")
        table.add_column("Severity", overflow="fold")
        table.add_column("Source", overflow="fold")
        table.add_column("Message", overflow="fold")
        for f in result.findings:
            table.add_row(f"{f.file}:{f.line}", f.func_name, f.cwe, f.severity, f.source, f.message)
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    calib = result.calibration
    if calib is not None:
        cert = Table(title="Certificate", show_header=False, box=None)
        cert.add_row("Corpus version", calib.corpus_version)
        cert.add_row(
            "t_hat (auto-approve threshold)",
            "none -- everything escalated" if calib.t_hat is None else f"{calib.t_hat:.4f}",
        )
        cert.add_row("Certified max miss-rate (alpha)", f"{calib.alpha:.2%}")
        cert.add_row("Certificate method", calib.method_description())
        console.print(cert)

    console.print(
        f"LLM calls made: {cost.calls_made}  |  avoided: {cost.calls_avoided}  |  "
        f"est. cost: ${cost.estimated_cost_usd:.4f} (estimate -- see --format pdf/json for assumptions)"
    )
