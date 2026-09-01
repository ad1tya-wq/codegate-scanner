from __future__ import annotations
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from codegate.config import load_config
from codegate.env import get_env
from codegate.research.artifacts import ArtifactVersionError, load_artifacts
from codegate.research.corpus.prompts import load_prompt_bank
from codegate.research.generation.backends import OllamaBackend, SimulatedBackend, stable_seed
from codegate.research.pipeline import run_full_pipeline

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()

# Canonical location for the artifacts the repo ships pre-trained, so a
# fresh clone works with zero setup -- `codegate info` and `codegate scan`
# both default here.
DEFAULT_MODEL_DIR = Path("data/model")
DEFAULT_OLLAMA_URL = "http://localhost:11434"
_VALID_FORMATS = ("pdf", "json", "sarif", "terminal")


@app.command()
def info(
    model_dir: Path = typer.Option(
        DEFAULT_MODEL_DIR, "--model-dir",
        help="Directory containing model.joblib and calibration.json",
    ),
) -> None:
    """Show the currently loaded model and its certificate."""
    try:
        _, calib = load_artifacts(model_dir / "model.joblib", model_dir / "calibration.json")
    except (FileNotFoundError, ArtifactVersionError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    table = Table(title="CodeGate certificate", show_header=False)
    table.add_row("Ranker", calib.ranker_id)
    table.add_row("Corpus version", calib.corpus_version)
    table.add_row(
        "t_hat (auto-approve threshold)",
        "none -- everything escalated" if calib.t_hat is None else f"{calib.t_hat:.4f}",
    )
    table.add_row("Certified max miss-rate (alpha)", f"{calib.alpha:.2%}")
    table.add_row("Confidence (1 - delta)", f"{1 - calib.delta:.2%}")
    table.add_row("Calibration vulnerable samples", str(calib.n_vuln_calib))
    table.add_row("Created", calib.created_at)
    console.print(table)

    if calib.is_provisional:
        console.print(
            "\n[bold yellow]PROVISIONAL[/bold yellow] -- calibrated on "
            f"'{calib.corpus_version}', not a real LLM-generated corpus. "
            "Coverage and miss-rate numbers are not yet meaningful. "
            "See docs/ENGINEERING_LOG.md, section 6."
        )


@app.command()
def calibrate(
    config: Path = typer.Option(Path("config.yaml"), "--config"),
    out_dir: Path = typer.Option(DEFAULT_MODEL_DIR, "--out-dir"),
    real: bool = typer.Option(
        False, "--real",
        help="Use live Ollama generators instead of the offline simulator",
    ),
    base_url: str = typer.Option(
        None, "--base-url", help="Ollama host URL (--real only; default OLLAMA_BASE_URL or localhost)"
    ),
    limit: int = typer.Option(None, "--limit", help="Only use the first N prompts"),
) -> None:
    """Re-run the research pipeline: generate, label, rank, and calibrate."""
    cfg = load_config(str(config))
    prompts = load_prompt_bank(cfg.prompts_dir)
    if limit is not None:
        prompts = prompts[:limit]

    if real:
        url = base_url or get_env("OLLAMA_BASE_URL", DEFAULT_OLLAMA_URL)
        backends = {name: OllamaBackend(model=name, base_url=url) for name in cfg.generators}
    else:
        backends = {name: SimulatedBackend(name=name, seed=stable_seed(name)) for name in cfg.generators}

    console.print(
        f"Calibrating ({'real Ollama' if real else 'simulated'} generation, "
        f"{len(prompts)} prompts) -> {out_dir}"
    )
    summary = run_full_pipeline(
        cfg, prompts, backends, is_simulated=not real, out_dir=out_dir,
        use_semgrep_and_adjudicator=real,
    )
    console.print(
        f"Vulnerable rate: {summary['vuln_rate']:.2%}  |  "
        f"t_hat: {summary.get('t_hat')}  |  coverage: {summary.get('coverage')}"
    )
    console.print(f"Wrote {out_dir / 'model.joblib'} and {out_dir / 'calibration.json'}")


@app.command()
def scan(
    path: Path = typer.Argument(..., help="File or directory to scan"),
    format: str = typer.Option("terminal", "--format", help="pdf | json | sarif | terminal"),
    output: Path = typer.Option(None, "--output"),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the LLM verifier; escalated findings report as needs-review"
    ),
    alpha: float = typer.Option(None, "--alpha", help="Override the certified max miss-rate"),
) -> None:
    """Scan a file or directory and produce a findings report."""
    if format not in _VALID_FORMATS:
        console.print(f"[red]--format must be one of {_VALID_FORMATS} (got '{format}').[/red]")
        raise typer.Exit(code=1)

    console.print(
        "[yellow]`codegate scan` is not implemented yet[/yellow] -- ingest, the "
        "scan pipeline, and reporting are Phases 4-7 (see docs/ENGINEERING_LOG.md, "
        "Part 3). `codegate info` and `codegate calibrate` are functional today."
    )
    raise typer.Exit(code=2)
