from __future__ import annotations
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from codegate.config import load_config
from codegate.env import get_env
from codegate.report.json_sarif import to_json, to_sarif
from codegate.report.pdf import generate_pdf
from codegate.report.terminal import render_terminal
from codegate.research.artifacts import ArtifactVersionError, load_artifacts
from codegate.research.corpus.prompts import load_prompt_bank
from codegate.research.generation.backends import OllamaBackend, SimulatedBackend, stable_seed
from codegate.scan.pipeline import run_scan
from codegate.scan.verifier import build_verifier_backend

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
    # Imported here, not at module level: run_full_pipeline transitively
    # imports matplotlib (research.eval.plots), which is only declared in
    # the optional `research` extra. `scan`/`info` must not require it --
    # a plain `pip install -e .` (no [research]) would otherwise crash on
    # every codegate invocation, not just `calibrate`.
    from codegate.research.pipeline import run_full_pipeline

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
    output: Path = typer.Option(None, "--output", help="Write the report here (json/sarif/pdf); defaults to stdout for json/sarif, codegate_report.pdf for pdf"),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the LLM verifier; escalated findings report as needs-review"
    ),
    alpha: float = typer.Option(None, "--alpha", help="Override the certified max miss-rate"),
    model_dir: Path = typer.Option(
        DEFAULT_MODEL_DIR, "--model-dir",
        help="Directory containing model.joblib and calibration.json",
    ),
    config: Path = typer.Option(
        Path("config.yaml"), "--config", help="Used only to look up the verifier model name",
    ),
) -> None:
    """Scan a file or directory and produce a findings report."""
    if format not in _VALID_FORMATS:
        console.print(f"[red]--format must be one of {_VALID_FORMATS} (got '{format}').[/red]")
        raise typer.Exit(code=1)

    if alpha is not None:
        console.print(
            "[red]--alpha is not implemented yet[/red] -- overriding the certified "
            "threshold requires recomputing it from the calibration trace against a "
            "real corpus, deferred until Track A lands (see docs/ENGINEERING_LOG.md, "
            "section 6). Re-run `codegate calibrate` if you need a different alpha."
        )
        raise typer.Exit(code=2)

    verifier_model: str | None = None
    verifier_backend = None
    if not no_llm:
        try:
            verifier_model = load_config(str(config)).verifier
        except FileNotFoundError:
            verifier_model = None  # no config.yaml in this directory -- scan still runs, just without LLM verification
        if verifier_model is not None:
            verifier_backend = build_verifier_backend(verifier_model)

    try:
        result = run_scan(path, model_dir=model_dir, verifier=verifier_backend)
    except (FileNotFoundError, ArtifactVersionError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    if format == "terminal":
        render_terminal(result, path, console, verifier_model)
    elif format == "json":
        text = to_json(result, path, verifier_model)
        if output is not None:
            output.write_text(text)
            console.print(f"Wrote {output}")
        else:
            print(text)  # not console.print -- rich would line-wrap and markup-parse the JSON
    elif format == "sarif":
        text = to_sarif(result, path)
        if output is not None:
            output.write_text(text)
            console.print(f"Wrote {output}")
        else:
            print(text)  # not console.print -- rich would line-wrap and markup-parse the JSON
    elif format == "pdf":
        out_path = output or Path("codegate_report.pdf")
        generate_pdf(result, path, out_path, verifier_model)
        console.print(f"Wrote {out_path}")
