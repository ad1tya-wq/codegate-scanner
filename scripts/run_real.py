#!/usr/bin/env python
"""
Generate and label the real corpus using open models served by Ollama.

Every generator in config.yaml is served by a single Ollama host, so this
runs with ZERO API keys and zero cost. The host may be this machine or a
teammate's -- set OLLAMA_BASE_URL in .env to point at it.

See docs/OLLAMA_SETUP.md for the full two-machine setup.

    python scripts/run_real.py --limit 5 --out-dir data/runs/smoke   # smoke test
    python scripts/run_real.py --out-dir data/runs/real_540          # full run

The run checkpoints after every sample, so it is safe to interrupt and
rerun the same command -- it resumes rather than starting over.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codegate.config import load_config, CodeGateConfig
from codegate.env import get_env
from codegate.research.corpus.prompts import load_prompt_bank
from codegate.research.generation.backends import Backend, OllamaBackend
from codegate.research.generation.harness import run_generation
from codegate.research.pipeline import run_full_pipeline
from codegate.schemas import validate_dataframe

DEFAULT_OLLAMA_URL = "http://localhost:11434"


def preflight(base_url: str, wanted_models: list[str]) -> None:
    """
    Fail fast and legibly if the Ollama host is unreachable or missing a
    model. Without this the run dies hours in, or silently produces garbage.
    """
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    try:
        resp = requests.get(tags_url, timeout=10)
        resp.raise_for_status()
    except requests.exceptions.ConnectTimeout:
        raise SystemExit(
            f"\nERROR: timed out connecting to Ollama at {base_url}\n"
            f"  Most likely the host's firewall is blocking port 11434.\n"
            f"  See docs/OLLAMA_SETUP.md step 4.\n"
        )
    except requests.exceptions.ConnectionError:
        raise SystemExit(
            f"\nERROR: could not connect to Ollama at {base_url}\n"
            f"  Most likely OLLAMA_HOST is still bound to localhost on the host\n"
            f"  machine, or Ollama was not fully quit and relaunched after the\n"
            f"  change. See docs/OLLAMA_SETUP.md step 3.\n"
        )
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"\nERROR: Ollama preflight failed at {base_url}: {exc}\n")

    available = {m["name"] for m in resp.json().get("models", [])}
    # Ollama reports "qwen2.5-coder:7b"; tolerate a bare name matching any tag.
    missing = [
        m for m in wanted_models
        if m not in available and not any(a.split(":")[0] == m.split(":")[0] for a in available)
    ]
    if missing:
        raise SystemExit(
            f"\nERROR: Ollama at {base_url} is missing model(s): {missing}\n"
            f"  Available: {sorted(available) or '(none)'}\n"
            f"  Ask the host to run:  ollama pull {missing[0]}\n"
            f"  Or edit config.yaml's `generators` to match what they actually pulled\n"
            f"  (smaller :1.5b / :3b variants are fine -- see docs/OLLAMA_SETUP.md step 2).\n"
        )

    print(f"[preflight] Ollama reachable at {base_url}; all {len(wanted_models)} models present")


def build_backends(cfg: CodeGateConfig, base_url: str) -> dict[str, Backend]:
    """Every configured generator is an Ollama model on the same host."""
    return {name: OllamaBackend(model=name, base_url=base_url) for name in cfg.generators}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="data/runs/real_540")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only use the first N prompts (for smoke tests)")
    parser.add_argument("--base-url", default=None,
                        help="Ollama host URL; overrides OLLAMA_BASE_URL")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument(
        "--generate-only", action="store_true",
        help="Generate code and stop, without labeling or training. "
             "Labeling runs the dynamic oracles, which EXECUTE the generated "
             "code -- never do that on a machine that is only hosting models. "
             "Use this on the model host, then ship generations.parquet to "
             "whoever runs the rest of the pipeline.",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    base_url = args.base_url or get_env("OLLAMA_BASE_URL", DEFAULT_OLLAMA_URL)

    if not args.skip_preflight:
        preflight(base_url, cfg.generators)

    prompts = load_prompt_bank(cfg.prompts_dir)
    if args.limit is not None:
        prompts = prompts[: args.limit]
    print(f"Loaded {len(prompts)} prompts across {len(cfg.cwes)} CWEs")

    backends = build_backends(cfg, base_url)
    total = len(prompts) * len(backends) * cfg.samples_per_prompt
    print(f"Generators: {list(backends)}")
    print(f"Planned samples: {total}  (resumable -- safe to interrupt and rerun)")

    out_dir = Path(args.out_dir)
    checkpoint = out_dir / "generations.checkpoint.jsonl"

    if args.generate_only:
        # Generation is pure inference against Ollama -- no generated code is
        # ever executed here. That is why this mode is safe to run on someone
        # else's machine, and why the labeling half deliberately stays behind.
        out_dir.mkdir(parents=True, exist_ok=True)
        gen_df = run_generation(
            prompts, backends,
            samples_per_prompt=cfg.samples_per_prompt,
            is_simulated=False,
            checkpoint_path=checkpoint,
        )
        if gen_df.empty:
            raise SystemExit(
                "\nERROR: every generation failed -- nothing was produced.\n"
                "  Ollama is most likely not running, or stopped partway.\n"
                "  Start it, then rerun the exact same command: completed\n"
                "  samples are kept, so you resume rather than start over.\n"
            )

        validate_dataframe(gen_df, "generations")
        out_path = out_dir / "generations.parquet"
        gen_df.to_parquet(out_path)

        print("\n=== GENERATION COMPLETE ===")
        print(f"Samples generated : {len(gen_df)}")
        print(f"Generators        : {sorted(gen_df['generator'].unique())}")
        print(f"Unique snippets   : {gen_df['code'].nunique()}")
        print(f"\nSend this ONE file back:\n  {out_path.resolve()}")
        print("\nNo labeling was performed and no generated code was executed.")
        return 0

    summary = run_full_pipeline(
        cfg, prompts, backends,
        is_simulated=False,
        out_dir=out_dir,
        use_semgrep_and_adjudicator=True,
        checkpoint_path=checkpoint,
    )

    print("\n=== CODEGATE REAL RUN SUMMARY ===")
    print(f"Snippets generated : {summary['n_generated']} (REAL model output)")
    print(f"Vulnerable rate    : {summary['vuln_rate']:.2%}")
    print(f"Calibration n_vuln : {summary['n_vuln_calib']}")
    print(f"Shift experiments  : {summary['n_shift_experiments']} generator(s) held out")
    print(f"Artifacts written  : {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
