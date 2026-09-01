#!/usr/bin/env python
"""
End-to-end CodeGate run on REAL LLM backends (Ollama / OpenRouter / Groq),
sharing the exact same pipeline logic as scripts/run_pipeline_dry_run.py
(see codegate.pipeline.run_full_pipeline) -- generation, oracle labeling,
consensus, ranking, LTT calibration, cost-coverage frontier, generator-shift
experiment.

Requires:
- A .env file at the repo root (copy .env.example) with OPENROUTER_API_KEY,
  GROQ_API_KEY -- see NEEDS_FROM_YOU.md section 1.
- Ollama running locally with `qwen2.5-coder:7b` pulled, for the
  qwen2.5-coder-7b generator.

Does NOT yet call semgrep or an LLM adjudicator during labeling (semgrep is
too slow per-row at corpus scale -- see NEEDS_FROM_YOU.md -- and the
adjudicator's GeminiBackend integration is untested against the live API).
Does NOT implement the escalation-time LLM verifier call (architecture step
5: "confirm/deny" on samples the gate doesn't auto-approve) -- only the
gate's threshold/coverage computation is built. Both are the next pieces
once this script has been run once for real and those gaps are worth
closing.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codegate.config import load_config, CodeGateConfig
from codegate.research.corpus.prompts import load_prompt_bank
from codegate.env import require_env
from codegate.research.generation.backends import Backend, OllamaBackend, OpenRouterBackend, GroqBackend
from codegate.research.pipeline import run_full_pipeline

# Maps each config.yaml generator name to how to build its real Backend.
# OpenRouter model slugs are best-effort as of 2026-08-28 and unverified
# against the live API (no key was available to test with tonight) --
# check https://openrouter.ai/models before relying on them; if a slug is
# wrong, OpenRouterBackend.generate() will raise on the first real call
# with an HTTP error naming the bad model, not silently misbehave.
def _build_backends(cfg: CodeGateConfig) -> dict[str, Backend]:
    backends: dict[str, Backend] = {}
    for name in cfg.generators:
        if name == "qwen2.5-coder-7b":
            backends[name] = OllamaBackend(model="qwen2.5-coder:7b")
        elif name == "deepseek-coder":
            backends[name] = OpenRouterBackend(model="deepseek/deepseek-coder", api_key=require_env("OPENROUTER_API_KEY"))
        elif name == "llama-3.3-70b":
            backends[name] = GroqBackend(model="llama-3.3-70b-versatile", api_key=require_env("GROQ_API_KEY"))
        elif name == "codestral":
            backends[name] = OpenRouterBackend(model="mistralai/codestral-2501", api_key=require_env("OPENROUTER_API_KEY"))
        else:
            raise ValueError(
                f"No real-backend mapping for generator '{name}' in config.yaml -- "
                f"add a branch to _build_backends() in scripts/run_real.py."
            )
    return backends


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="data/runs/real_run")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    prompts = load_prompt_bank(cfg.prompts_dir)
    print(f"Loaded {len(prompts)} prompts across {len(cfg.cwes)} CWEs")

    backends = _build_backends(cfg)
    print(f"Built {len(backends)} real backends: {list(backends.keys())}")

    summary = run_full_pipeline(
        cfg, prompts, backends, is_simulated=False, out_dir=Path(args.out_dir),
        use_semgrep_and_adjudicator=True,
    )

    print("\n=== CODEGATE REAL RUN SUMMARY ===")
    print(f"Snippets generated : {summary['n_generated']} (REAL LLM output)")
    print(f"Vulnerable rate    : {summary['vuln_rate']:.2%}")
    print(f"Calibration n_vuln : {summary['n_vuln_calib']}")
    print(f"Shift experiments  : {summary['n_shift_experiments']} generator(s) held out")
    print(f"Artifacts written  : {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
