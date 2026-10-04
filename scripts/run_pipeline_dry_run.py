#!/usr/bin/env python
"""
End-to-end CodeGate dry run on the SimulatedBackend. Exercises every stage
of the real pipeline (see codegate.pipeline.run_full_pipeline) -- generation,
oracle labeling, consensus, ranking, LTT calibration, cost-coverage frontier,
generator-shift experiment -- using deterministic offline code generation
instead of real LLM API calls, so it runs with zero network access and zero
API keys.

See scripts/run_real.py for the real-backend counterpart, which shares this
same pipeline logic.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codegate.config import load_config
from codegate.research.corpus.prompts import load_prompt_bank
from codegate.research.generation.backends import SimulatedBackend, stable_seed
from codegate.research.pipeline import run_full_pipeline


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="data/runs/dry_run")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    prompts = load_prompt_bank(cfg.prompts_dir)
    print(f"Loaded {len(prompts)} prompts across {len(cfg.cwes)} CWEs")

    backends = {name: SimulatedBackend(name=name, seed=stable_seed(name)) for name in cfg.generators}

    summary = run_full_pipeline(
        cfg, prompts, backends, is_simulated=True, out_dir=Path(args.out_dir),
    )

    print("\n=== CODEGATE DRY RUN SUMMARY ===")
    print(f"Snippets generated : {summary['n_generated']} (SIMULATED -- swap backends for real data)")
    print(f"Vulnerable rate    : {summary['vuln_rate']:.2%}")
    print(f"Calibration n_vuln : {summary['n_vuln_calib']}")
    print(f"Shift experiments  : {summary['n_shift_experiments']} generator(s) held out")
    print(f"Artifacts written  : {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
