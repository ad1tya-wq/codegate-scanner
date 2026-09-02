#!/usr/bin/env python
"""
Labels and trains on an already-generated corpus (a real Ollama run
someone else shipped back as generations.parquet), skipping the
generation step entirely.

This is the receiving half of docs/OLLAMA_SETUP.md's "host runs
generation, ships back generations.parquet" workflow -- the sending half
(--generate-only) already existed; this script is what actually consumes
the result. See research/pipeline.py::run_full_pipeline's
`pregenerated_df` parameter.

    python scripts/train_from_pregenerated.py data/runs/real_540/generations.parquet
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd

from codegate.config import load_config
from codegate.research.pipeline import run_full_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generations_path", help="Path to a generations.parquet from a real run")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out-dir", default="data/model")
    args = parser.parse_args()

    cfg = load_config(args.config)
    gen_df = pd.read_parquet(args.generations_path)
    print(f"Loaded {len(gen_df)} pregenerated samples from {args.generations_path}")

    # backends is unused on the pregenerated_df path (generation is
    # skipped entirely) -- only its length is printed for the summary
    # line, so a name-keyed dummy dict keeps that line accurate without
    # needing real Backend instances.
    backends = {name: None for name in cfg.generators}

    summary = run_full_pipeline(
        cfg, prompts=[], backends=backends,
        is_simulated=False, out_dir=Path(args.out_dir),
        use_semgrep_and_adjudicator=True,
        pregenerated_df=gen_df,
    )
    print()
    print("Summary:", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
