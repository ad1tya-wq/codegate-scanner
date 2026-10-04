#!/usr/bin/env python
"""
Re-label an already-generated corpus with the current oracles.

Generation is the expensive half (hours on a teammate's laptop); labelling
is minutes. When the oracles change, this measures the effect against real
data without regenerating anything.

    python scripts/relabel.py \
        --generations data/runs/real_540/generations.parquet \
        --out-dir data/runs/real_540_relabeled

Never point --out-dir at data/model/: that directory holds the shipped
artifacts, and an exploratory run has overwritten them before (see
docs/ENGINEERING_LOG.md section 11).
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from codegate.research.pipeline import (  # noqa: E402
    LABEL_ABSTAIN,
    LABEL_VULNERABLE,
    label_summary,
    relabel,
)

# LTT cannot certify any threshold at alpha=0.05, delta=0.05 with fewer than
# 59 vulnerable calibration samples, even if none of them score above t_hat:
# binom.cdf(0, n, 0.05) <= 0.05 first holds at n = 59.
_MIN_VULN_CALIB_FOR_ALPHA_05 = 59


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generations", required=True,
                        help="path to an existing generations.parquet")
    parser.add_argument("--out-dir", required=True,
                        help="where to write labeled.parquet (never data/model/)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    if out_dir.resolve() == (Path(__file__).resolve().parents[1] / "data" / "model").resolve():
        raise SystemExit(
            "\nERROR: refusing to write to data/model/ -- that holds the shipped\n"
            "  artifacts. Use a scratch directory under data/runs/ instead.\n"
        )

    gen_df = pd.read_parquet(args.generations)
    labeled = relabel(gen_df)

    out_dir.mkdir(parents=True, exist_ok=True)
    labeled.to_parquet(out_dir / "labeled.parquet")

    n = len(labeled)
    n_abstain = int((labeled["label"] == LABEL_ABSTAIN).sum())
    decided = labeled[labeled["label"] != LABEL_ABSTAIN]
    n_vuln = int((decided["label"] == LABEL_VULNERABLE).sum())

    print(f"samples             : {n}")
    print(f"abstentions         : {n_abstain} ({n_abstain / max(n, 1):.1%})")
    print(f"vulnerable (decided): {n_vuln} ({n_vuln / max(len(decided), 1):.1%})")
    print()
    print(label_summary(gen_df, labeled).to_string())

    merged = gen_df.merge(labeled[["sample_id", "label"]], on="sample_id")
    n_vuln_calib = int(
        ((merged["split"] == "calib") & (merged["label"] == LABEL_VULNERABLE)).sum()
    )
    verdict = "OK" if n_vuln_calib >= _MIN_VULN_CALIB_FOR_ALPHA_05 else "SHORT"
    print()
    print(f"n_vuln_calib        : {n_vuln_calib}  "
          f"(need >= {_MIN_VULN_CALIB_FOR_ALPHA_05} to certify alpha=0.05 at all) "
          f"-> {verdict}")
    print(f"artifacts written   : {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
