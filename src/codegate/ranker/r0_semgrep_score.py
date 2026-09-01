from __future__ import annotations
import pandas as pd
from codegate.oracles.semgrep_oracle import run_semgrep

_SEVERITY_WEIGHTS = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def score_r0(generations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Cheapest ranker: run semgrep, turn finding count/severity into a
    monotone danger score, negate to a safety score (higher = safer) so it
    matches the ranker convention used by the LTT gate.

    NOTE (perf): each semgrep CLI invocation costs ~1-10s of process
    startup. Calling this row-by-row does not scale past a few hundred
    samples -- see NEEDS_FROM_YOU.md "batch semgrep calls" for the fix
    needed before running R0 over the full ~2,200-sample corpus.
    """
    rows = []
    for _, row in generations_df.iterrows():
        result = run_semgrep(row["code"])
        danger = sum(_SEVERITY_WEIGHTS.get(f["severity"], 1) for f in result["findings"])
        safety_score = -float(danger)
        rows.append({"sample_id": row["sample_id"], "ranker_id": "R0", "score": safety_score})
    return pd.DataFrame(rows)
