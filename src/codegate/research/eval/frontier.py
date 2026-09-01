from __future__ import annotations
import numpy as np
import pandas as pd
from codegate.gate.ltt import calibrate_threshold


def compute_frontier(
    scores: np.ndarray, labels: np.ndarray, alphas: list[float], delta: float
) -> pd.DataFrame:
    """
    For each candidate alpha, certify a threshold via LTT and record the
    coverage it buys. This is the headline cost-coverage curve: coverage ==
    fraction of traffic that never needs an LLM call.
    """
    rows = []
    for alpha in alphas:
        result = calibrate_threshold(scores, labels, alpha=alpha, delta=delta)
        rows.append({
            "alpha": alpha,
            "t_hat": result.t_hat,
            "coverage": result.coverage,
            "n_vuln_calib": result.n_vuln_calib,
        })
    return pd.DataFrame(rows)
