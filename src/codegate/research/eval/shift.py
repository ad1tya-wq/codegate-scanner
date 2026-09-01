from __future__ import annotations
from dataclasses import dataclass
import numpy as np
from codegate.gate.ltt import calibrate_threshold
from codegate.gate.risk import empirical_risk


@dataclass(frozen=True)
class ShiftResult:
    held_out_generator: str
    t_hat: float | None
    certified_alpha: float
    realized_risk_on_held_out: float
    certificate_held: bool


def run_shift_experiment(
    scores_by_generator: dict[str, np.ndarray],
    labels_by_generator: dict[str, np.ndarray],
    held_out: str,
    alpha: float,
    delta: float,
) -> ShiftResult:
    """
    Calibrate the LTT threshold on every generator EXCEPT `held_out`, pooled
    together, then measure the realized risk on `held_out`'s own data. This
    is the headline "does the certificate survive a generator switch"
    experiment (spec section 5).
    """
    calib_generators = [g for g in scores_by_generator if g != held_out]
    if not calib_generators:
        raise ValueError("need at least one non-held-out generator to calibrate on")

    calib_scores = np.concatenate([scores_by_generator[g] for g in calib_generators])
    calib_labels = np.concatenate([labels_by_generator[g] for g in calib_generators])

    result = calibrate_threshold(calib_scores, calib_labels, alpha=alpha, delta=delta)

    if result.t_hat is None:
        return ShiftResult(held_out, None, alpha, float("nan"), certificate_held=False)

    realized = empirical_risk(scores_by_generator[held_out], labels_by_generator[held_out], result.t_hat)
    return ShiftResult(
        held_out_generator=held_out,
        t_hat=result.t_hat,
        certified_alpha=alpha,
        realized_risk_on_held_out=realized,
        certificate_held=bool(realized <= alpha),
    )
