from __future__ import annotations
import json
import math
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker


class UncertifiedAlphaError(ValueError):
    """The requested alpha has no certified threshold in this calibration."""

    def __init__(self, alpha: float, certified: list[float]):
        self.alpha = alpha
        self.certified = certified
        super().__init__(
            f"alpha={alpha} has no certified threshold in this calibration. "
            f"Certified alphas: {certified or 'none'}."
        )


@dataclass(frozen=True)
class Calibration:
    """The certificate, persisted alongside the model it was calibrated
    against. Every field the scanner needs to state what it guarantees --
    and, via `ranker_id`, to refuse pairing with the wrong model.

    `frontier` holds one {alpha, t_hat, coverage} row per alpha that LTT was
    run at on the same calibration split, which is what makes scan-time
    `--alpha` possible. It defaults to empty so calibration.json files
    written before it existed still load."""
    t_hat: float | None
    alpha: float
    delta: float
    n_vuln_calib: int
    ranker_id: str
    corpus_version: str
    is_provisional: bool
    created_at: str
    frontier: list[dict] = field(default_factory=list)
    # Which LTT test produced t_hat: "cluster-hb" (task groups are the unit of
    # evidence) or "sample-binomial" (each sample is). Files written before
    # this field existed were all sample-binomial.
    method: str = "sample-binomial"
    n_vuln_groups: int | None = None

    def method_description(self) -> str:
        """How t_hat was certified, in words, for reports."""
        if self.method == "cluster-hb":
            return f"cluster-aware: {self.n_vuln_groups} task groups (Hoeffding-Bentkus)"
        return "per-sample binomial"

    def certified_alphas(self) -> list[float]:
        alphas = {row["alpha"] for row in self.frontier if row.get("t_hat") is not None}
        if self.t_hat is not None:
            alphas.add(self.alpha)
        return sorted(alphas)

    def at_alpha(self, alpha: float) -> "Calibration":
        """
        This certificate restated at `alpha`: the same calibration with that
        alpha's own LTT threshold. Raises UncertifiedAlphaError unless LTT
        actually certified a threshold at exactly that alpha -- never
        interpolates between certified alphas, since an interpolated
        threshold carries no guarantee at all.

        Each alpha's certificate holds individually at confidence 1 - delta.
        The guarantee assumes the alpha is chosen before seeing scan
        results, not tuned against them.
        """
        if math.isclose(alpha, self.alpha):
            return self
        for row in self.frontier:
            if math.isclose(row["alpha"], alpha) and row.get("t_hat") is not None:
                return replace(self, alpha=row["alpha"], t_hat=row["t_hat"])
        raise UncertifiedAlphaError(alpha, self.certified_alphas())


class ArtifactVersionError(ValueError):
    """A calibration.json's ranker_id doesn't match the loaded model's."""


def save_model(ranker: R2Ranker, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(ranker, path)


def load_model(path: Path) -> R2Ranker:
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. Run `codegate calibrate` first."
        )
    ranker = joblib.load(path)
    if not isinstance(ranker, R2Ranker):
        raise TypeError(f"{path} does not contain an R2Ranker (got {type(ranker).__name__})")
    return ranker


def save_calibration(
    result: LTTResult,
    path: Path,
    corpus_version: str,
    is_provisional: bool,
    ranker_id: str = R2Ranker.RANKER_ID,
    frontier: pd.DataFrame | None = None,
) -> None:
    rows = []
    if frontier is not None:
        for rec in frontier.to_dict("records"):
            t = rec.get("t_hat")
            # compute_frontier's uncertified None becomes NaN inside a float
            # column; JSON needs it back as null.
            if t is None or (isinstance(t, float) and math.isnan(t)):
                t = None
            rows.append({"alpha": float(rec["alpha"]), "t_hat": None if t is None else float(t),
                         "coverage": float(rec["coverage"])})
    calib = Calibration(
        t_hat=result.t_hat,
        alpha=result.alpha,
        delta=result.delta,
        n_vuln_calib=result.n_vuln_calib,
        ranker_id=ranker_id,
        corpus_version=corpus_version,
        is_provisional=is_provisional,
        created_at=datetime.now(timezone.utc).isoformat(),
        frontier=rows,
        method=result.method,
        n_vuln_groups=result.n_vuln_groups,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(calib), indent=2))


def load_calibration(path: Path) -> Calibration:
    if not path.exists():
        raise FileNotFoundError(
            f"No calibration at {path}. Run `codegate calibrate` first."
        )
    return Calibration(**json.loads(path.read_text()))


def load_artifacts(model_path: Path, calibration_path: Path) -> tuple[R2Ranker, Calibration]:
    """
    Load the model and its calibration together, and refuse the pair if the
    calibration wasn't produced for this model's ranker contract. Loading
    them independently (via `load_model`/`load_calibration`) skips this
    check -- use this function wherever both are needed for scoring, i.e.
    everywhere except tests of the individual save/load round trips.
    """
    ranker = load_model(model_path)
    calib = load_calibration(calibration_path)
    if calib.ranker_id != ranker.RANKER_ID:
        raise ArtifactVersionError(
            f"{calibration_path} was calibrated for ranker '{calib.ranker_id}', "
            f"but {model_path} is a '{ranker.RANKER_ID}' model. Recalibrate: "
            f"`codegate calibrate`."
        )
    return ranker, calib
