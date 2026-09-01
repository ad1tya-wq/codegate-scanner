from __future__ import annotations
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib

from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker


@dataclass(frozen=True)
class Calibration:
    """The certificate, persisted alongside the model it was calibrated
    against. Every field the scanner needs to state what it guarantees --
    and, via `ranker_id`, to refuse pairing with the wrong model."""
    t_hat: float | None
    alpha: float
    delta: float
    n_vuln_calib: int
    ranker_id: str
    corpus_version: str
    is_provisional: bool
    created_at: str


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
) -> None:
    calib = Calibration(
        t_hat=result.t_hat,
        alpha=result.alpha,
        delta=result.delta,
        n_vuln_calib=result.n_vuln_calib,
        ranker_id=ranker_id,
        corpus_version=corpus_version,
        is_provisional=is_provisional,
        created_at=datetime.now(timezone.utc).isoformat(),
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
