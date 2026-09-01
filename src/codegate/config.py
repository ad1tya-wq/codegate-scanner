from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass(frozen=True)
class CodeGateConfig:
    alpha: float
    delta: float
    random_seed: int
    cwes: list[str]
    flavors: list[str]
    generators: list[str]
    adjudicator: str
    verifier: str
    samples_per_prompt: int
    prompts_per_cwe: int
    split_ratios: dict[str, float]
    prompts_dir: str
    fixtures_dir: str
    runs_dir: str


def load_config(path: str = "config.yaml") -> CodeGateConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = yaml.safe_load(p.read_text())

    if raw["adjudicator"] in raw["generators"]:
        raise ValueError(
            f"role-reuse violation: adjudicator '{raw['adjudicator']}' "
            f"also appears in generators {raw['generators']}"
        )

    ratios = raw["split_ratios"]
    total = sum(ratios.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"split_ratios must sum to 1.0, got {total}")

    paths = raw["paths"]
    return CodeGateConfig(
        alpha=raw["alpha"],
        delta=raw["delta"],
        random_seed=raw["random_seed"],
        cwes=list(raw["cwes"]),
        flavors=list(raw["flavors"]),
        generators=list(raw["generators"]),
        adjudicator=raw["adjudicator"],
        verifier=raw["verifier"],
        samples_per_prompt=raw["samples_per_prompt"],
        prompts_per_cwe=raw["prompts_per_cwe"],
        split_ratios=dict(ratios),
        prompts_dir=paths["prompts_dir"],
        fixtures_dir=paths["fixtures_dir"],
        runs_dir=paths["runs_dir"],
    )
