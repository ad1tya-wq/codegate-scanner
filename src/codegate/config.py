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
    verifier: str
    samples_per_prompt: int
    prompts_per_cwe: int
    prompts_dir: str
    fixtures_dir: str
    runs_dir: str
    certificate: str = "cluster"   # "cluster" (task group = unit of evidence) or "sample"


def load_config(path: str = "config.yaml") -> CodeGateConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = yaml.safe_load(p.read_text())

    # An `adjudicator` key used to be required here and checked against the
    # generator list. Nothing ever called the adjudicator -- its verdict was
    # hard-coded False -- so the key is now ignored if present, like
    # `split_ratios` below.

    # There was a `split_ratios` key here, parsed and validated to sum to
    # 1.0, and read by nothing. Splits are assigned per task group by the
    # `split:` key in each prompt YAML, which is what load_prompt_bank
    # actually reads. Dead config that reads as live is how the hardcoded
    # alpha/delta defect (decision #3) went unnoticed, so it is gone rather
    # than left as documentation of an intention.

    # The certificate's unit of evidence. "cluster" treats each task group as
    # one draw, which stays valid when several models answer the same task;
    # "sample" is the original per-sample binomial test, optimistic under that
    # correlation (docs/cluster-aware-certificate/README.md).
    certificate = raw.get("certificate", "cluster")
    if certificate not in ("cluster", "sample"):
        raise ValueError(f"certificate must be 'cluster' or 'sample', got {certificate!r}")

    paths = raw["paths"]
    return CodeGateConfig(
        alpha=raw["alpha"],
        delta=raw["delta"],
        random_seed=raw["random_seed"],
        cwes=list(raw["cwes"]),
        flavors=list(raw["flavors"]),
        generators=list(raw["generators"]),
        verifier=raw["verifier"],
        samples_per_prompt=raw["samples_per_prompt"],
        prompts_per_cwe=raw["prompts_per_cwe"],
        prompts_dir=paths["prompts_dir"],
        fixtures_dir=paths["fixtures_dir"],
        runs_dir=paths["runs_dir"],
        certificate=certificate,
    )
