from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

# Where a finding came from -- this is what makes the report's detection
# attribution breakdown possible (semgrep vs model-escalated vs
# LLM-confirmed vs auto-approved).
_VALID_SOURCES = ("semgrep", "model", "verifier")


@dataclass(frozen=True)
class Finding:
    file: Path
    line: int
    func_name: str
    cwe: str
    severity: str
    source: str
    confidence: float
    message: str
    fix_hint: str

    def __post_init__(self) -> None:
        if self.source not in _VALID_SOURCES:
            raise ValueError(f"Finding.source must be one of {_VALID_SOURCES}, got '{self.source}'")
