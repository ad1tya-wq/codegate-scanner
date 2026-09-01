from __future__ import annotations
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Protocol

import requests

from codegate.env import get_env
from codegate.scan.findings import Finding
from codegate.scan.ingest import Unit

DEFAULT_CACHE_DIR = Path(".codegate_cache")

# config.yaml's `verifier` field names a role, not necessarily the literal
# model string an API expects. Maps known role names to the real Groq
# model id -- kept as an explicit table (not a guess baked into the
# backend) so a future model rename is a one-line change here.
_GROQ_MODEL_IDS = {
    "llama-3.3-70b-groq": "llama-3.3-70b-versatile",
}

_SYSTEM_PROMPT = (
    "You are a security code reviewer. You will be shown one Python "
    "function. Decide whether it is vulnerable to CWE-89 (SQL injection "
    "via string-built queries), CWE-78 (OS command injection via "
    "shell=True or similar), or CWE-798 (a hardcoded credential literal). "
    "Respond with ONLY a JSON object and nothing else, in this exact "
    'shape: {"vulnerable": true or false, "cwe": one of "CWE-89", '
    '"CWE-78", "CWE-798", or null if not vulnerable, "line": the line '
    "number of the vulnerable statement within the shown function (1 for "
    'the first line) or null, "reason": a one-sentence explanation, '
    '"fix_hint": a one-sentence remediation, or an empty string if not '
    "vulnerable}."
)

_VALID_CWES = ("CWE-89", "CWE-78", "CWE-798")


class VerifierBackend(Protocol):
    def ask(self, code: str) -> str:
        """Return the raw LLM completion text for one code-review prompt."""
        ...


@dataclass(frozen=True)
class VerifierResult:
    vulnerable: bool
    cwe: str | None
    line: int | None
    reason: str
    fix_hint: str


class GroqVerifierBackend:
    """
    Real verifier backend: Groq's OpenAI-compatible chat completions API.
    Same request shape as research/generation/backends.py::GroqBackend, but
    a distinct minimal interface (`ask(code) -> str`, not
    `generate(Prompt, seed) -> str`) -- verification sends a code snippet
    and expects a structured JSON verdict back, not a code-generation task,
    so reusing the Backend ABC directly would mean forcing a Prompt object
    where none exists.
    """

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    def ask(self, code: str) -> str:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "model": self._model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": code},
                ],
                "temperature": 0,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def build_verifier_backend(model: str) -> VerifierBackend | None:
    """
    Returns a ready-to-use verifier backend, or None if GROQ_API_KEY isn't
    set. None is not an error here -- the scanner must degrade cleanly
    without a key (static + ranker + gate still produce a full report;
    escalated units just stay unconfirmed) rather than refuse to run.
    """
    api_key = get_env("GROQ_API_KEY", "")
    if not api_key:
        return None
    return GroqVerifierBackend(api_key=api_key, model=_GROQ_MODEL_IDS.get(model, model))


def _parse_verdict(raw: str) -> VerifierResult | None:
    """
    Extracts and validates the JSON verdict from a raw completion. Returns
    None -- never raises -- on any parse or shape failure: a model that
    doesn't obey the requested format is exactly as untrustworthy as one
    that answers "not vulnerable" incorrectly, and both must degrade to
    "needs review" rather than crash the scan or silently pass through
    unvalidated data.
    """
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match is None:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    if not isinstance(data.get("vulnerable"), bool):
        return None

    cwe = data.get("cwe")
    if cwe not in _VALID_CWES:
        cwe = None

    line = data.get("line")
    if not isinstance(line, int):
        line = None

    return VerifierResult(
        vulnerable=data["vulnerable"],
        cwe=cwe,
        line=line,
        reason=str(data.get("reason") or ""),
        fix_hint=str(data.get("fix_hint") or ""),
    )


def _cache_path(cache_dir: Path, content_hash: str) -> Path:
    return cache_dir / f"{content_hash}.json"


def _load_cached(cache_dir: Path, content_hash: str) -> VerifierResult | None:
    path = _cache_path(cache_dir, content_hash)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    try:
        return VerifierResult(**data)
    except TypeError:
        return None


def _save_cache(cache_dir: Path, content_hash: str, result: VerifierResult) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    _cache_path(cache_dir, content_hash).write_text(json.dumps(asdict(result)))


def verify_unit(
    unit: Unit,
    backend: VerifierBackend | None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> VerifierResult | None:
    """
    Resolves one escalated unit with at most one LLM call, cached by
    `content_hash` so re-scanning unchanged code costs zero calls. Returns
    None when there's no backend (no key -- see `build_verifier_backend`),
    the call fails (network/HTTP error), or the response can't be parsed
    into a verdict. Callers must treat None as "needs review", never as
    "confirmed safe" -- an unresolved escalation is not a cleared one.
    """
    cached = _load_cached(cache_dir, unit.content_hash)
    if cached is not None:
        return cached

    if backend is None:
        return None

    try:
        raw = backend.ask(unit.source)
    except (requests.RequestException, KeyError, IndexError, ValueError):
        return None

    result = _parse_verdict(raw)
    if result is None:
        return None

    _save_cache(cache_dir, unit.content_hash, result)
    return result


def to_finding(unit: Unit, result: VerifierResult) -> Finding:
    """
    Turns a confirmed-vulnerable VerifierResult into a source="verifier"
    Finding. Callers only call this when `result.vulnerable` is True --
    a cleared unit produces no finding at all, same as an auto-approved one.
    """
    return Finding(
        file=unit.file,
        line=result.line if result.line is not None else unit.lineno,
        func_name=unit.func_name,
        cwe=result.cwe or "UNSPECIFIED",
        severity="ERROR",
        source="verifier",
        confidence=1.0,
        message=result.reason or "LLM verifier confirmed this is vulnerable.",
        fix_hint=result.fix_hint,
    )
