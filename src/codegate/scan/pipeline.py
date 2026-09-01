from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from codegate.oracles.semgrep_oracle import run_semgrep_on_path
from codegate.research.artifacts import Calibration, load_artifacts
from codegate.scan.findings import Finding
from codegate.scan.ingest import SkippedFile, Unit, ingest_path
from codegate.scan.verifier import (
    DEFAULT_CACHE_DIR,
    VerifierBackend,
    is_cached,
    to_finding,
    verify_unit,
)

DEFAULT_MODEL_DIR = Path("data/model")

# Maps this project's own semgrep ruleset (data/semgrep_rules/codegate_rules.yaml)
# to the CWE it targets. A rule ID not in this map is a ruleset/pipeline
# drift bug, not a code-under-scan problem -- surfaced loudly rather than
# silently dropped, same principle as consensus.py's unrecognized-CWE guard.
_RULE_ID_TO_CWE = {
    "codegate-sqli-string-build": "CWE-89",
    "codegate-cmdi-shell-true": "CWE-78",
    "codegate-hardcoded-credential-assignment": "CWE-798",
}

# Short pointer only -- report/remediation.py (Phase 7) supersedes this
# with full hand-written before/after remediation content per CWE.
_SHORT_FIX_HINT = {
    "CWE-89": "Use a parameterized query instead of building SQL by concatenation/formatting.",
    "CWE-78": "Avoid shell=True; pass the command as an argv list with shell=False.",
    "CWE-798": "Load the credential from an environment variable or secret store, not a literal.",
}

_UNSPECIFIED_CWE = "UNSPECIFIED"


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    n_units: int
    n_auto_approved: int
    n_escalated: int
    skipped: list[SkippedFile]
    # Only meaningful when run_scan was given a verifier backend; all of
    # these stay 0 when the LLM step was skipped (--no-llm or no key),
    # which is how a report distinguishes "not attempted" from "attempted,
    # nothing confirmed." tokens_saved/tokens_spent feed
    # report/accounting.py's cost estimate; see _VerificationTally.
    n_verified_confirmed: int = 0
    n_verified_cleared: int = 0
    n_verified_unresolved: int = 0
    n_verifier_cache_hits: int = 0
    n_verifier_calls_made: int = 0
    tokens_saved: int = 0
    tokens_spent: int = 0
    # The certificate this scan ran under -- None only when `units` was
    # empty (nothing to score, so nothing was loaded). Reports render
    # their certificate section from this, not by reloading artifacts.
    calibration: Calibration | None = None


def _base_rule_id(rule_id: str) -> str:
    """
    semgrep prefixes a rule's id with a path-derived namespace when the
    ruleset is loaded from a local file rather than the registry (e.g.
    'data.semgrep_rules.codegate-sqli-string-build' for our ruleset at
    data/semgrep_rules/codegate_rules.yaml). Our own rule ids use hyphens,
    never dots, so the segment after the last '.' recovers the id as
    written in codegate_rules.yaml regardless of the caller's cwd.
    """
    return rule_id.rsplit(".", 1)[-1]


def _map_to_unit(units: list[Unit], file: Path, line: int) -> Unit | None:
    resolved = file.resolve()
    candidates = [
        u for u in units
        if u.file.resolve() == resolved and u.lineno <= line <= u.end_lineno
    ]
    if not candidates:
        return None
    # Nested functions overlap their enclosing function's line range;
    # the innermost (smallest range) is the more specific match.
    return min(candidates, key=lambda u: u.end_lineno - u.lineno)


def _semgrep_findings(target: Path, units: list[Unit]) -> list[Finding]:
    result = run_semgrep_on_path(target)
    findings: list[Finding] = []
    for f in result["findings"]:
        cwe = _RULE_ID_TO_CWE.get(_base_rule_id(f["rule_id"]))
        if cwe is None:
            continue  # unrecognized rule id -- ruleset/pipeline drift, not a scan-target issue
        file_path = Path(f["path"])
        unit = _map_to_unit(units, file_path, f["start_line"])
        findings.append(Finding(
            file=file_path,
            line=f["start_line"],
            func_name=unit.func_name if unit else "<module>",
            cwe=cwe,
            severity=f["severity"],
            source="semgrep",
            confidence=1.0,  # deterministic pattern match
            message=f["message"],
            fix_hint=_SHORT_FIX_HINT.get(cwe, ""),
        ))
    return findings


def _rank_and_gate(
    units: list[Unit], model_dir: Path
) -> tuple[list[tuple[Unit, float]], int, int, Calibration | None]:
    """
    Scores every unit with the loaded ranker and applies the certified
    LTT gate (score >= t_hat -> auto-approve). Returns the units that did
    NOT clear the gate, paired with their score; the auto-approved count;
    and the summed token_estimate of the auto-approved units (an
    auto-approved unit needed zero LLM tokens under the certificate --
    report/accounting.py's savings baseline includes this). t_hat=None
    means the calibration couldn't certify any threshold, so everything
    escalates (see gate/ltt.py::LTTResult's own documented semantics).
    What happens to an escalated unit next (LLM verification, or staying
    a bare "needs review" finding) is `run_scan`'s decision, not this
    function's. Also returns the loaded `Calibration` (None for an empty
    `units` list, since nothing is loaded in that case) so the report can
    render the certificate the scan actually ran under.
    """
    if not units:
        return [], 0, 0, None

    ranker, calib = load_artifacts(model_dir / "model.joblib", model_dir / "calibration.json")

    sample_ids = [f"{u.file}:{u.lineno}:{u.func_name}" for u in units]
    df = pd.DataFrame({"sample_id": sample_ids, "code": [u.source for u in units]})
    scores_df = ranker.score(df)
    score_by_id = dict(zip(scores_df["sample_id"], scores_df["score"]))

    escalated: list[tuple[Unit, float]] = []
    n_auto = 0
    tokens_auto_approved = 0
    for unit, sample_id in zip(units, sample_ids):
        score = float(score_by_id[sample_id])
        if calib.t_hat is not None and score >= calib.t_hat:
            n_auto += 1
            tokens_auto_approved += unit.token_estimate
        else:
            escalated.append((unit, score))
    return escalated, n_auto, tokens_auto_approved, calib


def _needs_review_finding(unit: Unit, score: float) -> Finding:
    """
    The finding for an escalated unit that the LLM verifier either wasn't
    asked about (no backend) or couldn't resolve (call/parse failure).
    `source="model"` because the model's gate, not any LLM, is the reason
    this is being reported at all.
    """
    return Finding(
        file=unit.file,
        line=unit.lineno,
        func_name=unit.func_name,
        cwe=_UNSPECIFIED_CWE,
        severity="REVIEW",
        source="model",
        confidence=round(1.0 - score, 4),
        message=(
            "Not certifiably safe under the current calibration -- "
            "needs LLM verification."
        ),
        fix_hint="",
    )


@dataclass(frozen=True)
class _VerificationTally:
    findings: list[Finding]
    n_confirmed: int
    n_cleared: int
    n_unresolved: int
    n_cache_hits: int
    n_calls_made: int
    tokens_saved: int  # token_estimate of escalated units resolved from cache -- no fresh call needed
    tokens_spent: int  # token_estimate of escalated units that got a fresh call this run


def _resolve_escalated(
    escalated: list[tuple[Unit, float]],
    verifier: VerifierBackend | None,
    cache_dir: Path,
) -> _VerificationTally:
    """
    Attempts to resolve every escalated unit with the verifier. A cleared
    unit produces no finding at all -- the same convention as an
    auto-approved one. `verifier=None` (no key, or --no-llm) resolves
    nothing; every escalated unit falls back to `_needs_review_finding`,
    identical to Phase 5's behavior before Phase 7 wired verification in,
    and every count/token field stays 0.

    Token accounting is the chars/4 estimate already computed at ingest
    time (`Unit.token_estimate`), attributed to "spent" for any cache
    miss regardless of whether the response ultimately parsed -- the API
    call itself is what costs money, not just a successfully parsed one.
    """
    findings: list[Finding] = []
    n_confirmed = n_cleared = n_unresolved = n_cache_hits = n_calls_made = 0
    tokens_saved = tokens_spent = 0
    for unit, score in escalated:
        if verifier is None:
            findings.append(_needs_review_finding(unit, score))
            continue

        cached = is_cached(unit.content_hash, cache_dir)
        if cached:
            n_cache_hits += 1
            tokens_saved += unit.token_estimate
        else:
            n_calls_made += 1
            tokens_spent += unit.token_estimate

        result = verify_unit(unit, verifier, cache_dir)
        if result is None:
            n_unresolved += 1
            findings.append(_needs_review_finding(unit, score))
        elif result.vulnerable:
            n_confirmed += 1
            findings.append(to_finding(unit, result))
        else:
            n_cleared += 1
    return _VerificationTally(
        findings=findings,
        n_confirmed=n_confirmed,
        n_cleared=n_cleared,
        n_unresolved=n_unresolved,
        n_cache_hits=n_cache_hits,
        n_calls_made=n_calls_made,
        tokens_saved=tokens_saved,
        tokens_spent=tokens_spent,
    )


def run_scan(
    path: Path,
    model_dir: Path = DEFAULT_MODEL_DIR,
    verifier: VerifierBackend | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> ScanResult:
    """
    ingest -> static (one semgrep invocation over the whole target) ->
    rank -> gate -> (optional) LLM verification of escalated units.

    Hard invariant: no dynamic oracle runs on this path. The research
    half's detonation oracles (oracles/sandbox.py) execute code
    specifically because they're judging LLM-generated snippets under
    controlled conditions -- this function scans arbitrary user code, and
    executing it would mean running code the scanner has no business
    running (see docs/ENGINEERING_LOG.md decision #2). Nothing here
    imports oracles.sandbox, sqli_oracle, or cmdi_oracle.

    `verifier=None` (the default -- also what --no-llm or a missing
    GROQ_API_KEY produce, see scan/verifier.py::build_verifier_backend)
    skips LLM verification entirely: escalated units are reported as
    "needs review" and every n_verified_* count on the result stays 0.
    """
    path = Path(path)
    ingest_result = ingest_path(path)
    units = ingest_result.units

    semgrep_findings = _semgrep_findings(path, units)
    escalated, n_auto, tokens_auto_approved, calib = _rank_and_gate(units, model_dir)
    tally = _resolve_escalated(escalated, verifier, cache_dir)

    findings = sorted(semgrep_findings + tally.findings, key=lambda f: (str(f.file), f.line))
    return ScanResult(
        findings=findings,
        n_units=len(units),
        n_auto_approved=n_auto,
        n_escalated=len(escalated),
        skipped=ingest_result.skipped,
        n_verified_confirmed=tally.n_confirmed,
        n_verified_cleared=tally.n_cleared,
        n_verified_unresolved=tally.n_unresolved,
        n_verifier_cache_hits=tally.n_cache_hits,
        n_verifier_calls_made=tally.n_calls_made,
        tokens_saved=tokens_auto_approved + tally.tokens_saved,
        tokens_spent=tally.tokens_spent,
        calibration=calib,
    )
