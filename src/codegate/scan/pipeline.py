from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from codegate.oracles.semgrep_oracle import run_semgrep_on_path
from codegate.research.artifacts import load_artifacts
from codegate.scan.findings import Finding
from codegate.scan.ingest import SkippedFile, Unit, ingest_path

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


def _rank_and_gate(units: list[Unit], model_dir: Path) -> tuple[list[Finding], int, int]:
    """
    Scores every unit with the loaded ranker and applies the certified
    LTT gate (score >= t_hat -> auto-approve). Escalated units become
    `source="model"` findings, unconfirmed -- Phase 6's verifier (or a
    human, under --no-llm) resolves them. t_hat=None means the
    calibration couldn't certify any threshold, so everything escalates
    (see gate/ltt.py::LTTResult's own documented semantics).
    """
    if not units:
        return [], 0, 0

    ranker, calib = load_artifacts(model_dir / "model.joblib", model_dir / "calibration.json")

    sample_ids = [f"{u.file}:{u.lineno}:{u.func_name}" for u in units]
    df = pd.DataFrame({"sample_id": sample_ids, "code": [u.source for u in units]})
    scores_df = ranker.score(df)
    score_by_id = dict(zip(scores_df["sample_id"], scores_df["score"]))

    findings: list[Finding] = []
    n_auto = 0
    n_escalated = 0
    for unit, sample_id in zip(units, sample_ids):
        score = float(score_by_id[sample_id])
        auto_approved = calib.t_hat is not None and score >= calib.t_hat
        if auto_approved:
            n_auto += 1
            continue

        n_escalated += 1
        findings.append(Finding(
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
        ))
    return findings, n_auto, n_escalated


def run_scan(path: Path, model_dir: Path = DEFAULT_MODEL_DIR) -> ScanResult:
    """
    ingest -> static (one semgrep invocation over the whole target) ->
    rank -> gate.

    Hard invariant: no dynamic oracle runs on this path. The research
    half's detonation oracles (oracles/sandbox.py) execute code
    specifically because they're judging LLM-generated snippets under
    controlled conditions -- this function scans arbitrary user code, and
    executing it would mean running code the scanner has no business
    running (see docs/ENGINEERING_LOG.md decision #2). Nothing here
    imports oracles.sandbox, sqli_oracle, or cmdi_oracle.
    """
    path = Path(path)
    ingest_result = ingest_path(path)
    units = ingest_result.units

    semgrep_findings = _semgrep_findings(path, units)
    model_findings, n_auto, n_escalated = _rank_and_gate(units, model_dir)

    findings = sorted(semgrep_findings + model_findings, key=lambda f: (str(f.file), f.line))
    return ScanResult(
        findings=findings,
        n_units=len(units),
        n_auto_approved=n_auto,
        n_escalated=n_escalated,
        skipped=ingest_result.skipped,
    )
