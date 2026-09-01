from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

from codegate import __version__
from codegate.report.accounting import CostSummary, compute_cost_summary
from codegate.report.remediation import get_remediation
from codegate.scan.pipeline import ScanResult

# SARIF severity is one of "error"/"warning"/"note"/"none" -- maps this
# project's own Finding.severity strings onto it. Anything unrecognized
# falls back to "warning" rather than raising, since a report generator
# must always produce valid output for whatever findings a scan handed it.
_SARIF_LEVEL = {
    "ERROR": "error",
    "WARNING": "warning",
    "REVIEW": "note",
}
_TRACKED_CWES = ("CWE-89", "CWE-78", "CWE-798")


def _scanned_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summary_dict(result: ScanResult, cost: CostSummary) -> dict:
    return {
        "n_units": result.n_units,
        "n_auto_approved": result.n_auto_approved,
        "n_escalated": result.n_escalated,
        "n_verified_confirmed": result.n_verified_confirmed,
        "n_verified_cleared": result.n_verified_cleared,
        "n_verified_unresolved": result.n_verified_unresolved,
        "n_skipped_files": len(result.skipped),
        "n_findings": len(result.findings),
        "llm_calls_made": cost.calls_made,
        "llm_calls_avoided": cost.calls_avoided,
    }


def _certificate_dict(result: ScanResult) -> dict | None:
    calib = result.calibration
    if calib is None:
        return None
    return {
        "ranker_id": calib.ranker_id,
        "corpus_version": calib.corpus_version,
        "is_provisional": calib.is_provisional,
        "t_hat": calib.t_hat,
        "alpha": calib.alpha,
        "delta": calib.delta,
        "n_vuln_calib": calib.n_vuln_calib,
    }


def to_json(result: ScanResult, target: Path, verifier_model: str | None = None) -> str:
    """
    Renders a ScanResult as CodeGate's own JSON report shape (not a
    third-party schema -- that's what SARIF is for). Every number here
    traces back to a ScanResult field or CostSummary; nothing is
    recomputed or guessed at render time.
    """
    cost = compute_cost_summary(result, verifier_model)
    payload = {
        "codegate_version": __version__,
        "target": str(target),
        "scanned_at": _scanned_at(),
        "summary": _summary_dict(result, cost),
        "certificate": _certificate_dict(result),
        "cost": {
            "tokens_saved": cost.tokens_saved,
            "tokens_spent": cost.tokens_spent,
            "estimated_cost_usd": cost.estimated_cost_usd,
            "price_per_million_tokens_usd": cost.price_per_million_tokens_usd,
            "is_estimate": cost.is_estimate,
        },
        "findings": [
            {
                "file": str(f.file),
                "line": f.line,
                "func_name": f.func_name,
                "cwe": f.cwe,
                "severity": f.severity,
                "source": f.source,
                "confidence": f.confidence,
                "message": f.message,
                "fix_hint": f.fix_hint,
            }
            for f in result.findings
        ],
        "skipped_files": [{"file": str(s.file), "reason": s.reason} for s in result.skipped],
    }
    return json.dumps(payload, indent=2)


def to_sarif(result: ScanResult, target: Path) -> str:
    """
    Renders a ScanResult as SARIF 2.1.0 (https://sarif-standard.readthedocs.io/),
    the format GitHub code scanning and most CI security tooling consume.
    One rule per tracked CWE (description reused from report/remediation.py
    so the explanation text has exactly one source of truth), plus an
    UNSPECIFIED rule for escalated-but-unconfirmed findings.
    """
    rule_ids = list(_TRACKED_CWES) + ["UNSPECIFIED"]
    rules = [
        {
            "id": cwe,
            "name": get_remediation(cwe).title,
            "shortDescription": {"text": get_remediation(cwe).title},
            "fullDescription": {"text": get_remediation(cwe).explanation},
        }
        for cwe in rule_ids
    ]

    results = [
        {
            "ruleId": f.cwe if f.cwe in rule_ids else "UNSPECIFIED",
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(f.file).as_posix()},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
        }
        for f in result.findings
    ]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeGate",
                    "version": __version__,
                    "informationUri": "https://github.com/ad1tya-wq/codegate-scanner",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
