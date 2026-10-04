import json
from pathlib import Path

from codegate.report.json_sarif import to_json, to_sarif
from codegate.research.artifacts import Calibration
from codegate.scan.findings import Finding
from codegate.scan.ingest import SkippedFile
from codegate.scan.pipeline import ScanResult


def _calibration() -> Calibration:
    return Calibration(
        t_hat=0.66, alpha=0.05, delta=0.05, n_vuln_calib=42, ranker_id="R2",
        corpus_version="simulated-v2", is_provisional=True, created_at="2026-08-31T00:00:00+00:00",
    )


def _result() -> ScanResult:
    findings = [
        Finding(
            file=Path("app/db.py"), line=4, func_name="get_user", cwe="CWE-89",
            severity="ERROR", source="semgrep", confidence=1.0,
            message="SQL built by concatenation.", fix_hint="Parameterize the query.",
        ),
        Finding(
            file=Path("app/util.py"), line=10, func_name="handler", cwe="UNSPECIFIED",
            severity="REVIEW", source="model", confidence=0.4,
            message="Not certifiably safe -- needs LLM verification.", fix_hint="",
        ),
    ]
    skipped = [SkippedFile(file=Path("app/broken.py"), reason="syntax error")]
    return ScanResult(
        findings=findings, n_units=5, n_auto_approved=3, n_escalated=2, skipped=skipped,
        n_verified_confirmed=0, n_verified_cleared=0, n_verified_unresolved=1,
        n_verifier_cache_hits=0, n_verifier_calls_made=1, tokens_saved=120, tokens_spent=80,
        calibration=_calibration(),
    )


def test_to_json_round_trips_as_valid_json_with_the_right_counts():
    raw = to_json(_result(), Path("app"))
    payload = json.loads(raw)
    assert payload["summary"]["n_units"] == 5
    assert payload["summary"]["n_findings"] == 2
    assert len(payload["findings"]) == 2
    assert payload["certificate"]["t_hat"] == 0.66
    assert payload["certificate"]["is_provisional"] is True
    assert payload["cost"]["is_estimate"] is True


def test_to_json_certificate_is_null_when_scan_result_has_none():
    result = _result()
    result_no_calib = ScanResult(
        findings=result.findings, n_units=result.n_units, n_auto_approved=result.n_auto_approved,
        n_escalated=result.n_escalated, skipped=result.skipped, calibration=None,
    )
    payload = json.loads(to_json(result_no_calib, Path("app")))
    assert payload["certificate"] is None


def test_to_sarif_is_valid_sarif_2_1_0_shape():
    payload = json.loads(to_sarif(_result(), Path("app")))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "CodeGate"
    assert len(run["results"]) == 2


def test_to_sarif_maps_severity_to_sarif_levels():
    payload = json.loads(to_sarif(_result(), Path("app")))
    results = payload["runs"][0]["results"]
    error_result = next(r for r in results if r["ruleId"] == "CWE-89")
    review_result = next(r for r in results if r["ruleId"] == "UNSPECIFIED")
    assert error_result["level"] == "error"
    assert review_result["level"] == "note"


def test_to_sarif_locations_use_posix_paths_and_the_finding_line():
    payload = json.loads(to_sarif(_result(), Path("app")))
    loc = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/db.py"
    assert loc["region"]["startLine"] == 4


def test_to_sarif_rules_cover_every_tracked_cwe_plus_unspecified():
    payload = json.loads(to_sarif(_result(), Path("app")))
    rule_ids = {r["id"] for r in payload["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"CWE-89", "CWE-78", "CWE-798", "UNSPECIFIED"}


def test_to_json_certificate_names_its_method():
    calib = Calibration(
        t_hat=0.83, alpha=0.10, delta=0.05, n_vuln_calib=206, ranker_id="R2",
        corpus_version="real-2040-sym", is_provisional=False, created_at="2026-10-04T00:00:00+00:00",
        method="cluster-hb", n_vuln_groups=66,
    )
    r = _result()
    r = ScanResult(**{**r.__dict__, "calibration": calib})
    cert = json.loads(to_json(r, Path("target")))["certificate"]
    assert cert["method"] == "cluster-hb" and cert["n_vuln_groups"] == 66
