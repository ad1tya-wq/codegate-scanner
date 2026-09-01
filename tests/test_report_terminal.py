import io
from pathlib import Path

from rich.console import Console

from codegate.report.terminal import render_terminal
from codegate.research.artifacts import Calibration
from codegate.scan.findings import Finding
from codegate.scan.pipeline import ScanResult


def _render(result: ScanResult) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=120)
    render_terminal(result, Path("app"), console)
    return buf.getvalue()


def test_render_terminal_shows_no_findings_message_when_clean():
    result = ScanResult(findings=[], n_units=3, n_auto_approved=3, n_escalated=0, skipped=[])
    output = _render(result)
    assert "No findings" in output


def test_render_terminal_lists_each_finding():
    finding = Finding(
        file=Path("app/db.py"), line=4, func_name="get_user", cwe="CWE-89",
        severity="ERROR", source="semgrep", confidence=1.0,
        message="SQL built by concatenation.", fix_hint="Parameterize the query.",
    )
    result = ScanResult(findings=[finding], n_units=1, n_auto_approved=0, n_escalated=1, skipped=[])
    output = _render(result)
    assert "get_user" in output
    assert "CWE-89" in output


def test_render_terminal_shows_provisional_banner():
    calib = Calibration(
        t_hat=0.5, alpha=0.05, delta=0.05, n_vuln_calib=10, ranker_id="R2",
        corpus_version="simulated-v2", is_provisional=True, created_at="2026-08-31T00:00:00+00:00",
    )
    result = ScanResult(findings=[], n_units=1, n_auto_approved=1, n_escalated=0, skipped=[], calibration=calib)
    output = _render(result)
    assert "PROVISIONAL" in output


def test_render_terminal_omits_certificate_section_when_none():
    result = ScanResult(findings=[], n_units=0, n_auto_approved=0, n_escalated=0, skipped=[], calibration=None)
    output = _render(result)
    assert "Certificate" not in output
