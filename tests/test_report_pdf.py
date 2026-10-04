from pathlib import Path

from codegate.report.pdf import _findings_flowables, _highlight, _read_excerpt, _styles, generate_pdf
from codegate.research.artifacts import Calibration
from codegate.scan.findings import Finding
from codegate.scan.ingest import SkippedFile
from codegate.scan.pipeline import ScanResult


def _calibration(is_provisional: bool = True) -> Calibration:
    return Calibration(
        t_hat=0.66, alpha=0.05, delta=0.05, n_vuln_calib=42, ranker_id="R2",
        corpus_version="simulated-v2", is_provisional=is_provisional, created_at="2026-08-31T00:00:00+00:00",
    )


def _result(findings=None, calibration=None) -> ScanResult:
    return ScanResult(
        findings=findings or [], n_units=5, n_auto_approved=3, n_escalated=2,
        skipped=[SkippedFile(file=Path("broken.py"), reason="syntax error")],
        n_verified_confirmed=0, n_verified_cleared=0, n_verified_unresolved=1,
        n_verifier_cache_hits=0, n_verifier_calls_made=1, tokens_saved=120, tokens_spent=80,
        calibration=calibration if calibration is not None else _calibration(),
    )


def test_highlight_wraps_a_keyword_in_a_font_tag():
    markup = _highlight("def f():\n    return 1\n")
    assert "<font color=" in markup
    assert "def" in markup


def test_highlight_preserves_leading_indentation_as_nbsp():
    markup = _highlight("    return 1")
    assert markup.startswith("&nbsp;" * 4)


def test_highlight_escapes_xml_special_characters():
    markup = _highlight("x = a < b")
    assert "&lt;" in markup


def test_read_excerpt_returns_lines_around_the_target_line(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("\n".join(f"line{i}" for i in range(1, 11)))  # 10 lines
    excerpt, first_line = _read_excerpt(f, line=5, context=2)
    assert first_line == 3
    assert "line3" in excerpt
    assert "line7" in excerpt
    assert "line1" not in excerpt.split("\n")[0]  # window doesn't reach line1


def test_read_excerpt_returns_empty_for_a_missing_file(tmp_path):
    excerpt, first_line = _read_excerpt(tmp_path / "does_not_exist.py", line=1)
    assert excerpt == ""
    assert first_line == 0


def test_findings_flowables_escapes_angle_bracket_func_name():
    # Regression: a module-level finding's func_name is the literal string
    # "<module>" (scan/pipeline.py::_semgrep_findings' fallback). Passed
    # unescaped into a reportlab Paragraph, "<module>" is parsed as an
    # (invalid, silently dropped) XML tag, leaving the heading as
    # "file.py:5 -- ()" -- caught by hand-inspecting a real generated PDF.
    finding = Finding(
        file=Path("app/config.py"), line=5, func_name="<module>", cwe="CWE-798",
        severity="WARNING", source="semgrep", confidence=1.0,
        message="hardcoded credential", fix_hint="",
    )
    flow = _findings_flowables(_styles(), _result(findings=[finding]))
    heading = next(f for f in flow if getattr(f, "text", "").startswith("app"))
    assert "&lt;module&gt;" in heading.text
    assert "<module>" not in heading.text.replace("&lt;module&gt;", "")


def test_generate_pdf_produces_a_real_pdf_file(tmp_path):
    findings = [
        Finding(
            file=Path("app/db.py"), line=1, func_name="get_user", cwe="CWE-89",
            severity="ERROR", source="semgrep", confidence=1.0,
            message="SQL built by concatenation.", fix_hint="Parameterize the query.",
        ),
    ]
    out = tmp_path / "report.pdf"
    result_path = generate_pdf(_result(findings=findings), target=Path("app"), output_path=out)
    assert result_path == out
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"
    assert out.stat().st_size > 2000


def test_generate_pdf_handles_zero_findings(tmp_path):
    out = tmp_path / "report.pdf"
    generate_pdf(_result(findings=[]), target=Path("app"), output_path=out)
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_generate_pdf_handles_no_certificate(tmp_path):
    out = tmp_path / "report.pdf"
    generate_pdf(_result(findings=[], calibration=None), target=Path("app"), output_path=out)
    assert out.exists()


def test_generate_pdf_handles_a_finding_whose_source_file_no_longer_exists(tmp_path):
    findings = [
        Finding(
            file=Path("nonexistent/ghost.py"), line=1, func_name="f", cwe="CWE-78",
            severity="ERROR", source="semgrep", confidence=1.0,
            message="shell=True.", fix_hint="Avoid shell=True.",
        ),
    ]
    out = tmp_path / "report.pdf"
    generate_pdf(_result(findings=findings), target=Path("app"), output_path=out)
    assert out.exists()


def test_generate_pdf_creates_missing_parent_directories(tmp_path):
    out = tmp_path / "nested" / "dir" / "report.pdf"
    generate_pdf(_result(findings=[]), target=Path("app"), output_path=out)
    assert out.exists()


def test_certificate_section_names_the_method_and_states_the_right_guarantee():
    from codegate.report.pdf import _certificate_flowables
    calib = Calibration(
        t_hat=0.83, alpha=0.10, delta=0.05, n_vuln_calib=206, ranker_id="R2",
        corpus_version="real-2040-sym", is_provisional=False, created_at="2026-10-04T00:00:00+00:00",
        method="cluster-hb", n_vuln_groups=66,
    )
    flow = _certificate_flowables(_styles(), _result(calibration=calib))
    text = " ".join(str(getattr(f, "text", "")) for f in flow)
    cells = " ".join(str(c) for f in flow if hasattr(f, "_cellvalues") for row in f._cellvalues for c in row)
    assert "66 task groups" in cells
    # The bound is on vulnerable code being approved, not on approved code being vulnerable.
    assert "of vulnerable functions" in text
    assert "probability it is actually vulnerable" not in text
