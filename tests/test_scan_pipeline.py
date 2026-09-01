from pathlib import Path

import pandas as pd
import pytest
from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.research.artifacts import save_calibration, save_model
from codegate.scan.findings import Finding
from codegate.scan.pipeline import run_scan

FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


def _write_model_dir(model_dir: Path, t_hat: float | None) -> None:
    gens = pd.DataFrame({
        "sample_id": ["s1", "s2"],
        "code": [
            "def f(conn, u):\n    return conn.execute(\"SELECT * FROM t WHERE c='\" + u + \"'\")\n",
            "def f(conn, u):\n    return conn.execute('SELECT * FROM t WHERE c=?', (u,))\n",
        ],
    })
    labels = pd.Series([1, 0], index=gens.index)
    ranker = R2Ranker(random_seed=0).fit(gens, labels)
    result = LTTResult(
        t_hat=t_hat, alpha=0.05, delta=0.05, n_vuln_calib=10, coverage=0.6, trace=[],
    )
    save_model(ranker, model_dir / "model.joblib")
    save_calibration(result, model_dir / "calibration.json", corpus_version="simulated-v2", is_provisional=True)


def test_finding_rejects_invalid_source():
    with pytest.raises(ValueError, match="source"):
        Finding(
            file=Path("x.py"), line=1, func_name="f", cwe="CWE-89",
            severity="ERROR", source="not-a-real-source", confidence=1.0,
            message="x", fix_hint="x",
        )


def test_scan_finds_sqli_via_semgrep_and_maps_to_the_right_function(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "db.py").write_text((FIXTURES / "sqli_vuln.py").read_text())

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    _write_model_dir(model_dir, t_hat=None)  # escalate everything; only care about semgrep here

    result = run_scan(target, model_dir=model_dir)
    semgrep_hits = [f for f in result.findings if f.source == "semgrep"]
    assert any(f.cwe == "CWE-89" and f.func_name == "get_user" for f in semgrep_hits)


def test_scan_never_executes_the_scanned_code(tmp_path):
    # The hard invariant: scanning must not run the target code. Prove it
    # rather than just asserting by inspection -- a file that would leave
    # a detectable side effect if executed must NOT do so after a scan.
    sentinel = tmp_path / "sentinel.txt"
    target = tmp_path / "app"
    target.mkdir()
    (target / "evil.py").write_text(
        "import pathlib\n"
        f"pathlib.Path(r{str(sentinel)!r}).write_text('pwned')\n"
        "def handler(x):\n"
        "    return x\n"
    )
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    _write_model_dir(model_dir, t_hat=None)

    run_scan(target, model_dir=model_dir)
    assert not sentinel.exists()


def test_scan_gate_partitions_units_into_auto_approved_and_escalated(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "safe.py").write_text("def add(a, b):\n    return a + b\n")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    # t_hat=0.0: score >= 0.0 is always true for a probability -> everything auto-approved
    _write_model_dir(model_dir, t_hat=0.0)

    result = run_scan(target, model_dir=model_dir)
    assert result.n_units == 1
    assert result.n_auto_approved + result.n_escalated == result.n_units
    assert result.n_auto_approved == 1
    assert result.n_escalated == 0


def test_scan_uncertified_threshold_escalates_everything(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "safe.py").write_text("def add(a, b):\n    return a + b\n")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    _write_model_dir(model_dir, t_hat=None)

    result = run_scan(target, model_dir=model_dir)
    assert result.n_escalated == result.n_units
    assert result.n_auto_approved == 0
    model_findings = [f for f in result.findings if f.source == "model"]
    assert len(model_findings) == 1
    assert model_findings[0].cwe == "UNSPECIFIED"


def test_scan_reports_skipped_files(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "good.py").write_text("def good():\n    pass\n")
    (target / "bad.py").write_text("def bad(:\n    pass\n")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    _write_model_dir(model_dir, t_hat=None)

    result = run_scan(target, model_dir=model_dir)
    assert len(result.skipped) == 1
    assert result.skipped[0].file.name == "bad.py"


def test_scan_without_a_trained_model_raises_actionable_error(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "safe.py").write_text("def add(a, b):\n    return a + b\n")

    with pytest.raises(FileNotFoundError, match="codegate calibrate"):
        run_scan(target, model_dir=tmp_path / "no_such_model_dir")
