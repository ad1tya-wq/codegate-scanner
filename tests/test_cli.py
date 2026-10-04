import json
from pathlib import Path

from typer.testing import CliRunner

from codegate.cli import app
from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.research.artifacts import save_calibration, save_model

import pandas as pd

runner = CliRunner()


def _write_fake_artifacts(model_dir: Path, is_provisional: bool = True, ranker_id: str = "R2",
                          frontier=None) -> None:
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
        t_hat=0.5, alpha=0.05, delta=0.05, n_vuln_calib=10, coverage=0.6, trace=[],
    )
    save_model(ranker, model_dir / "model.joblib")
    save_calibration(
        result, model_dir / "calibration.json",
        corpus_version="simulated-v2", is_provisional=is_provisional, ranker_id=ranker_id,
        frontier=frontier,
    )


def test_info_without_a_trained_model_exits_nonzero_with_actionable_message(tmp_path):
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path / "missing")])
    assert result.exit_code == 1
    assert "codegate calibrate" in result.output


def test_info_prints_certificate_table(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "R2" in result.output
    assert "simulated-v2" in result.output
    # The corpus version is disclosed in the table itself; no separate
    # PROVISIONAL banner is printed live -- that disclosure lives in the
    # PDF report and docs/ENGINEERING_LOG.md instead.
    assert "PROVISIONAL" not in result.output


def test_info_rejects_ranker_id_mismatch(tmp_path):
    _write_fake_artifacts(tmp_path, ranker_id="R0")
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "R0" in result.output


def test_scan_rejects_invalid_format(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "bogus"])
    assert result.exit_code == 1
    assert "--format" in result.output


def _scan_target(tmp_path: Path) -> Path:
    target = tmp_path / "app"
    target.mkdir()
    (target / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    return target


def test_scan_alpha_override_uses_the_certified_threshold_for_that_alpha(tmp_path):
    _write_fake_artifacts(tmp_path, frontier=pd.DataFrame({
        "alpha": [0.05, 0.10], "t_hat": [0.5, 0.4], "coverage": [0.6, 0.7], "n_vuln_calib": [10, 10],
    }))
    target = _scan_target(tmp_path)
    result = runner.invoke(
        app, ["scan", str(target), "--model-dir", str(tmp_path), "--no-llm",
              "--alpha", "0.1", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["certificate"]["alpha"] == 0.1


def test_scan_alpha_override_refuses_an_uncertified_alpha_and_lists_valid_ones(tmp_path):
    _write_fake_artifacts(tmp_path, frontier=pd.DataFrame({
        "alpha": [0.05, 0.10], "t_hat": [0.5, 0.4], "coverage": [0.6, 0.7], "n_vuln_calib": [10, 10],
    }))
    target = _scan_target(tmp_path)
    result = runner.invoke(
        app, ["scan", str(target), "--model-dir", str(tmp_path), "--no-llm", "--alpha", "0.42"],
    )
    assert result.exit_code == 2
    assert "0.05" in result.output and "0.1" in result.output


def test_scan_without_a_trained_model_exits_nonzero_with_actionable_message(tmp_path):
    target = _scan_target(tmp_path)
    result = runner.invoke(
        app, ["scan", str(target), "--model-dir", str(tmp_path / "missing"), "--no-llm"]
    )
    assert result.exit_code == 1
    assert "codegate calibrate" in result.output


def test_scan_terminal_format_prints_a_summary(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    target = _scan_target(tmp_path)
    result = runner.invoke(app, ["scan", str(target), "--model-dir", str(tmp_path), "--no-llm"])
    assert result.exit_code == 0, result.output
    assert "CodeGate scan" in result.output


def test_scan_json_format_prints_valid_json(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    target = _scan_target(tmp_path)
    result = runner.invoke(
        app, ["scan", str(target), "--model-dir", str(tmp_path), "--format", "json", "--no-llm"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "findings" in payload
    assert payload["certificate"]["corpus_version"] == "simulated-v2"


def test_scan_sarif_format_prints_valid_sarif(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    target = _scan_target(tmp_path)
    result = runner.invoke(
        app, ["scan", str(target), "--model-dir", str(tmp_path), "--format", "sarif", "--no-llm"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"


def test_scan_json_format_with_output_writes_a_file_instead_of_stdout(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    target = _scan_target(tmp_path)
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(target), "--model-dir", str(tmp_path), "--format", "json", "--output", str(out), "--no-llm"],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    json.loads(out.read_text())  # valid JSON on disk


def test_scan_pdf_format_writes_a_real_pdf(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    target = _scan_target(tmp_path)
    out = tmp_path / "report.pdf"
    result = runner.invoke(
        app,
        ["scan", str(target), "--model-dir", str(tmp_path), "--format", "pdf", "--output", str(out), "--no-llm"],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_calibrate_writes_model_and_calibration(tmp_path):
    # No --limit: a small prefix of prompts isn't guaranteed to include any
    # calib-split, vulnerable-flavor task, which would skip artifact writing
    # entirely (run_full_pipeline only persists when n_vuln_calib > 0).
    out_dir = tmp_path / "model_out"
    result = runner.invoke(app, ["calibrate", "--out-dir", str(out_dir)])
    assert result.exit_code == 0, result.output
    assert (out_dir / "model.joblib").exists()
    assert (out_dir / "calibration.json").exists()
