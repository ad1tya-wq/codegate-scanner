from pathlib import Path

from typer.testing import CliRunner

from codegate.cli import app
from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.research.artifacts import save_calibration, save_model

import pandas as pd

runner = CliRunner()


def _write_fake_artifacts(model_dir: Path, is_provisional: bool = True, ranker_id: str = "R2") -> None:
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
    )


def test_info_without_a_trained_model_exits_nonzero_with_actionable_message(tmp_path):
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path / "missing")])
    assert result.exit_code == 1
    assert "codegate calibrate" in result.output


def test_info_prints_certificate_and_provisional_warning(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=True)
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "R2" in result.output
    assert "simulated-v2" in result.output
    assert "PROVISIONAL" in result.output


def test_info_omits_provisional_warning_when_not_provisional(tmp_path):
    _write_fake_artifacts(tmp_path, is_provisional=False)
    result = runner.invoke(app, ["info", "--model-dir", str(tmp_path)])
    assert result.exit_code == 0
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


def test_scan_reports_not_implemented(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "not implemented" in result.output


def test_calibrate_writes_model_and_calibration(tmp_path):
    # No --limit: a small prefix of prompts isn't guaranteed to include any
    # calib-split, vulnerable-flavor task, which would skip artifact writing
    # entirely (run_full_pipeline only persists when n_vuln_calib > 0).
    out_dir = tmp_path / "model_out"
    result = runner.invoke(app, ["calibrate", "--out-dir", str(out_dir)])
    assert result.exit_code == 0, result.output
    assert (out_dir / "model.joblib").exists()
    assert (out_dir / "calibration.json").exists()
