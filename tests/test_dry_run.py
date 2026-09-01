import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dry_run_script_completes_and_produces_artifacts(tmp_path):
    out_dir = tmp_path / "dry_run_test"
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "run_pipeline_dry_run.py"), "--out-dir", str(out_dir)],
        capture_output=True, text=True, timeout=300,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert (out_dir / "generations.parquet").exists()
    assert (out_dir / "labeled.parquet").exists()
    assert (out_dir / "frontier.csv").exists()
    assert (out_dir / "frontier.png").exists()
    assert (out_dir / "shift_results.csv").exists()
    assert (out_dir / "shift_results.png").exists()
    assert (out_dir / "model.joblib").exists()
    assert (out_dir / "calibration.json").exists()
    assert "CODEGATE DRY RUN SUMMARY" in proc.stdout

    calib = json.loads((out_dir / "calibration.json").read_text())
    assert calib["is_provisional"] is True
    assert calib["corpus_version"] == "simulated-v2"
    assert calib["ranker_id"] == "R2"
