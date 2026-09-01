from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path

# Local, offline, hand-written ruleset targeting exactly our 3 CWEs' vulnerable
# shapes (see data/semgrep_rules/codegate_rules.yaml for the rationale: the
# free-tier community registry packs (p/python, p/security-audit,
# p/sql-injection) were verified empirically 2026-08-28 to produce 0 findings
# on our raw-stdlib sqlite3/subprocess corpus -- they mostly target framework
# code (SQLAlchemy/Django/Flask)). Using a local file also makes this oracle
# fully independent of network/registry availability.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CUSTOM_RULESET_PATH = _REPO_ROOT / "data" / "semgrep_rules" / "codegate_rules.yaml"


def _run_semgrep_cli(target: Path, ruleset_path: Path | None = None, timeout: int = 60) -> dict:
    """
    Shared CLI invocation: runs semgrep against `target` (a single file or
    a whole directory -- semgrep accepts either) using CodeGate's local
    custom ruleset by default. Returns `hit: bool` and `findings:
    list[dict]`, each with rule_id, severity, path, start_line, end_line,
    and message. If the semgrep binary is unavailable or times out,
    returns `{"hit": False, "findings": [], "error": "..."}` rather than
    raising, so callers degrade gracefully instead of crashing a run.
    """
    config_path = ruleset_path or _CUSTOM_RULESET_PATH
    try:
        proc = subprocess.run(
            ["semgrep", "--config", str(config_path), "--json", "--quiet", str(target)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"hit": False, "findings": [], "error": str(e)}

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"hit": False, "findings": [], "error": "unparseable semgrep output"}

    results = payload.get("results", [])
    findings = [
        {
            "rule_id": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", ""),
            "path": r.get("path", ""),
            "start_line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
            "message": r.get("extra", {}).get("message", "").strip(),
        }
        for r in results
    ]
    return {"hit": len(findings) > 0, "findings": findings}


def run_semgrep(code: str, ruleset_path: Path | None = None) -> dict:
    """
    Runs semgrep against one in-memory code snippet (written to a temp
    file). Used by the research-side oracle/ranker path, which hands this
    function synthetic generated code rather than a real file on disk.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "snippet.py"
        path.write_text(code)
        return _run_semgrep_cli(path, ruleset_path)


def run_semgrep_on_path(target: Path, ruleset_path: Path | None = None) -> dict:
    """
    Runs semgrep directly against a real file or directory already on
    disk -- one CLI invocation covering everything under `target`, rather
    than one per unit (see ranker/r0_semgrep_score.py's docstring for the
    per-row cost this avoids at scan scale). Used by the scan pipeline's
    static pre-pass; findings carry real file paths and line numbers so
    they can be mapped back to specific ingest Units.
    """
    return _run_semgrep_cli(target, ruleset_path, timeout=120)
