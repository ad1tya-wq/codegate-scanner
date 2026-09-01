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


def run_semgrep(code: str, ruleset_path: Path | None = None) -> dict:
    """
    Runs the semgrep CLI against `code` using CodeGate's local custom
    ruleset by default. Returns a dict with `hit: bool` and `findings:
    list[dict]` (each with rule_id and severity). If the semgrep binary is
    unavailable, returns `{"hit": False, "findings": [], "error": "..."}`
    rather than raising, so pipeline runs degrade gracefully to the
    dynamic/static oracles alone.
    """
    config_path = ruleset_path or _CUSTOM_RULESET_PATH
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "snippet.py"
        path.write_text(code)
        try:
            proc = subprocess.run(
                ["semgrep", "--config", str(config_path), "--json", "--quiet", str(path)],
                capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"hit": False, "findings": [], "error": str(e)}

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"hit": False, "findings": [], "error": "unparseable semgrep output"}

        results = payload.get("results", [])
        findings = [
            {"rule_id": r.get("check_id", ""), "severity": r.get("extra", {}).get("severity", "")}
            for r in results
        ]
        return {"hit": len(findings) > 0, "findings": findings}
