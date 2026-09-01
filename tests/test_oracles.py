from pathlib import Path
import sqlite3
import pytest
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.sandbox import run_sandboxed
from codegate.oracles.sqli_oracle import check_sqli
from codegate.oracles.cmdi_oracle import check_cmdi
from codegate.oracles.creds_oracle import check_creds
from codegate.oracles.consensus import consensus_label
from codegate.oracles.semgrep_oracle import run_semgrep

FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_function_exists_true_for_defined_function():
    assert function_exists("def get_user(a, b): pass", "get_user") is True


def test_function_exists_false_for_missing_function():
    assert function_exists("def other(): pass", "get_user") is False


def test_function_exists_false_for_syntax_error():
    assert function_exists("def broken(:\n  pass", "broken") is False


def test_sandbox_runs_simple_code_and_captures_stdout():
    result = run_sandboxed("print('hello')", harness="", timeout_s=5.0)
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert not result.timed_out


def test_sandbox_kills_infinite_loop_on_timeout():
    result = run_sandboxed("while True: pass", harness="", timeout_s=1.0)
    assert result.timed_out


def test_sandbox_captures_nonzero_exit():
    result = run_sandboxed("raise ValueError('boom')", harness="", timeout_s=5.0)
    assert result.returncode != 0
    assert "boom" in result.stderr


def test_check_sqli_detects_vulnerable_fixture():
    code = _read("sqli_vuln.py")
    assert check_sqli(code, function_name="get_user") is True


def test_check_sqli_clears_safe_fixture():
    code = _read("sqli_safe.py")
    assert check_sqli(code, function_name="get_user") is False


def test_check_sqli_returns_none_when_function_missing():
    assert check_sqli("def other(): pass", function_name="get_user") is None


def test_check_cmdi_detects_vulnerable_fixture():
    code = _read("cmdi_vuln.py")
    assert check_cmdi(code, function_name="ping_host") is True


def test_check_cmdi_clears_safe_fixture():
    code = _read("cmdi_safe.py")
    assert check_cmdi(code, function_name="ping_host") is False


def test_check_creds_detects_vulnerable_fixture():
    code = _read("creds_vuln.py")
    assert check_creds(code) is True


def test_check_creds_clears_safe_fixture():
    code = _read("creds_safe.py")
    assert check_creds(code) is False


def test_consensus_label_unanimous_vulnerable():
    assert consensus_label("CWE-89", semgrep_hit=True, dynamic_verdict=True,
                            static_verdict=None, adjudicator_verdict=True) == 1


def test_consensus_label_unanimous_safe():
    assert consensus_label("CWE-89", semgrep_hit=False, dynamic_verdict=False,
                            static_verdict=None, adjudicator_verdict=False) == 0


def test_consensus_label_dynamic_oracle_breaks_semgrep_false_positive():
    # semgrep flags a pattern but the dynamic PoC proves it's not exploitable;
    # dynamic evidence outranks static pattern-matching in the consensus rule.
    assert consensus_label("CWE-89", semgrep_hit=True, dynamic_verdict=False,
                            static_verdict=None, adjudicator_verdict=False) == 0


def test_consensus_label_creds_uses_static_verdict_not_dynamic():
    assert consensus_label("CWE-798", semgrep_hit=True, dynamic_verdict=None,
                            static_verdict=True, adjudicator_verdict=True) == 1


def test_run_semgrep_flags_sqli_vulnerable_fixture():
    result = run_semgrep(_read("sqli_vuln.py"))
    assert result["hit"] is True
    assert any("sqli" in f["rule_id"] for f in result["findings"])


def test_run_semgrep_clears_sqli_safe_fixture():
    result = run_semgrep(_read("sqli_safe.py"))
    assert result["hit"] is False


def test_run_semgrep_flags_cmdi_vulnerable_fixture():
    result = run_semgrep(_read("cmdi_vuln.py"))
    assert result["hit"] is True
    assert any("cmdi" in f["rule_id"] for f in result["findings"])


def test_run_semgrep_clears_cmdi_safe_fixture():
    result = run_semgrep(_read("cmdi_safe.py"))
    assert result["hit"] is False
