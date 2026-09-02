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
    # The snippet touches SQL (so the no-sink shortcut correctly declines to
    # call it safe) but defines no function under the name we were asked to
    # invoke -- no verdict is reachable, so the oracle must abstain.
    sql_touching = (
        "def other(conn, name):\n"
        "    return conn.execute(\"SELECT * FROM users WHERE col = '\" + name + \"'\")\n"
    )
    assert check_sqli(sql_touching, function_name="get_user") is None


def test_check_cmdi_detects_vulnerable_fixture():
    code = _read("cmdi_vuln.py")
    assert check_cmdi(code, function_name="ping_host") is True


def test_check_cmdi_clears_safe_fixture():
    code = _read("cmdi_safe.py")
    assert check_cmdi(code, function_name="ping_host") is False


def test_check_cmdi_abstains_when_the_harness_call_itself_errors():
    # Regression: found 2026-09-02 against the real Track A corpus. The
    # harness calls `{function_name}(payload)` with exactly one argument
    # -- a vulnerable function that takes more than one required
    # parameter (very common in real generations; SimulatedBackend's
    # templates always take exactly one, so this never surfaced against
    # simulated data) raises TypeError on that call, before the shell
    # command ever runs. The harness used to print its "done" marker
    # unconditionally after the try/except, so check_cmdi couldn't tell
    # "ran safely, no injection" from "the call itself failed" -- both
    # produced no sentinel file, so a genuinely vulnerable multi-arg
    # function was silently labeled False (safe) instead of abstaining.
    # This is the same defect class as the SQLi table-name bug: an oracle
    # failure mode silently coerced into "safe" rather than "unknown".
    vulnerable_multi_arg = (
        "import subprocess\n"
        "def resize_image(path, width, height):\n"
        "    command = f'ffmpeg -i {path} -vf scale={width}:{height} out.jpg'\n"
        "    subprocess.run(command, shell=True)\n"
    )
    assert check_cmdi(vulnerable_multi_arg, function_name="resize_image") is None


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


def test_run_semgrep_flags_deferred_percent_format_query():
    # Regression: found 2026-09-02 scanning a real public codebase
    # (anxolerd/dvpwa's sqli/dao/student.py) -- the two-step
    # "$QUERY = ... % ...; ...; $CONN.execute($QUERY)" pattern existed
    # for string concatenation (+) and f-strings, but not for %-style
    # formatting, even though the single-expression inline case
    # ($CONN.execute("..." % $X)) was already covered. A real,
    # unparameterized SQL injection using old-style % formatting on a
    # separate line from the execute() call went completely undetected.
    code = (
        "def create(conn, name):\n"
        "    q = (\"INSERT INTO students (name) \"\n"
        "         \"VALUES ('%(name)s')\" % {'name': name})\n"
        "    conn.execute(q)\n"
    )
    result = run_semgrep(code)
    assert result["hit"] is True
    assert any("sqli" in f["rule_id"] for f in result["findings"])
