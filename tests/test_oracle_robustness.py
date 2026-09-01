"""Regression tests for the oracle-abstention defect class.

The original bug: SimulatedBackend emitted `SELECT * FROM t` while the SQLi
harness only created a table named `users`. Every call raised `no such
table`, the oracle abstained, and the pipeline recorded all 540 CWE-89
samples as safe -- including the deliberately vulnerable ones. The corpus
looked fine; a third of it was silently wrong.

Real models pick table names freely, so this must not be able to recur.
"""
import pytest
from codegate.oracles.sqli_oracle import check_sqli
from codegate.research.generation.backends import SimulatedBackend
from codegate.research.corpus.prompts import Prompt
from codegate.research.pipeline import label_row, LABEL_ABSTAIN, LABEL_VULNERABLE

import pandas as pd


VULN_TEMPLATE = (
    "def get_row(conn, name):\n"
    "    q = \"SELECT * FROM {table} WHERE col = '\" + name + \"'\"\n"
    "    return conn.execute(q).fetchall()\n"
)

SAFE_TEMPLATE = (
    "def get_row(conn, name):\n"
    "    return conn.execute(\"SELECT * FROM {table} WHERE col = ?\", (name,)).fetchall()\n"
)


@pytest.mark.parametrize(
    "table", ["users", "user", "accounts", "customers", "products", "orders", "t"]
)
def test_sqli_oracle_detects_injection_regardless_of_table_name(table):
    verdict = check_sqli(VULN_TEMPLATE.format(table=table), function_name="get_row")
    assert verdict is True, (
        f"oracle abstained or cleared a vulnerable snippet using table "
        f"'{table}' -- this is the silent-mislabel defect, not a safe result"
    )


@pytest.mark.parametrize("table", ["users", "accounts", "products"])
def test_sqli_oracle_clears_parameterized_query_regardless_of_table_name(table):
    verdict = check_sqli(SAFE_TEMPLATE.format(table=table), function_name="get_row")
    assert verdict is False


def test_simulated_vulnerable_sqli_is_labeled_vulnerable_not_abstained():
    # End-to-end guard: the exact path that was broken. A vulnerable-flavor
    # CWE-89 sample from the simulator must come back labelled vulnerable.
    backend = SimulatedBackend(name="sim", seed=0)
    prompt = Prompt("CWE-89-001-vulnerable", "CWE-89", "vulnerable", "train", "irrelevant")
    code = backend.generate(prompt, seed=1)

    row = pd.Series({"sample_id": "s1", "cwe": "CWE-89", "code": code})
    result = label_row(row)

    assert result["label"] != LABEL_ABSTAIN, "oracle abstained on simulated vulnerable SQLi"
    assert result["label"] == LABEL_VULNERABLE


def test_abstention_is_its_own_label_not_safe():
    # Genuinely unjudgeable: the code *does* touch SQL (so the no-sink
    # shortcut correctly declines to call it safe), but there is no function
    # for the harness to invoke, so no verdict can be reached. That must be
    # recorded as abstain -- never silently as safe.
    row = pd.Series({
        "sample_id": "s2", "cwe": "CWE-89",
        "code": 'QUERY = "SELECT * FROM users WHERE col = \'" + name + "\'"\n',
    })
    result = label_row(row)
    assert result["label"] == LABEL_ABSTAIN


def test_code_with_no_sql_sink_is_safe_not_abstain():
    # A function that never touches a database cannot be SQL-injectable.
    # Reporting "unknown" here would discard a perfectly good negative
    # sample -- the neutral-flavor prompts are full of these.
    assert check_sqli("def c_to_f(c):\n    return c * 9 / 5 + 32\n", "c_to_f") is False


def test_code_with_no_shell_sink_is_safe_not_abstain():
    from codegate.oracles.cmdi_oracle import check_cmdi
    assert check_cmdi("def rev(s):\n    return s[::-1]\n", "rev") is False


def test_sink_shortcut_does_not_swallow_real_vulnerabilities():
    # The shortcut must never fire on code that does touch the sink.
    from codegate.oracles.sqli_oracle import has_sql_sink
    from codegate.oracles.cmdi_oracle import has_shell_sink
    assert has_sql_sink("conn.execute('SELECT 1')")
    assert has_sql_sink('q = "select * from users"')
    assert has_shell_sink("subprocess.run(cmd, shell=True)")
    assert has_shell_sink("os.system(cmd)")
