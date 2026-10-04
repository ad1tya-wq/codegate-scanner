import pandas as pd

from codegate.research.pipeline import label_summary, relabel

VULN_SQLI = (
    "def get_user(conn, username):\n"
    "    return conn.execute(\n"
    "        \"SELECT * FROM users WHERE username = '\" + username + \"'\").fetchall()\n"
)
SAFE_SQLI = (
    "def get_user(conn, username):\n"
    "    return conn.execute(\n"
    "        'SELECT * FROM users WHERE username = ?', (username,)).fetchall()\n"
)
FENCED_VULN_SQLI = (
    "Here is the function you asked for:\n\n"
    "```python\n" + VULN_SQLI + "```\n\n"
    "Note that this is vulnerable to SQL injection.\n"
)


def _gen_df(rows: list[dict]) -> pd.DataFrame:
    base = {
        "prompt_id": "CWE-89-001-vulnerable", "cwe": "CWE-89",
        "flavor": "vulnerable", "generator": "m", "split": "train",
        "is_simulated": False,
    }
    return pd.DataFrame([{**base, **r} for r in rows])


def test_relabel_produces_one_row_per_input_sample():
    df = _gen_df([
        {"sample_id": "a-0", "code": VULN_SQLI},
        {"sample_id": "b-0", "code": SAFE_SQLI},
    ])
    out = relabel(df)
    assert len(out) == 2
    assert set(out["sample_id"]) == {"a-0", "b-0"}


def test_relabel_separates_vulnerable_from_parameterized():
    df = _gen_df([
        {"sample_id": "a-0", "code": VULN_SQLI},
        {"sample_id": "b-0", "code": SAFE_SQLI, "flavor": "near_miss",
         "prompt_id": "CWE-89-001-near_miss"},
    ])
    out = relabel(df).set_index("sample_id")
    assert out.loc["a-0", "label"] == 1
    assert out.loc["b-0", "label"] == 0


def test_relabel_extracts_code_from_a_markdown_fence():
    """Real chat models wrap code in prose; relabel must apply the same
    extraction run_full_pipeline does, or every such sample abstains."""
    df = _gen_df([{"sample_id": "a-0", "code": FENCED_VULN_SQLI}])
    out = relabel(df)
    assert out.iloc[0]["label"] == 1


def test_relabel_does_not_mutate_the_input_frame():
    df = _gen_df([{"sample_id": "a-0", "code": FENCED_VULN_SQLI}])
    before = df["code"].iloc[0]
    relabel(df)
    assert df["code"].iloc[0] == before


def test_label_summary_crosstabs_cwe_flavor_and_verdict():
    df = _gen_df([
        {"sample_id": "a-0", "code": VULN_SQLI},
        {"sample_id": "b-0", "code": SAFE_SQLI, "flavor": "near_miss",
         "prompt_id": "CWE-89-001-near_miss"},
    ])
    summary = label_summary(df, relabel(df))
    assert summary.loc[("CWE-89", "vulnerable"), "VULN"] == 1
    assert summary.loc[("CWE-89", "near_miss"), "SAFE"] == 1
