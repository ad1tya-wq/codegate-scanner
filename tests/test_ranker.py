import pandas as pd
import pytest
from codegate.schemas import validate_dataframe
from codegate.ranker.r0_semgrep_score import score_r0
from codegate.ranker.r2_embedding_lr import R2Ranker


def _toy_generations() -> pd.DataFrame:
    return pd.DataFrame({
        "sample_id": ["s1", "s2"],
        "prompt_id": ["p1", "p2"],
        "cwe": ["CWE-89", "CWE-89"],
        "flavor": ["vulnerable", "near_miss"],
        "generator": ["g1", "g1"],
        "code": [
            "def f(conn, u):\n    return conn.execute(\"SELECT * FROM t WHERE c='\" + u + \"'\")\n",
            "def f(conn, u):\n    return conn.execute('SELECT * FROM t WHERE c=?', (u,))\n",
        ],
        "split": ["train", "train"],
        "is_simulated": [True, True],
    })


def test_score_r0_returns_valid_schema():
    df = score_r0(_toy_generations())
    validate_dataframe(df, "scores")
    assert set(df["ranker_id"]) == {"R0"}
    assert set(df["sample_id"]) == {"s1", "s2"}


def test_score_r0_higher_is_safer_direction():
    # r0 must produce a lower score for the string-concat sample than the
    # parameterized-query sample -- direction convention: higher = safer.
    df = score_r0(_toy_generations())
    s1 = df.loc[df.sample_id == "s1", "score"].iloc[0]
    s2 = df.loc[df.sample_id == "s2", "score"].iloc[0]
    assert s2 >= s1


def test_r2_ranker_fit_and_score_returns_valid_schema():
    gens = _toy_generations()
    labels = pd.Series([1, 0], index=gens.index)  # s1 vulnerable, s2 safe
    ranker = R2Ranker(random_seed=0)
    ranker.fit(gens, labels)
    scored = ranker.score(gens)
    validate_dataframe(scored, "scores")
    assert set(scored["ranker_id"]) == {"R2"}


def test_r2_ranker_score_is_deterministic():
    gens = _toy_generations()
    labels = pd.Series([1, 0], index=gens.index)
    r_a = R2Ranker(random_seed=0)
    r_a.fit(gens, labels)
    scored_a = r_a.score(gens).sort_values("sample_id").reset_index(drop=True)

    r_b = R2Ranker(random_seed=0)
    r_b.fit(gens, labels)
    scored_b = r_b.score(gens).sort_values("sample_id").reset_index(drop=True)

    pd.testing.assert_series_equal(scored_a["score"], scored_b["score"])


def test_r2_ranker_score_before_fit_raises():
    ranker = R2Ranker(random_seed=0)
    with pytest.raises(RuntimeError, match="fit"):
        ranker.score(_toy_generations())
