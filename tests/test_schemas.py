import pandas as pd
import pytest
from codegate.schemas import validate_dataframe, SchemaError, SCHEMAS

def test_generations_schema_registered():
    assert "generations" in SCHEMAS
    assert "labeled" in SCHEMAS
    assert "scores" in SCHEMAS

def test_valid_generations_frame_passes():
    df = pd.DataFrame({
        "sample_id": ["a1"],
        "prompt_id": ["p1"],
        "cwe": ["CWE-89"],
        "flavor": ["vulnerable"],
        "generator": ["qwen2.5-coder-7b"],
        "code": ["def f(): pass"],
        "split": ["train"],
        "is_simulated": [True],
    })
    validate_dataframe(df, "generations")  # should not raise

def test_missing_column_reports_all_missing():
    df = pd.DataFrame({"sample_id": ["a1"]})
    with pytest.raises(SchemaError) as exc:
        validate_dataframe(df, "generations")
    msg = str(exc.value)
    assert "prompt_id" in msg
    assert "cwe" in msg
    assert "code" in msg

def test_unknown_schema_name_raises():
    with pytest.raises(KeyError):
        validate_dataframe(pd.DataFrame(), "not_a_real_schema")
