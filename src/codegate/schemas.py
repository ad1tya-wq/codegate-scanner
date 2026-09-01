from __future__ import annotations
import pandas as pd


class SchemaError(ValueError):
    pass


SCHEMAS: dict[str, dict[str, str]] = {
    "generations": {
        "sample_id": "object",
        "prompt_id": "object",
        "cwe": "object",
        "flavor": "object",
        "generator": "object",
        "code": "object",
        "split": "object",
        "is_simulated": "bool",
    },
    "labeled": {
        "sample_id": "object",
        "cwe": "object",
        "label": "int64",              # 1 = vulnerable, 0 = safe
        "semgrep_hit": "bool",
        "dynamic_verdict": "object",   # True/False/None (creds has no dynamic oracle)
        "static_verdict": "object",
        "adjudicator_verdict": "bool",
        "consensus_rule_version": "object",
    },
    "scores": {
        "sample_id": "object",
        "ranker_id": "object",
        "score": "float64",            # higher = safer
    },
}


def validate_dataframe(df: pd.DataFrame, schema_name: str) -> None:
    schema = SCHEMAS[schema_name]  # KeyError on unknown name is intentional
    errors: list[str] = []

    missing = [c for c in schema if c not in df.columns]
    if missing:
        errors.append(f"missing columns: {missing}")

    extra = [c for c in df.columns if c not in schema]
    if extra:
        errors.append(f"unexpected columns: {extra}")

    for col, expected_dtype in schema.items():
        if col not in df.columns:
            continue
        actual = str(df[col].dtype)
        if expected_dtype == "bool" and actual not in ("bool", "boolean"):
            errors.append(f"column '{col}' expected bool-like, got {actual}")
        elif expected_dtype not in ("bool",) and expected_dtype != actual and not (
            expected_dtype == "object" and actual == "object"
        ):
            if expected_dtype in ("int64", "float64") and actual not in (
                "int64", "float64", "int32", "float32"
            ):
                errors.append(f"column '{col}' expected {expected_dtype}, got {actual}")

    if errors:
        raise SchemaError(f"schema '{schema_name}' validation failed: " + "; ".join(errors))
