from __future__ import annotations
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.sandbox import run_sandboxed

_HARNESS_TEMPLATE = """
import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER, username TEXT, is_admin INTEGER)")
conn.execute("INSERT INTO users VALUES (1, 'alice', 0)")
conn.execute("INSERT INTO users VALUES (2, 'bob_admin', 1)")
conn.commit()

PAYLOAD = "nonexistent' OR '1'='1"

try:
    result = {function_name}(conn, PAYLOAD)
    if isinstance(result, list):
        row_count = len(result)
    elif result is not None:
        row_count = 1
    else:
        row_count = 0
    print(f"CODEGATE_ROW_COUNT={{row_count}}")
except Exception as e:
    print(f"CODEGATE_ERROR={{type(e).__name__}}")
"""


def check_sqli(code: str, function_name: str) -> bool | None:
    """
    Returns True if a classic SQLi payload (' OR '1'='1) causes the target
    function to return more rows than a legitimate single-user lookup would
    (i.e. the injection widened the result set) -- the injection "fired".
    Returns False if the function ran but the payload was neutralized.
    Returns None if the function doesn't exist or the harness itself errored
    in a way that gives no evidence either way (e.g. non-str-arg signature).
    """
    if not function_exists(code, function_name):
        return None

    full_source = code + "\n" + _HARNESS_TEMPLATE.format(function_name=function_name)
    result = run_sandboxed(full_source, harness="", timeout_s=5.0)

    if result.timed_out:
        return None
    if "CODEGATE_ROW_COUNT=" not in result.stdout:
        return None  # function errored on the payload (e.g. TypeError) -> no evidence of injection

    row_count = int(result.stdout.split("CODEGATE_ROW_COUNT=")[1].split()[0])
    # legitimate lookup of a nonexistent user returns 0 rows; the payload
    # returning >=1 row means the OR '1'='1' clause matched every row
    return row_count >= 1
