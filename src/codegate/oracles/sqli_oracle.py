from __future__ import annotations
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.sandbox import run_sandboxed

# The fixture creates every table name a model plausibly picks for these
# prompts, all with identical shape. A real model asked to "look up a user"
# may write `FROM users`, `FROM user`, `FROM accounts`, `FROM customers`, or
# `FROM t` -- and if the table it chose does not exist, sqlite raises, the
# oracle abstains, and the sample is silently lost from the corpus. Creating
# the union is far cheaper than trying to constrain what models emit.
_FIXTURE_TABLES = (
    "users", "user", "accounts", "account", "customers", "customer",
    "products", "product", "items", "orders", "comments", "posts",
    "books", "reviews", "stock", "t",
)

_HARNESS_TEMPLATE = """
import sqlite3

conn = sqlite3.connect(":memory:")
for _t in {tables!r}:
    conn.execute(
        f"CREATE TABLE {{_t}} (id INTEGER, username TEXT, name TEXT, "
        f"email TEXT, password TEXT, col TEXT, category TEXT, "
        f"status TEXT, author TEXT, title TEXT, is_admin INTEGER)"
    )
    conn.execute(
        f"INSERT INTO {{_t}} VALUES (1, 'alice', 'alice', 'a@x.com', 'pw1', "
        f"'alice', 'books', 'open', 'alice', 'Book One', 0)"
    )
    conn.execute(
        f"INSERT INTO {{_t}} VALUES (2, 'bob_admin', 'bob', 'b@x.com', 'pw2', "
        f"'bob', 'tools', 'closed', 'bob', 'Book Two', 1)"
    )
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


_SQL_SINK_MARKERS = (
    ".execute", ".executemany", ".executescript", "cursor",
    "select ", "insert ", "update ", "delete ", "sqlite3", "psycopg", "sqlalchemy",
)


def has_sql_sink(code: str) -> bool:
    """
    Cheap scope check: could this code plausibly execute SQL at all?

    Used to distinguish "confidently safe" from "no verdict". A function
    that never touches a database cannot contain SQL injection, so returning
    an abstention for it would needlessly discard a valid negative sample --
    and the neutral-flavor prompts are deliberately full of such functions.
    Deliberately over-inclusive: any hint of SQL means we run the real
    dynamic oracle rather than taking the shortcut.
    """
    lowered = code.lower()
    return any(marker in lowered for marker in _SQL_SINK_MARKERS)


def check_sqli(code: str, function_name: str) -> bool | None:
    """
    Returns True if a classic SQLi payload (' OR '1'='1) causes the target
    function to return more rows than a legitimate single-user lookup would
    (i.e. the injection widened the result set) -- the injection "fired".
    Returns False if the function ran but the payload was neutralized.
    Returns None if the function doesn't exist or the harness itself errored
    in a way that gives no evidence either way (e.g. non-str-arg signature).
    """
    if not has_sql_sink(code):
        return False  # no SQL anywhere: confidently safe, not "unknown"

    if not function_exists(code, function_name):
        return None

    full_source = code + "\n" + _HARNESS_TEMPLATE.format(
        function_name=function_name, tables=_FIXTURE_TABLES
    )
    result = run_sandboxed(full_source, harness="", timeout_s=5.0)

    if result.timed_out:
        return None
    if "CODEGATE_ROW_COUNT=" not in result.stdout:
        return None  # function errored on the payload (e.g. TypeError) -> no evidence of injection

    row_count = int(result.stdout.split("CODEGATE_ROW_COUNT=")[1].split()[0])
    # legitimate lookup of a nonexistent user returns 0 rows; the payload
    # returning >=1 row means the OR '1'='1' clause matched every row
    return row_count >= 1
