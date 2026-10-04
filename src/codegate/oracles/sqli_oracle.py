from __future__ import annotations
import re

from codegate.oracles.ast_utils import function_exists
from codegate.oracles.dbapi_recorder import RECORDER_SOURCE
from codegate.oracles.invocation import HARNESS_PRELUDE, benign_candidates, guarded_exec_source
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

# Widened from the original two-row fixture: multi-argument prompts
# (add_comment, update_stock, orders_in_range) reference columns it never
# created, so the query raised OperationalError before anything observable
# happened and the sample abstained.
_FIXTURE_COLUMNS = (
    "id INTEGER, username TEXT, name TEXT, email TEXT, password TEXT, "
    "col TEXT, category TEXT, status TEXT, author TEXT, title TEXT, "
    "body TEXT, created_at TEXT, quantity INTEGER, warehouse TEXT, "
    "customer_id INTEGER, post_id INTEGER, product_id INTEGER, "
    "order_id INTEGER, review_id INTEGER, is_admin INTEGER"
)
_FIXTURE_ROW_1 = (
    "1,'alice','alice','a@x.com','pw1','alice','books','open',"
    "'alice','Book One','body one','2024-01-01',5,'w1',1,1,1,1,1,0"
)
_FIXTURE_ROW_2 = (
    "2,'bob','bob','b@x.com','pw2','bob','tools','closed',"
    "'bob','Book Two','body two','2024-06-01',7,'w2',2,2,2,2,2,1"
)

# One payload is enough. Detection happens at the execute() call boundary,
# before SQLite parses anything, so this works in an identifier position
# (`ORDER BY <payload>`, invalid SQL that SQLite would never prepare) just
# as well as in a value position. The trace-callback design this replaced
# needed a second, column-shaped payload plus a literal-aware scan to tell
# a splice from a bound parameter; neither is necessary now.
_PAYLOAD = "nonexistent' OR '1'='1"

_SQL_SINK_MARKERS = (
    ".execute", ".executemany", ".executescript", "cursor",
    "select ", "insert ", "update ", "delete ", "sqlite3", "psycopg", "sqlalchemy",
)

_FUTURE_IMPORT = re.compile(r"^from __future__ import .*$", re.MULTILINE)

_HARNESS_TEMPLATE = '''
_TABLES = {tables!r}
_PAYLOAD = {payload!r}
_ALLOWLIST = {allowlist!r}


def _fresh_real_conn():
    conn = sqlite3.connect(":memory:")
    for _t in _TABLES:
        conn.execute("CREATE TABLE " + _t + " ({columns})")
        conn.execute("INSERT INTO " + _t + " VALUES ({row1})")
        conn.execute("INSERT INTO " + _t + " VALUES ({row2})")
    conn.commit()
    return conn


_fn = {function_name}


def _invoke(args):
    recorder = SqlRecorder()
    try:
        _fn(RecordingConnection(_fresh_real_conn(), recorder), *args)
    except Exception:
        pass
    return recorder


_params = positional_params(_fn)
_names = [p.name for p in _params]
_free = _params[1:] if takes_connection(_names) else []

_fired = False
_observed = False

if _free:
    # Control run first, with benign arguments. Code that validates its
    # input and rejects the payload -- a whitelist raising ValueError is
    # the standard mitigation for an identifier position, which cannot be
    # parameterized -- would otherwise never be observed doing anything,
    # and would abstain despite being exactly the safe shape the corpus
    # needs labelled.
    _benign = [benign_value_for(p.name) for p in _free]
    for _vec in benign_vectors(_free, _ALLOWLIST):
        if _invoke(_vec).observed:
            _observed = True
            _benign = _vec
            break

    for _i in range(len(_free)):
        _args = list(_benign)
        _args[_i] = _PAYLOAD
        _recorder = _invoke(_args)
        if _recorder.observed:
            _observed = True
        if _recorder.payload_was_spliced(_PAYLOAD):
            _fired = True
            break

if _fired:
    print("CODEGATE_VERDICT=VULNERABLE")
elif _observed:
    print("CODEGATE_VERDICT=SAFE")
else:
    print("CODEGATE_VERDICT=NOEVIDENCE")
'''


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


def _build_source(code: str, function_name: str) -> str:
    """
    Assemble the sandbox script: preamble, then the generated code, then
    the invocation harness.

    Order is load-bearing. The preamble installs the missing-module stub
    finder, and the generated code's own imports run at module level -- so
    a script that put the generated code first would hit `import psycopg2`
    before the finder existed and die there. `from __future__` imports are
    stripped from both embedded sources because such a statement is only
    legal as the first statement in a file, and neither fragment is first
    any more; `annotations` is the only one in practice and dropping it
    changes nothing that matters here.
    """
    return (
        "import sqlite3\n"
        + _FUTURE_IMPORT.sub("", RECORDER_SOURCE) + "\n"
        + HARNESS_PRELUDE + "\n"
        + guarded_exec_source(code) + "\n"
        + _HARNESS_TEMPLATE.format(
            tables=_FIXTURE_TABLES,
            columns=_FIXTURE_COLUMNS,
            row1=_FIXTURE_ROW_1,
            row2=_FIXTURE_ROW_2,
            payload=_PAYLOAD,
            allowlist=benign_candidates(code),
            function_name=function_name,
        )
    )


def check_sqli(code: str, function_name: str) -> bool | None:
    """
    Detonates the generated function against a recording DB-API connection
    and observes the SQL it hands to `execute()`.

    Returns True when the payload reaches a statement as query *text*
    rather than as a bound parameter -- which is precisely what SQL
    injection is. Returns False only when SQL was observed to run and the
    payload never reached it as text: a "safe" verdict always rests on
    positive evidence. Returns None when the function is absent, takes no
    database connection, or issued no SQL at all -- unjudgeable, which is
    not the same as safe.

    Two earlier designs were replaced. A row-count heuristic could only see
    injections that widened a SELECT, so it labelled injectable DELETE,
    UPDATE and INSERT code *safe* and parameterized SELECT COUNT(*) code
    *vulnerable*. A SQLite trace callback fixed that but still required
    SQLite to have accepted the statement, which lost every sample written
    in Postgres idiom -- 19 of 25 remaining CWE-89 abstentions on the
    real-540 corpus. Recording at the call boundary depends on neither.
    See docs/ENGINEERING_LOG.md sections 11 and 12.
    """
    if not has_sql_sink(code):
        return False  # no SQL anywhere: confidently safe, not "unknown"

    if not function_exists(code, function_name):
        return None

    # 15s rather than the original 5s: the harness makes up to n_params + 1
    # invocations inside one process instead of a single call. Still one
    # subprocess per sample, so corpus-scale wall clock is unchanged.
    result = run_sandboxed(
        _build_source(code, function_name), harness="", timeout_s=15.0
    )

    if result.timed_out:
        return None
    if "CODEGATE_VERDICT=VULNERABLE" in result.stdout:
        return True
    if "CODEGATE_VERDICT=SAFE" in result.stdout:
        return False
    return None
