from __future__ import annotations
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.invocation import HARNESS_PRELUDE
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

# Two payload shapes are needed, and they are detected by different rules.
#
# The VALUE payload carries single quotes. SQLite doubles them when it
# expands a bound parameter ("nonexistent'' OR ''1''=''1"), so the raw
# string can only appear in the executed SQL if the code spliced it --
# a plain substring test is exact.
#
# The IDENT payload has to be valid in an identifier position (a value
# payload there is a syntax error that raises before anything is observed),
# so it contains nothing SQLite would escape -- which means binding leaves
# it byte-identical and a plain substring test would flag every
# parameterized query. It is instead detected by quote context: a bound
# parameter always expands to 'payload' with adjacent quotes, while an
# identifier splice does not. The comment marker makes accidental matches
# against real column names impossible.
_VALUE_PAYLOAD = "nonexistent' OR '1'='1"
_IDENT_PAYLOAD = "id /*cg_9f3a2b*/"

_SQL_SINK_MARKERS = (
    ".execute", ".executemany", ".executescript", "cursor",
    "select ", "insert ", "update ", "delete ", "sqlite3", "psycopg", "sqlalchemy",
)

_HARNESS_TEMPLATE = '''
import sqlite3
{prelude}

_TABLES = {tables!r}
_VALUE_PAYLOAD = {value_payload!r}
_IDENT_PAYLOAD = {ident_payload!r}
# (payload, detection mode) -- see the module-level comment on why the two
# shapes cannot share one rule.
_PAYLOADS = ((_VALUE_PAYLOAD, "raw"), (_IDENT_PAYLOAD, "unquoted"))


def _fresh_conn():
    conn = sqlite3.connect(":memory:")
    for _t in _TABLES:
        conn.execute("CREATE TABLE " + _t + " ({columns})")
        conn.execute("INSERT INTO " + _t + " VALUES ({row1})")
        conn.execute("INSERT INTO " + _t + " VALUES ({row2})")
    conn.commit()
    return conn


def _unquoted_spans(sql):
    # Index ranges of `sql` lying outside single-quoted string literals.
    # SQLite escapes a quote inside a literal by doubling it, so '' is a
    # literal quote rather than a terminator.
    spans = []
    i = 0
    n = len(sql)
    start = 0
    in_literal = False
    while i < n:
        if sql[i] == "'":
            if in_literal:
                if i + 1 < n and sql[i + 1] == "'":
                    i += 2
                    continue
                in_literal = False
                start = i + 1
            else:
                if start < i:
                    spans.append((start, i))
                in_literal = True
        i += 1
    if not in_literal and start < n:
        spans.append((start, n))
    return spans


def _is_spliced(statements, payload, mode):
    for sql in statements:
        if mode == "raw":
            # Quotes in the payload are doubled when SQLite expands a bound
            # parameter, so a verbatim match proves concatenation outright.
            if payload in sql:
                return True
        else:
            # Nothing in this payload gets escaped, so binding leaves it
            # byte-identical -- it is only evidence of injection when it
            # lands OUTSIDE a string literal, i.e. in identifier position.
            # Checking quote adjacency is not enough: a bound value can be
            # wrapped inside its literal, as LIKE '%' + value + '%' does.
            for _a, _b in _unquoted_spans(sql):
                if payload in sql[_a:_b]:
                    return True
    return False


def _invoke(fn, args):
    conn = _fresh_conn()
    seen = []
    conn.set_trace_callback(seen.append)
    try:
        fn(conn, *args)
    except Exception:
        pass
    finally:
        try:
            conn.set_trace_callback(None)
        except Exception:
            pass
    return seen


_fn = {function_name}
_params = positional_params(_fn)
_names = [p.name for p in _params]
_free = _params[1:] if takes_connection(_names) else []

_fired = False
_observed = False

if _free:
    # Control run first: benign arguments throughout. If the function
    # executes SQL here it is genuinely exercisable, which is what lets a
    # later "no payload was spliced" result mean safe rather than unknown.
    # Without this, code that correctly rejects a malicious identifier
    # (the standard whitelist mitigation) would abstain on every payload
    # and be discarded, even though it is exactly the safe shape the
    # corpus needs.
    _benign = [benign_value_for(p.name) for p in _free]
    if _invoke(_fn, _benign):
        _observed = True

    for _payload, _mode in _PAYLOADS:
        for _i in range(len(_free)):
            _args = list(_benign)
            _args[_i] = _payload
            _seen = _invoke(_fn, _args)
            if _seen:
                _observed = True
            if _is_spliced(_seen, _payload, _mode):
                _fired = True
                break
        if _fired:
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


def check_sqli(code: str, function_name: str) -> bool | None:
    """
    Detonates the generated function and observes the SQL it actually
    executes, via sqlite3's trace callback.

    Returns True when a payload reaches the executed SQL text verbatim --
    direct proof the value was concatenated into the query rather than
    bound. SQLite escapes bound parameters when it expands a statement
    ("nonexistent'' OR ''1''=''1"), so a parameterized query can never
    produce a verbatim match, whatever the payload. Returns False only when
    SQL was observed to run and no payload was spliced: a "safe" verdict
    always rests on positive evidence. Returns None when the function is
    absent, takes no database connection, or nothing observable ran --
    unjudgeable, which is not the same as safe.

    This replaces a row-count heuristic that could only see injections
    widening a SELECT. That heuristic labelled injectable DELETE, UPDATE,
    INSERT, ORDER BY and LIKE code *safe*, and labelled correctly
    parameterized SELECT COUNT(*) code *vulnerable* -- both of which put
    wrong labels into the corpus rather than merely dropping samples. See
    docs/ENGINEERING_LOG.md section 11.
    """
    if not has_sql_sink(code):
        return False  # no SQL anywhere: confidently safe, not "unknown"

    if not function_exists(code, function_name):
        return None

    harness = _HARNESS_TEMPLATE.format(
        prelude=HARNESS_PRELUDE,
        tables=_FIXTURE_TABLES,
        columns=_FIXTURE_COLUMNS,
        row1=_FIXTURE_ROW_1,
        row2=_FIXTURE_ROW_2,
        value_payload=_VALUE_PAYLOAD,
        ident_payload=_IDENT_PAYLOAD,
        function_name=function_name,
    )
    # Raised from 5s: the harness now performs up to 2 x n_params invocations
    # inside one process rather than a single call. Still one subprocess per
    # sample, so corpus-scale wall clock is essentially unchanged.
    result = run_sandboxed(code + "\n" + harness, harness="", timeout_s=15.0)

    if result.timed_out:
        return None
    if "CODEGATE_VERDICT=VULNERABLE" in result.stdout:
        return True
    if "CODEGATE_VERDICT=SAFE" in result.stdout:
        return False
    return None
