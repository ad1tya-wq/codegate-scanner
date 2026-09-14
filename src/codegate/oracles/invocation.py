"""
Shared signature analysis for the dynamic detonation oracles.

Both harnesses used to call the generated function with a fixed arity --
`f(conn, PAYLOAD)` for SQLi, `f(payload)` for cmdi. Any generated function
with a different signature raised TypeError, produced no evidence, and
abstained. Measured on the real-540 corpus that silently discarded roughly
44% of the dynamic prompt bank, and it discarded the vulnerable samples
hardest: all 22 CWE-78 vulnerable labels came from one-argument prompts,
while two- and three-argument prompts produced zero across 68 samples. See
docs/ENGINEERING_LOG.md section 11.

The harness bodies run in a separate process with no import path back to
this repo, so this module exports its own source as HARNESS_PRELUDE for the
templates to prepend rather than being importable from inside the sandbox.
"""
from __future__ import annotations

# Parameter-name heuristics. Deliberately biased toward the numeric side:
# passing 1 where a string was wanted usually still executes, while passing
# "alice" where an int was wanted often raises before any sink is reached.
NUMERIC_HINTS = ("id", "num", "count", "qty", "quantity", "width", "height",
                 "port", "limit", "size", "age", "year", "offset", "page")
DATE_HINTS = ("date", "start", "end", "created", "updated", "since", "until")
# Parameters that name a column rather than hold a value. These need a real
# column name: code that whitelists identifiers (the standard mitigation,
# since column names cannot be parameterized) rejects anything else and
# never reaches its query, leaving the oracle with nothing to observe and
# forcing an abstention on a sample that is in fact cleanly safe.
COLUMN_HINTS = ("column", "sort", "order_by", "orderby", "field")

CONNECTION_PARAM_NAMES = ("conn", "connection", "db", "database", "cursor", "cur")


def benign_value_for(param_name: str) -> str | int:
    """
    A type-plausible, harmless value for one parameter, chosen from its name.

    Used to fill every parameter except the one currently carrying the
    payload, so that a multi-argument function can actually be invoked at
    all -- and for the control run, which establishes that the function
    executes SQL at all before any "safe" verdict is reached.

    Order matters: `sort_column` matches both the column and numeric lists,
    and `start_date` matches both the date and numeric lists; in each case
    the more specific hint is the right answer.
    """
    low = param_name.lower()
    if any(h in low for h in COLUMN_HINTS):
        return "name"
    if any(h in low for h in DATE_HINTS):
        return "2024-01-01"
    if any(h in low for h in NUMERIC_HINTS):
        return 1
    return "alice"


def takes_connection(param_names: list[str]) -> bool:
    """Whether the first parameter looks like a database connection."""
    return bool(param_names) and param_names[0].lower() in CONNECTION_PARAM_NAMES


HARNESS_PRELUDE = f"""
NUMERIC_HINTS = {NUMERIC_HINTS!r}
DATE_HINTS = {DATE_HINTS!r}
COLUMN_HINTS = {COLUMN_HINTS!r}
CONNECTION_PARAM_NAMES = {CONNECTION_PARAM_NAMES!r}


def benign_value_for(param_name):
    low = param_name.lower()
    if any(h in low for h in COLUMN_HINTS):
        return "name"
    if any(h in low for h in DATE_HINTS):
        return "2024-01-01"
    if any(h in low for h in NUMERIC_HINTS):
        return 1
    return "alice"


def positional_params(fn):
    import inspect
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return []
    return [
        p for p in sig.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]


def takes_connection(param_names):
    return bool(param_names) and param_names[0].lower() in CONNECTION_PARAM_NAMES
"""
