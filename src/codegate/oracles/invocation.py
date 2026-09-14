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


# Modules that must NEVER be stubbed out, whatever happens. Stubbing any of
# these would make the oracle observe a fake sink and report SAFE for code
# that is in fact injectable -- a silent false-safe, the worst failure this
# labeller can produce. They are all stdlib and therefore always importable,
# so the guard should be unreachable; it exists because the cost of being
# wrong here is a corrupted corpus rather than a crash.
NEVER_STUB = (
    "subprocess", "os", "sys", "sqlite3", "shlex", "shutil", "pathlib",
    "builtins", "importlib", "io", "tempfile",
)

HARNESS_PRELUDE = f"""
NEVER_STUB = {NEVER_STUB!r}


def _install_missing_module_stubs():
    # Generated code frequently imports a driver the labelling machine does
    # not have -- psycopg2 above all. That ImportError fires at module level,
    # before the target function is even defined, so the sample abstains
    # without the oracle ever seeing its SQL. Worse, it abstains
    # *systematically*: every Postgres-flavored sample is dropped, biasing
    # the corpus toward sqlite idiom, which is precisely the distribution
    # shift the certificate is meant to survive.
    #
    # This finder is appended to the END of sys.meta_path, so every real
    # finder gets first refusal and only genuinely absent modules reach it.
    import sys
    import types
    from importlib.machinery import ModuleSpec

    def _stub_getattr(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _make_stub(name)

    class _StubMeta(type):
        def __getattr__(cls, name):
            if name.startswith("__"):
                raise AttributeError(name)
            return _make_stub(name)

    def _make_stub(name):
        # Subclasses Exception so `except psycopg2.Error:` is legal --
        # catching a non-BaseException raises TypeError at handling time.
        return _StubMeta(name, (Exception,), {{
            "__getattr__": _stub_getattr,
            "__enter__": lambda self: self,
            "__exit__": lambda self, *exc: False,
            "__iter__": lambda self: iter(()),
            "__len__": lambda self: 0,
        }})

    class _StubLoader:
        def create_module(self, spec):
            mod = types.ModuleType(spec.name)
            # __path__ makes the stub a package, so a dotted import like
            # `mysql.connector` resolves its submodule through this finder
            # too instead of raising "'mysql' is not a package".
            mod.__path__ = []
            mod.__getattr__ = lambda name: _make_stub(name)
            return mod

        def exec_module(self, module):
            return None

    class _StubFinder:
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in NEVER_STUB:
                return None
            return ModuleSpec(fullname, _StubLoader())

    sys.meta_path.append(_StubFinder())


_install_missing_module_stubs()


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
