from __future__ import annotations
import ast
import math
import re

_SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|secret|api_key|apikey|access_key|token|credential)", re.IGNORECASE
)

_KNOWN_KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS access key id
    re.compile(r"[A-Za-z0-9/+=]{40}"),               # AWS-secret-shaped base64 (heuristic)
]

# Anything a developer would write to mean "not a real value". Matched as a
# substring against the lowercased literal.
_PLACEHOLDER_MARKERS = (
    "changeme", "change_me", "change-me", "example", "xxx", "todo",
    "your_", "your-", "yourpassword", "<", "insert", "placeholder",
    "dummy", "fake", "redacted", "n/a", "none", "null", "replace",
    "fill_in", "fillme", "sample", "test_value", "somepassword",
)

_MIN_SECRET_LEN = 6
# Entropy is no longer the gate for a secret-NAMED literal (see check_creds).
# It survives only as an independent trigger for a long, random-looking
# literal whose variable name gives nothing away.
_HIGH_ENTROPY_THRESHOLD = 3.5
_MIN_UNNAMED_SECRET_LEN = 20


def _is_placeholder(literal: str) -> bool:
    return any(marker in literal.lower() for marker in _PLACEHOLDER_MARKERS)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def check_creds(code: str) -> bool:
    """
    Static-only oracle (no dynamic execution): flags a hardcoded credential
    when a string literal is assigned to, passed as, or defaulted for a
    parameter/variable/kwarg whose name matches a secret-ish pattern, is
    long enough to be a real credential, and is not an obvious placeholder.

    Entropy is deliberately NOT part of that test. It used to be the gate,
    at `> 3.0`, and it rejected 'hunter2' (2.81), 'letmein' (2.52),
    'P@ssw0rd' (2.75), 'admin123' (3.00) and 's3cr3t' (2.25) -- five of nine
    realistic secrets. Real passwords are low-entropy by nature, and that is
    exactly what makes them bad passwords, not what makes them safe. On the
    real-540 corpus this defect labelled 49 of 58 CWE-798 vulnerable-flavor
    samples "safe" with zero abstentions: the oracle decided, and decided
    wrong. See docs/ENGINEERING_LOG.md section 11.

    Entropy survives only in the final name-independent sweep, where a long
    random-looking literal is a credential regardless of what it is called.

    The near-miss flavor reads from `os.environ`, which is a Call rather
    than a Constant and so never reaches any of these branches -- that is
    why loosening this rule does not put false positives into the corpus.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        name = None
        value_node = None

        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if targets:
                name = targets[0]
                value_node = node.value
        elif isinstance(node, ast.keyword) and isinstance(node.value, ast.Constant):
            name = node.arg
            value_node = node.value

        if name is None or not _SECRET_NAME_PATTERN.search(name):
            continue
        if value_node is None or not isinstance(value_node.value, str):
            continue

        literal = value_node.value
        if len(literal) < _MIN_SECRET_LEN or _is_placeholder(literal):
            continue

        # A string literal bound to a secret-named target, long enough to be
        # a real credential and not a placeholder, IS the finding.
        return True

    # also catch default-arg literals directly, e.g. def f(password="hunter2"):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = node.args.args[-len(node.args.defaults):] if node.args.defaults else []
            for arg, default in zip(args, node.args.defaults):
                if not _SECRET_NAME_PATTERN.search(arg.arg):
                    continue
                if not (isinstance(default, ast.Constant) and isinstance(default.value, str)):
                    continue
                literal = default.value
                if len(literal) >= _MIN_SECRET_LEN and not _is_placeholder(literal):
                    return True

    # Finally, a name-independent sweep: a long, random-looking literal or
    # one matching a known key shape is a hardcoded credential whatever the
    # variable is called -- `k = "AKIA..."` still leaks the key. The length
    # floor and the higher entropy bar keep ordinary prose and SQL strings
    # out; this branch never fires on the short, guessable passwords the
    # named branches above are there to catch.
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        literal = node.value
        if _is_placeholder(literal):
            continue
        if any(p.search(literal) for p in _KNOWN_KEY_PATTERNS):
            return True
        if (len(literal) >= _MIN_UNNAMED_SECRET_LEN
                and " " not in literal
                and _shannon_entropy(literal) > _HIGH_ENTROPY_THRESHOLD):
            return True

    return False
