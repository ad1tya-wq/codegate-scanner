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


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def check_creds(code: str) -> bool:
    """
    Static-only oracle (no dynamic execution): flags a hardcoded credential
    when a string literal is (a) assigned to, passed as, or defaulted for a
    parameter/variable/kwarg whose name matches a secret-ish pattern, is not
    an obvious placeholder, and has high enough entropy or matches a known
    key-shape regex.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    placeholder_markers = {"changeme", "example", "xxx", "todo", "your_", "<", "insert"}

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
        if not literal or len(literal) < 6:
            continue
        if any(marker in literal.lower() for marker in placeholder_markers):
            continue

        if _shannon_entropy(literal) > 3.0 or any(p.search(literal) for p in _KNOWN_KEY_PATTERNS):
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
                if len(literal) >= 6 and not any(m in literal.lower() for m in placeholder_markers):
                    if _shannon_entropy(literal) > 2.5:
                        return True

    return False
