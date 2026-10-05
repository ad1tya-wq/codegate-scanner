from __future__ import annotations
import ast


def parses(code: str) -> bool:
    """True if `code` is syntactically valid Python. The dynamic oracles
    abstain on code that doesn't parse: with no runnable function there is
    no evidence either way, and the absence of a sink keyword in a fragment
    says nothing about the code the model meant to write."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            ast.parse(code)
    except (SyntaxError, ValueError):  # ValueError: null bytes, Python < 3.12
        return False
    return True


def function_exists(code: str, function_name: str) -> bool:
    """True if `code` parses and defines a top-level or nested function
    named `function_name`. Used by the dynamic oracles to decide whether a
    generated snippet even has the expected entry point before attempting
    to execute it."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    return any(
        isinstance(node, ast.FunctionDef) and node.name == function_name
        for node in ast.walk(tree)
    )
