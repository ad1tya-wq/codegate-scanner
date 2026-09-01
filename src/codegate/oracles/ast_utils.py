from __future__ import annotations
import ast


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
