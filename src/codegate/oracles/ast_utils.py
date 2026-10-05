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


def module_level_functions(tree: ast.AST) -> list:
    """Function definitions the module binds as globals, in source order:
    top-level `def`/`async def`, including ones under a module-level
    `if`/`try`/`with`, but not methods or functions nested in functions --
    the harness calls the entry point by its global name, so only these
    can be called."""
    found = []

    def visit(stmts):
        for node in stmts:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append(node)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.AsyncWith)):
                visit(node.body)
                visit(getattr(node, "orelse", []))
            elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
                visit(node.body)
                for h in node.handlers:
                    visit(h.body)
                visit(node.orelse)
                visit(node.finalbody)

    visit(getattr(tree, "body", []))
    return found


def function_exists(code: str, function_name: str) -> bool:
    """True if `code` parses and defines a module-level function (sync or
    async) named `function_name`. Used by the dynamic oracles to decide
    whether a generated snippet even has the expected entry point before
    attempting to execute it. A method of the same name does not count:
    the harness resolves the name in module globals, where `Scanner.run`
    is not bound and `run` may be an imported `subprocess.run`."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    return any(node.name == function_name for node in module_level_functions(tree))
