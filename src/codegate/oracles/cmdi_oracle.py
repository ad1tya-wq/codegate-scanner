from __future__ import annotations
import tempfile
import uuid
from pathlib import Path
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.sandbox import run_sandboxed


_SHELL_SINK_MARKERS = (
    "subprocess", "os.system", "os.popen", "os.exec", "os.spawn",
    "commands.", "pty.spawn", "shell=true",
)


def has_shell_sink(code: str) -> bool:
    """
    Cheap scope check: could this code plausibly invoke a shell or process?

    Same rationale as sqli_oracle.has_sql_sink -- a function that never
    spawns a process cannot contain command injection, so it is confidently
    safe rather than unjudgeable. Over-inclusive on purpose.
    """
    lowered = code.lower()
    return any(marker in lowered for marker in _SHELL_SINK_MARKERS)


def check_cmdi(code: str, function_name: str) -> bool | None:
    """
    Returns True if a shell-metacharacter payload causes a sentinel file to
    be created (proof the payload reached a shell), False if the function
    ran without creating it, None if the function doesn't exist or errored
    with no evidence either way.

    Payload uses `&` as the command separator (not `;`) so the check works
    identically whether the vulnerable code's `shell=True` call is executed
    via POSIX sh (dev/CI Linux, the eventual Docker sandbox) or cmd.exe
    (Windows dev machine): `&` sequences commands in cmd.exe, and in POSIX
    sh backgrounds the first command and runs the second immediately after
    -- both cause the sentinel-creating echo to run either way.
    """
    if not has_shell_sink(code):
        return False  # no process invocation anywhere: confidently safe

    if not function_exists(code, function_name):
        return None

    with tempfile.TemporaryDirectory() as tmp:
        sentinel = Path(tmp) / f"cg_pwned_{uuid.uuid4().hex}.txt"
        payload_host = f"127.0.0.1 & echo pwned > {sentinel}"

        harness = f"""
try:
    {function_name}({payload_host!r})
    print("CODEGATE_DONE")
except Exception as e:
    print(f"CODEGATE_ERROR={{type(e).__name__}}")
"""
        full_source = code + "\n" + harness
        result = run_sandboxed(full_source, harness="", timeout_s=5.0)

        if result.timed_out:
            return None
        if "CODEGATE_DONE" not in result.stdout:
            return None

        return sentinel.exists()
