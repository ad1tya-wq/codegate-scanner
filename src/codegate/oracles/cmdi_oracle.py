from __future__ import annotations
import tempfile
import uuid
from pathlib import Path
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.sandbox import run_sandboxed


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
    if not function_exists(code, function_name):
        return None

    with tempfile.TemporaryDirectory() as tmp:
        sentinel = Path(tmp) / f"cg_pwned_{uuid.uuid4().hex}.txt"
        payload_host = f"127.0.0.1 & echo pwned > {sentinel}"

        harness = f"""
try:
    {function_name}({payload_host!r})
except Exception as e:
    print(f"CODEGATE_ERROR={{type(e).__name__}}")
print("CODEGATE_DONE")
"""
        full_source = code + "\n" + harness
        result = run_sandboxed(full_source, harness="", timeout_s=5.0)

        if result.timed_out:
            return None
        if "CODEGATE_DONE" not in result.stdout:
            return None

        return sentinel.exists()
