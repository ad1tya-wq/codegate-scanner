from __future__ import annotations
from dataclasses import dataclass
import subprocess
import sys
import tempfile
from pathlib import Path


@dataclass(frozen=True)
class SandboxResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool


def run_sandboxed(code: str, harness: str, timeout_s: float = 5.0) -> SandboxResult:
    """
    Execute `code` (optionally preceded by `harness` setup code) as a fresh
    Python subprocess with a wall-clock timeout.

    TONIGHT: this is a best-effort *process-level* isolation only (no network
    disable, no container, no filesystem readonly) -- Docker Desktop is not
    running. It is written so `oracles/consensus.py` and every oracle above
    it never sees the difference: swap this function's body for a
    `docker run --network none --read-only ...` invocation (see
    `docker/poc_sandbox.Dockerfile`) once Docker Desktop is available, and
    nothing downstream changes. DO NOT run this against untrusted
    LLM-generated code until that swap happens -- see NEEDS_FROM_YOU.md.
    """
    full_source = harness + "\n" + code
    with tempfile.TemporaryDirectory() as tmp:
        script_path = Path(tmp) / "snippet.py"
        script_path.write_text(full_source)
        try:
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=tmp,
            )
            return SandboxResult(
                stdout=proc.stdout, stderr=proc.stderr,
                returncode=proc.returncode, timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            return SandboxResult(
                stdout=e.stdout or "", stderr=e.stderr or "",
                returncode=-1, timed_out=True,
            )
