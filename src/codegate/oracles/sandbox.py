from __future__ import annotations
from dataclasses import dataclass
import platform
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


def _kill_process_tree(pid: int) -> None:
    """
    Kills `pid` and every descendant it spawned. `Popen.kill()` (what
    `subprocess.run(timeout=...)` uses internally on TimeoutExpired) only
    signals the direct child -- if the sandboxed code itself shells out
    (exactly what the cmdi detonation payload's target function does:
    subprocess.run(..., shell=True) / os.system(...)), that grandchild
    process survives the parent's death. On Windows especially, an
    orphaned grandchild (nslookup/ping/tar/git/etc., anything that can
    block on network or file I/O) keeps stdout/stderr pipe handles open,
    and Popen.communicate()'s read-until-EOF then blocks forever even
    though the "timeout" already fired -- confirmed empirically 2026-09-02:
    a real Track A retraining run hung for 56+ minutes at <1s of actual
    CPU time in the parent, on a real sample whose vulnerable function
    shelled out to a command that never returned.
    """
    if platform.system() == "Windows":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, timeout=10,
        )
    else:
        import os
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass  # already gone


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

        # A new process group (Windows) / session (POSIX) so a timeout can
        # kill the whole tree, not just this direct child -- see
        # _kill_process_tree's docstring for why that distinction is load-
        # bearing here, not defensive-programming for its own sake.
        creation_kwargs = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if platform.system() == "Windows"
            else {"start_new_session": True}
        )
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=tmp, **creation_kwargs,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            return SandboxResult(
                stdout=stdout, stderr=stderr,
                returncode=proc.returncode, timed_out=False,
            )
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            try:
                # Bounded reap, not for the output (callers never read
                # stdout/stderr when timed_out=True) but so the now-dead
                # process doesn't linger as a zombie. Never blocks
                # indefinitely even if this second wait also times out.
                proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
            return SandboxResult(stdout="", stderr="", returncode=-1, timed_out=True)
