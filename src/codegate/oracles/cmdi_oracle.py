from __future__ import annotations
import tempfile
import uuid
from pathlib import Path
from codegate.oracles.ast_utils import function_exists
from codegate.oracles.invocation import (
    HARNESS_PRELUDE, benign_candidates, guarded_exec_source, harvest_affixes,
)
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

    The payload is tried in each parameter position in turn, rather than
    assuming a one-argument signature. The original harness always called
    `fn(payload)`, so every prompt asking for a wider signature raised
    TypeError and abstained: all 22 CWE-78 vulnerable labels in the
    real-540 corpus came from one-argument prompts, while two- and
    three-argument prompts produced zero across 68 samples. Positions are
    tried one at a time because a payload in a numeric parameter often
    raises before the shell call, which would otherwise mask a genuinely
    injectable parameter beside it. See docs/ENGINEERING_LOG.md section 11.

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
        # A payload that fails the code's own suffix/prefix check never
        # reaches the shell, so injection behind `path.endswith(".zip")`
        # was undetectable. Affixed variants carry the expected suffix
        # (via a trailing harmless `echo`) or prefix.
        prefixes, suffixes = harvest_affixes(code)
        payloads = ([payload_host]
                    + [f"{payload_host} & echo cg{sfx}" for sfx in suffixes]
                    + [pfx + payload_host for pfx in prefixes])

        harness = f"""
_fn = {function_name}
_params = positional_params(_fn)
_payloads = {payloads!r}
_allowlist = {benign_candidates(code)!r}


def _reached_a_spawn(args):
    # True when the call got as far as trying to start a process.
    try:
        _fn(*args)
        return True
    except FileNotFoundError:
        # The process could not be spawned because the target binary is
        # absent. That is itself evidence of SAFE behaviour: it can only
        # happen on the argv / shell=False path, because shell=True execs a
        # shell and a shell always exists (verified on this platform --
        # shell=True returns a non-zero exit code for a missing binary and
        # never raises). Without this, every near-miss sample calling a tool
        # the labelling machine lacks -- ffmpeg, gzip, git -- abstains.
        return True
    except Exception:
        return False


_observed = False

if not _params:
    # Nothing to inject into; the function takes no input at all.
    pass
else:
    # Control run first, with benign arguments. Near-miss code validates its
    # input and rejects the payload outright (a regex whitelist raising
    # ValueError is the canonical safe shape), so without a control run the
    # oracle never observes it doing anything and abstains -- which
    # discarded 33 of 58 CWE-78 near-miss samples in the real-540 corpus,
    # exactly the samples that teach the ranker what safe-but-alarming code
    # looks like.
    _benign = [benign_value_for(p.name) for p in _params]
    for _vec in benign_vectors(_params, _allowlist):
        if _reached_a_spawn(_vec):
            _observed = True
            _benign = _vec
            break

    for _payload in _payloads:
        for _i in range(len(_params)):
            _args = list(_benign)
            _args[_i] = _payload
            if _reached_a_spawn(_args):
                _observed = True

print("CODEGATE_DONE" if _observed else "CODEGATE_NOEVIDENCE")
"""
        # Preamble first, then the generated code, then the harness. The
        # preamble installs the missing-module stub finder, and the
        # generated code's imports run at module level -- putting the code
        # first means `import psycopg2` dies before the finder exists. The
        # code runs inside a guard so a crashing module-level example call
        # cannot kill the harness (see `guarded_exec_source`).
        full_source = (
            HARNESS_PRELUDE + "\n"
            + guarded_exec_source(code) + "\n"
            + harness
        )
        # Raised from 5s: the harness now makes one call per parameter
        # inside a single process instead of exactly one call overall.
        result = run_sandboxed(full_source, harness="", timeout_s=15.0)

        # A written sentinel is direct proof the payload reached a shell, so
        # it decides the verdict before anything else. Code that parses the
        # command's output afterwards (`int(output.split()[0])`) raises once
        # the payload has run, which used to read as "never reached a
        # spawn" and abstain on proven-vulnerable code.
        if sentinel.exists():
            return True
        if result.timed_out:
            return None
        if "CODEGATE_DONE" not in result.stdout:
            return None
        return False
