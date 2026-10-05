from __future__ import annotations
import re
import uuid
from codegate.oracles.ast_utils import function_exists, parses
from codegate.oracles.invocation import (
    HARNESS_PRELUDE, benign_candidates, guarded_exec_source, harvest_affixes,
)
from codegate.oracles.sandbox import SANDBOX_TIMEOUTS_S, run_sandboxed
from codegate.oracles.shell_recorder import RECORDER_SOURCE


_SHELL_SINK_MARKERS = (
    "subprocess", "os.system", "os.popen", "os.exec", "os.spawn", "posix_spawn",
    "commands.", "pty.spawn", "shell=true",
)

_FUTURE_IMPORT = re.compile(r"^from __future__ import .*$", re.MULTILINE)

# Modules whose functions start processes, for `from os import system`,
# `import os as o` and similar spellings the keyword scan cannot see.
_PROCESS_MODULES = {"os", "subprocess", "asyncio", "asyncio.subprocess", "pty", "commands", "posix", "nt"}
_PROCESS_FUNCTIONS = re.compile(
    r"^(system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|Popen|run|call|check_call|"
    r"check_output|getoutput|getstatusoutput|create_subprocess_(shell|exec)|spawn|"
    r"subprocess_(shell|exec))$")


def _imports_process_function(code: str) -> bool:
    import ast
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _PROCESS_MODULES:
            if any(a.name == "*" or _PROCESS_FUNCTIONS.match(a.name) for a in node.names):
                return True
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name in _PROCESS_MODULES and a.asname:
                    aliases.add(a.asname)
        elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
              and node.value.id in aliases and _PROCESS_FUNCTIONS.match(node.attr)):
            return True
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "__import__"):
            return True
    return False


def has_shell_sink(code: str) -> bool:
    """
    Cheap scope check: could this code plausibly invoke a shell or process?

    Same rationale as sqli_oracle.has_sql_sink -- a function that never
    spawns a process cannot contain command injection, so it is confidently
    safe rather than unjudgeable. Over-inclusive on purpose: a miss here is
    a confident SAFE label on code the oracle never ran, so process
    functions imported by name (`from os import system`) or through a
    module alias (`import os as o; o.system`) count too.
    """
    lowered = code.lower()
    if any(marker in lowered for marker in _SHELL_SINK_MARKERS):
        return True
    return _imports_process_function(code)


def build_payloads(marker: str, prefixes: list[str], suffixes: list[str]) -> list[str]:
    """
    Breakout payloads, one per quoting context the value might land in:
    unquoted, inside "...", inside '...'; then command substitution and
    payloads that avoid spaces or `;`, since a blocklist of either is not
    sanitisation. The breakouts end in `#`, so whatever the
    code appends after the value (`{src}/`, `{path}.bak`) becomes a shell
    comment instead of breaking the injected command. Affixed variants
    carry a suffix the code checks with `.endswith()` (after the `#`, so it
    is commented out too) or a prefix it checks with `.startswith()`.
    """
    bases = [
        # Breakouts with `;`, one per quoting context.
        f"127.0.0.1; {marker} #", f'x"; {marker} #', f"x'; {marker} #",
        # Command substitution: runs unquoted and inside "...", needs no
        # separator, no space, and survives code that escapes `"` only.
        f"$({marker})", f"`{marker}`",
        # No spaces at all, for code that rejects whitespace.
        f"127.0.0.1;{marker};#",
        # Other separators, for code that blocklists `;`.
        f"127.0.0.1 | {marker} #", f"127.0.0.1 && {marker} #", f"127.0.0.1\n{marker}\n#",
        f"127.0.0.1|{marker}|#",
    ]
    payloads = []
    for base in bases:
        payloads.append(base)
        payloads += [base + sfx for sfx in suffixes]
        payloads += [pfx + base for pfx in prefixes]
    return payloads


_HARNESS = '''
_fn = {function_name}
_params = positional_params(_fn)
_payloads = {payloads!r}
_marker = {marker!r}
_allowlist = {allowlist!r}


def _invoke(args, evidence):
    """Call the function once; return (the input reached a process call,
    injected). `evidence` are the values that must show up in a recorded
    call for it to count as the input reaching a process."""
    import asyncio
    import inspect
    _REC.reset()
    try:
        result = _fn(*args)
        if inspect.iscoroutine(result):
            asyncio.run(result)
    except KeyboardInterrupt:
        raise
    except BaseException:
        # SystemExit included: generated code calls sys.exit() on bad input.
        # The command, if any, is already recorded.
        pass
    return _REC.reached(evidence), _REC.injected(_marker)


def _call_texts():
    return [_REC._call_text(line, a) for line, a in _REC.calls]


def _input_reached(vec):
    """
    Whether some argument of `vec` reached a process call because it was
    the input. A benign value can also be a word the code itself uses
    (`ffmpeg` harvested from `['ffmpeg', '-version']`), so a match alone is
    not proof: the argument is changed and the call re-recorded. A call
    that carried the input changes or disappears; a preflight that never
    saw it is recorded again unchanged.
    """
    if not _invoke(vec, vec)[0]:
        return False
    before = _call_texts()
    for _j, _v in enumerate(vec):
        if isinstance(_v, bool) or not isinstance(_v, (str, int)):
            continue
        if not _REC.reached([_v]):
            continue
        _carrying = [t for t in before if str(_v) in t]
        _probe = list(vec)
        _probe[_j] = (_v + 7919) if isinstance(_v, int) else (_v + "cgprobe")
        _invoke(_probe, [])
        _after = set(_call_texts())
        if any(t not in _after for t in _carrying):
            return True
    return False


# Existing paths for code that checks os.path.exists/isdir/isfile before
# running its tool: every name-based filler failed that check, so 16
# CWE-78 near-miss samples never reached their command and abstained. The
# sandbox runs in its own temporary directory, so these are created there,
# along with a real file for each harvested filename-like candidate
# ("alice.zip" for code that also checks the suffix).
import os as _os
_os.makedirs("cg_dir", exist_ok=True)
for _name in ["cg_file.txt"] + [v for v in _allowlist if isinstance(v, str)
                                and "." in v and not any(c in v for c in "/" + chr(92))]:
    try:
        open(_name, "a").close()
    except OSError:
        pass
_allowlist = list(_allowlist) + [".", "cg_dir", "cg_file.txt"]

_fired = False
_observed = False

if _params:
    # Control run first, with benign arguments. Near-miss code validates its
    # input and rejects the payload outright (a regex allowlist raising
    # ValueError is the canonical safe shape), so without a control run the
    # oracle never observes it reaching a process and abstains -- which
    # discarded 33 of 58 CWE-78 near-miss samples in the real-540 corpus.
    # It counts only when a benign argument shows up in a recorded call.
    _benign = None
    for _vec in benign_vectors(_params, _allowlist):
        if _input_reached(_vec):
            _observed = True
            _benign = _vec
            break
    if _benign is None:
        _benign = [benign_value_for(p.name) for p in _params]

    # Each payload is tried with payload paths reported missing (the real
    # filesystem), then reported existing: code guarded by `if not
    # exists(p)` and code guarded by `if exists(p): raise` both reach
    # their command in one of the two.
    for _exist in (False, True):
        _CG_PAYLOAD_PATHS_EXIST[0] = _exist
        for _payload in _payloads:
            for _i in range(len(_params)):
                _args = list(_benign)
                _args[_i] = _payload
                _reached, _hit = _invoke(_args, [_marker])
                _observed = _observed or _reached
                if _hit:
                    _fired = True
                    break
            if _fired:
                break
        if _fired:
            break
    _CG_PAYLOAD_PATHS_EXIST[0] = False

if _fired:
    print("CODEGATE_VERDICT=VULNERABLE")
elif _observed:
    print("CODEGATE_VERDICT=SAFE")
else:
    print("CODEGATE_VERDICT=NOEVIDENCE")
'''


# An existence check is not sanitisation: anyone able to create a file can
# name it `x'; cmd #`. Inside the sandbox, while _CG_PAYLOAD_PATHS_EXIST[0]
# is set, every path containing this run's marker exists -- as a file and
# as a directory -- so injection behind
# os.path.isfile()/exists()/isdir() or pathlib's is_file()/exists()/is_dir()
# is caught on every platform (a `"` cannot appear in a Windows filename,
# so creating the payloads for real would miss that context). Installed
# before the generated code runs, so `from os.path import isfile` binds it
# too. The marker is random per call, so no other path can match. The
# harness also runs every payload with the switch off: code that refuses
# an existing path (`if exists(p): raise FileExistsError`) is just as
# injectable, and an always-on override hid it.
_PATHS_EXIST_FOR_PAYLOADS = '''
_CG_PAYLOAD_PATHS_EXIST = [False]


def _cg_paths_exist_for_payloads(marker):
    import os
    import pathlib

    def _wrap(orig):
        def check(p, *a, **k):
            try:
                if _CG_PAYLOAD_PATHS_EXIST[0] and marker in os.fspath(p):
                    return True
            except TypeError:
                pass
            return orig(p, *a, **k)
        return check

    for name in ("exists", "lexists", "isfile", "isdir"):
        setattr(os.path, name, _wrap(getattr(os.path, name)))
    for name in ("exists", "is_file", "is_dir"):
        orig = getattr(pathlib.Path, name)
        setattr(pathlib.Path, name,
                (lambda o: lambda self, *a, **k: True if (_CG_PAYLOAD_PATHS_EXIST[0] and marker in str(self))
                 else o(self, *a, **k))(orig))


_cg_paths_exist_for_payloads({marker!r})
'''


def _build_source(code: str, function_name: str, marker: str) -> str:
    """
    Preamble (missing-module stubs), then the recorder, installed before the
    generated code runs so that `from subprocess import run` binds the
    recorder too; then the generated code inside a guard (a crashing
    module-level example call cannot kill the harness); then the harness.
    `from __future__` lines are stripped from the embedded recorder: such a
    statement is only legal first in a file.
    """
    prefixes, suffixes = harvest_affixes(code)
    return (
        HARNESS_PRELUDE + "\n"
        + _FUTURE_IMPORT.sub("", RECORDER_SOURCE) + "\n"
        + "_REC = ShellRecorder()\n_REC.install()\n"
        + _PATHS_EXIST_FOR_PAYLOADS.format(marker=marker)
        + guarded_exec_source(code) + "\n"
        + _HARNESS.format(
            function_name=function_name,
            payloads=build_payloads(marker, prefixes, suffixes),
            marker=marker,
            allowlist=benign_candidates(code),
        )
    )


def check_cmdi(code: str, function_name: str) -> bool | None:
    """
    Returns True when a payload placed in one of the function's parameters
    becomes a command of its own in a command line the function hands to a
    shell -- judged by POSIX shell grammar on the recorded command line
    (see shell_recorder). False when the function was observed reaching a
    process call and no payload broke out: argv lists with shell=False,
    `shlex.quote`, allowlist validation. None when the code doesn't parse,
    the function is absent or takes no parameters, or its input never
    reached a process call -- no evidence either way. A process call that
    does not carry the input (a `--version` preflight) is not evidence.

    Nothing is executed. The previous design ran the command for real and
    looked for a sentinel file, which tied the verdict to the labelling
    machine's shell: on Windows (cmd.exe), double-quoted and single-quoted
    interpolation never wrote the sentinel, so 20 vulnerable samples in the
    shipped corpus were labelled SAFE. See docs/ENGINEERING_LOG.md
    section 14.

    The payload is tried in each parameter position in turn, rather than
    assuming a one-argument signature: the original harness always called
    `fn(payload)`, so every prompt asking for a wider signature abstained
    (docs/ENGINEERING_LOG.md section 11). Positions are tried one at a
    time because a payload in a numeric parameter often raises before the
    command is built, which would otherwise mask an injectable parameter
    beside it.
    """
    if not parses(code):
        return None  # no runnable code, so no evidence either way

    if not has_shell_sink(code):
        return False  # no process invocation anywhere: confidently safe

    if not function_exists(code, function_name):
        return None

    marker = "cgpwn" + uuid.uuid4().hex[:12]
    source = _build_source(code, function_name, marker)
    # A timeout is retried once with a longer budget (see SANDBOX_TIMEOUTS_S).
    # Rare now that no command actually runs, but generated code can still
    # loop, sleep or block on the network on its own.
    for timeout_s in SANDBOX_TIMEOUTS_S:
        result = run_sandboxed(source, harness="", timeout_s=timeout_s)
        if not result.timed_out:
            break
    if result.timed_out:
        return None
    if "CODEGATE_VERDICT=VULNERABLE" in result.stdout:
        return True
    if "CODEGATE_VERDICT=SAFE" in result.stdout:
        return False
    return None
