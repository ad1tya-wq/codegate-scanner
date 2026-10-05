"""
A recording stand-in for every way Python code starts a process: runs
generated code while capturing each command it tries to run, instead of
running it.

Why this exists. The CWE-78 oracle used to detonate for real: a payload
`127.0.0.1 & echo pwned > <sentinel>` went into each parameter, the code
ran its shell command, and a written sentinel file proved injection. That
made the ground truth depend on the labelling machine's shell. The real
corpus was labelled on Windows, where cmd.exe treats `&` inside double
quotes as text and does not treat `'...'` as quoting at all, so code that
is plainly injectable under a POSIX shell -- `f'cp "{src}" "{dest}"'`,
`f"mv '{src}' '{dest}'"` -- never wrote the sentinel and was labelled SAFE.
The payload's own redirect also broke whenever the code appended text to
the value (`f"rsync {src}/ {dest}/"` redirects into `<sentinel>/`, which
cannot be written). A full-corpus audit found 20 vulnerable samples
mislabelled SAFE this way (docs/ENGINEERING_LOG.md section 14). Real
execution also ran whatever the generated code did at import -- one sample
ran a real `npm install` -- and made verdicts depend on machine load.

Recording at the call boundary removes all three problems. Nothing is
executed; the oracle sees the exact command string the code built and asks
the question that defines command injection: read the way a POSIX shell
reads it, does the payload's marker become a command of its own? The
verdict is the same on every platform, and quoting is judged by the shell
grammar rather than by whichever shell happened to run.

This is still a dynamic oracle -- the generated function genuinely runs,
so commands assembled across helpers, loops and string formatting are
observed as finally built. Only the last step, starting the process, is
replaced. Self-contained and stdlib-only: its source is exported as
RECORDER_SOURCE for the sandbox harness, like dbapi_recorder.
"""
from __future__ import annotations

import io
import os
import re
from pathlib import Path

# Shells whose `-c` argument is itself a command line, for code that avoids
# shell=True but builds the same thing: subprocess.run(["bash", "-c", cmd]).
_POSIX_SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "busybox")

# Commands that run the rest of their argv as another command:
# `env bash -c ...`, `timeout 5 sh -c ...`, `nice -n 10 bash -c ...`.
# Value: the options of that wrapper that consume the next argument.
_WRAPPERS = {
    "env": ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"),
    "timeout": ("-s", "--signal", "-k", "--kill-after"),
    "nice": ("-n", "--adjustment"),
    "ionice": ("-c", "--class", "-n", "--classdata", "-p", "--pid"),
    "stdbuf": ("-i", "-o", "-e"),
    "sudo": ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"),
    "doas": ("-u", "-C"),
    "nohup": (),
    "setsid": (),
    "exec": ("-a",),
    "command": (),
    "time": ("-f", "--format", "-o", "--output"),
    "chroot": (),
    "xargs": ("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"),
}
# Wrappers whose first non-option argument is consumed before the command.
_WRAPPER_POSITIONAL = {"timeout": 1, "chroot": 1}
# Shell options that take the next argument as their value (`bash -o pipefail`).
_SHELL_OPTS_WITH_VALUE = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}

_CONTROL_OPERATORS = {";", "&", "&&", "|", "||", "|&", ";;", "\n", "("}
_REDIRECTIONS = {"<", ">", ">>", "<<", "<<-", "<&", ">&", ">|", "<>", "&>", "&>>"}
_OPERATORS = sorted(_CONTROL_OPERATORS | _REDIRECTIONS | {")"}, key=len, reverse=True)
# Words after which the next word is still a command position.
_RESERVED = {"!", "{", "}", "then", "do", "else", "elif", "if", "while", "until", "time"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _text(a) -> str:
    return a.decode(errors="replace") if isinstance(a, (bytes, bytearray)) else str(a)


def _shell_c_argument(argv: list[str]) -> str | None:
    """
    The command line in `argv` when argv[0] is a POSIX shell given `-c`.
    Only options before the first operand belong to the shell:
    `bash backup.sh -c x` runs a script and passes it `-c x`.
    """
    if not argv or os.path.basename(argv[0]) not in _POSIX_SHELLS:
        return None
    rest = argv[1:]
    if os.path.basename(argv[0]) == "busybox":  # `busybox sh -c ...`
        if not rest or rest[0] not in _POSIX_SHELLS:
            return None
        rest = rest[1:]
    wants_command = False
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            i += 1
            break
        if a in _SHELL_OPTS_WITH_VALUE:
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if len(a) > 1 and a[0] in "-+":
            if a[0] == "-" and "c" in a[1:]:
                wants_command = True
            i += 1
            continue
        break  # first operand
    if wants_command and i < len(rest):
        return rest[i]
    return None


def _unwrap(argv: list[str]) -> list[str]:
    """Strip leading wrapper commands (`env`, `timeout 5`, `nice -n 5`, ...)
    and `VAR=value` assignments taken by `env`."""
    for _ in range(8):  # wrappers can nest: `sudo env timeout 5 sh -c ...`
        if not argv:
            return argv
        name = os.path.basename(argv[0])
        if name not in _WRAPPERS:
            return argv
        takes_value = _WRAPPERS[name]
        positional = _WRAPPER_POSITIONAL.get(name, 0)
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "--":
                i += 1
                break
            if a in takes_value:
                i += 2
                continue
            if a.startswith("-") and len(a) > 1:
                i += 1
                continue
            if name == "env" and _ASSIGNMENT.match(a):
                i += 1
                continue
            if positional:
                positional -= 1
                i += 1
                continue
            break
        argv = argv[i:]
    return argv


def shell_command_line(args, shell: bool):
    """
    The string a POSIX shell would interpret for this invocation, or None
    when no shell is involved (an argv list with shell=False is passed to
    the program verbatim, so nothing in it can be injected).

    With shell=True and a list, POSIX `subprocess` runs `/bin/sh -c args[0]`,
    so the first element is the command line. An argv list reaches a shell
    when it is `sh -c <line>`, possibly behind wrapper commands
    (`/usr/bin/env bash -c`, `timeout 5 sh -c`).
    """
    if shell:
        if isinstance(args, (str, bytes, bytearray)):
            return _text(args)
        if isinstance(args, (list, tuple)) and args:
            return _text(args[0])
        if isinstance(args, os.PathLike):
            return os.fspath(args)
        return None
    if isinstance(args, (list, tuple)) and len(args) >= 3:
        argv = [_text(os.fspath(a)) if isinstance(a, os.PathLike) else _text(a) for a in args]
        return _shell_c_argument(_unwrap(argv))
    return None


class _Malformed(ValueError):
    pass


def _skip_balanced(s: str, i: int, open_: str, close: str) -> int:
    """Index just past the `close` matching an already-consumed `open_`."""
    depth = 1
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _Malformed
            i = j + 1
            continue
        if s.startswith(open_, i):
            depth += 1
            i += len(open_)
            continue
        if s.startswith(close, i):
            depth -= 1
            i += len(close)
            if depth == 0:
                return i
            continue
        i += 1
    raise _Malformed


def _backtick_body(s: str, i: int) -> tuple[str, int]:
    """Body of a `...` substitution starting after its opening backtick."""
    body = []
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "`\\$":
            body.append(s[i + 1])
            i += 2
            continue
        if c == "`":
            return "".join(body), i + 1
        body.append(c)
        i += 1
    raise _Malformed


def _dollar(s: str, i: int, starts: list[str]) -> int:
    """At s[i] == '$': consume an expansion, recording command starts found
    in a command substitution. Returns the index after it."""
    if s.startswith("$((", i):
        return _skip_balanced(s, i + 3, "((", "))")
    if s.startswith("$(", i):
        return _parse(s, i + 2, starts, nested=True)
    if s.startswith("${", i):
        return _skip_balanced(s, i + 2, "{", "}")
    return i + 1


def _parse(s: str, i: int, starts: list[str], nested: bool = False) -> int:
    """
    Tokenise a command line the way a POSIX shell does, appending the first
    word of every simple command (including those inside `$( )`, backticks
    and `<( )`) to `starts`. Returns the index after the closing `)` when
    `nested`, else len(s). Raises _Malformed on an unclosed quote or
    substitution.
    """
    tokens: list[tuple[str, str]] = []  # ("op", text) | ("word", literal)
    word: list[str] | None = None
    depth = 0

    def end_word():
        nonlocal word
        if word is not None:
            tokens.append(("word", "".join(word)))
            word = None

    while i < len(s):
        c = s[i]
        if c in " \t":
            end_word()
            i += 1
            continue
        if c == "#" and word is None:
            # A comment only where a word would start; `issue#1` is a word.
            j = s.find("\n", i)
            i = len(s) if j < 0 else j
            continue
        if c == "\\":
            if i + 1 < len(s) and s[i + 1] == "\n":  # line continuation
                i += 2
                continue
            word = (word or []) + [s[i + 1:i + 2]]
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _Malformed
            word = (word or []) + [s[i + 1:j]]
            i = j + 1
            continue
        if c == '"':
            word = word or []
            i += 1
            while True:
                if i >= len(s):
                    raise _Malformed
                d = s[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and i + 1 < len(s) and s[i + 1] in '$`"\\\n':
                    word.append(s[i + 1])
                    i += 2
                elif d == "$":
                    j = _dollar(s, i, starts)
                    word.append(s[i:j])
                    i = j
                elif d == "`":
                    body, j = _backtick_body(s, i + 1)
                    _parse(body, 0, starts)
                    word.append(s[i:j])
                    i = j
                else:
                    word.append(d)
                    i += 1
            continue
        if c == "$":
            j = _dollar(s, i, starts)
            word = (word or []) + [s[i:j]]
            i = j
            continue
        if c == "`":
            body, j = _backtick_body(s, i + 1)
            _parse(body, 0, starts)
            word = (word or []) + [s[i:j]]
            i = j
            continue
        if c in "<>" and s.startswith("(", i + 1):  # process substitution
            end_word()
            i = _parse(s, i + 2, starts, nested=True)
            tokens.append(("word", "<procsub>"))
            continue
        op = next((o for o in _OPERATORS if s.startswith(o, i)), None)
        if op is not None:
            if op == ">" and word is not None and "".join(word).isdigit():
                word = None  # `2>file`: the fd number belongs to the redirection
            end_word()
            if op == ")":
                if depth == 0:
                    if nested:
                        _collect_starts(tokens, starts)
                        return i + 1
                    raise _Malformed
                depth -= 1
            elif op == "(":
                depth += 1
            tokens.append(("op", op))
            i += len(op)
            continue
        word = (word or []) + [c]
        i += 1
    if nested:
        raise _Malformed
    end_word()
    _collect_starts(tokens, starts)
    return i


def _collect_starts(tokens, starts: list[str]) -> None:
    at_start = True
    skip_next_word = False
    for kind, text in tokens:
        if kind == "op":
            if text in _REDIRECTIONS:
                skip_next_word = True
            elif text == ")":
                at_start = False
            else:
                at_start = True
            continue
        if skip_next_word:
            skip_next_word = False
            continue
        if at_start:
            if _ASSIGNMENT.match(text) or text in _RESERVED:
                continue
            starts.append(text)
            at_start = False


def command_starts(command_line: str) -> list[str] | None:
    """The first word of every command a POSIX shell would run for this
    line, or None when the line is malformed."""
    starts: list[str] = []
    try:
        _parse(command_line, 0, starts)
    except _Malformed:
        return None
    return starts


def marker_runs_as_command(command_line: str, marker: str) -> bool:
    """
    True when `marker`, read the way a POSIX shell reads the line, is the
    first word of a command of its own: after a control operator (`;`,
    `&`, `|`, `&&`, `||`, a newline) or inside a command substitution
    (`$(...)`, backticks, also within double quotes). That is the
    definition of command injection: the input stopped being data inside
    one command and started a new one.

    Quoting is handled by the grammar: `shlex.quote`d input, or input
    inside double quotes with `"`, `$` and backticks escaped, stays one
    word and never fires. `#` starts a comment only at the start of a word,
    as in a POSIX shell (`issue#1` is one word). Malformed command lines
    (an unclosed quote) do not count as a hit for that command.
    """
    starts = command_starts(command_line)
    return bool(starts) and marker in starts


class ShellRecorder:
    """
    Replaces the process-starting functions of `subprocess`, `os`,
    `asyncio`, `pty` and `shutil.which` with recorders. Every invocation is
    stored as (command_line_or_None, args); nothing runs. Fakes return what
    a successful, silent command would: exit status 0, empty output.
    """

    def __init__(self):
        self.calls: list[tuple[str | None, object]] = []

    def reset(self):
        self.calls = []

    @property
    def observed(self) -> bool:
        """Whether the code got as far as trying to start any process.
        Not evidence on its own: see reached()."""
        return bool(self.calls)

    @staticmethod
    def _call_text(line, args) -> str:
        """Everything the process receives: the argv (or command string),
        plus the shell's command line when one was derived. With
        shell=True and a list, the elements after the first still reach
        the shell, as its positional parameters."""
        if isinstance(args, (list, tuple)):
            text = "\0".join(_text(os.fspath(a)) if isinstance(a, os.PathLike) else _text(a)
                              for a in args)
        else:
            text = _text(os.fspath(args)) if isinstance(args, os.PathLike) else _text(args)
        return text if line is None or line == text else line + "\0" + text

    def reached(self, values) -> bool:
        """
        Whether one of `values` -- the arguments the function was called
        with -- appears in a recorded process call. Reaching *a* process is
        not enough: a `--version` preflight runs before the input is used,
        and the fake empty output can stop the code there. Only a call that
        carries the input is evidence about how the input is handled.
        Strings match as substrings (realpath(), prefixes and quoting keep
        them visible); short strings and numbers must be a whole word.
        """
        texts = [self._call_text(line, args) for line, args in self.calls]
        if not texts:
            return False
        words = None
        for v in values:
            if isinstance(v, bool) or v is None:
                continue
            sv = _text(v)
            if not sv or sv == ".":
                continue
            if isinstance(v, str) and len(sv) >= 3:
                if any(sv in t for t in texts):
                    return True
                continue
            if words is None:
                words = {w.strip("'\"") for t in texts for w in re.split(r"[\s\0=,:]+", t)}
            if sv in words:
                return True
        return False

    def injected(self, marker: str) -> bool:
        return any(line is not None and marker_runs_as_command(line, marker)
                   for line, _ in self.calls)

    def _record(self, args, shell):
        self.calls.append((shell_command_line(args, shell), args))

    def install(self):
        import asyncio
        import shutil
        import subprocess

        recorder = self

        def _text_mode(kwargs):
            return bool(kwargs.get("text") or kwargs.get("universal_newlines")
                        or kwargs.get("encoding") or kwargs.get("errors"))

        def _empty(kwargs):
            return "" if _text_mode(kwargs) else b""

        class FakePopen:
            def __init__(self, args, *a, shell=False, **kwargs):
                recorder._record(args, shell)
                self.args = args
                self.returncode = 0
                self.pid = 4242
                empty = _empty(kwargs)
                stream = (lambda: io.StringIO("") if isinstance(empty, str) else io.BytesIO(b""))
                pipe = subprocess.PIPE
                self.stdout = stream() if kwargs.get("stdout") == pipe else None
                self.stderr = stream() if kwargs.get("stderr") == pipe else None
                self.stdin = stream() if kwargs.get("stdin") == pipe else None
                self._empty = empty

            def communicate(self, input=None, timeout=None):
                return (self._empty if self.stdout is not None else None,
                        self._empty if self.stderr is not None else None)

            def wait(self, timeout=None):
                return 0

            def poll(self):
                return 0

            def kill(self):
                pass

            def terminate(self):
                pass

            def send_signal(self, sig):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_run(args, *a, shell=False, capture_output=False, check=False, **kwargs):
            recorder._record(args, shell)
            captured = capture_output or kwargs.get("stdout") == subprocess.PIPE
            out = _empty(kwargs) if captured else None
            err = _empty(kwargs) if (capture_output or kwargs.get("stderr") == subprocess.PIPE) else None
            return subprocess.CompletedProcess(args, 0, out, err)

        def fake_call(args, *a, shell=False, **kwargs):
            recorder._record(args, shell)
            return 0

        def fake_check_output(args, *a, shell=False, **kwargs):
            recorder._record(args, shell)
            return _empty(kwargs)

        def fake_getoutput(cmd, *a, **kwargs):
            recorder._record(cmd, True)
            return ""

        def fake_getstatusoutput(cmd, *a, **kwargs):
            recorder._record(cmd, True)
            return (0, "")

        subprocess.Popen = FakePopen
        subprocess.run = fake_run
        subprocess.call = fake_call
        subprocess.check_call = fake_call
        subprocess.check_output = fake_check_output
        subprocess.getoutput = fake_getoutput
        subprocess.getstatusoutput = fake_getstatusoutput

        def fake_system(cmd):
            recorder._record(cmd, True)
            return 0

        def fake_popen(cmd, mode="r", buffering=-1):
            recorder._record(cmd, True)
            return io.StringIO("")

        def _argv_of(name, args):
            # os.exec*/os.spawn*/os.posix_spawn*: a program path plus its
            # argv, never a shell unless the program is one. The path is
            # what runs, so it replaces argv[0] for judging.
            #   execl(path, *argv)          execle(path, *argv, env)
            #   execv(path, argv[, env])    posix_spawn(path, argv, env, ...)
            #   spawnl(mode, path, *argv)   spawnle(mode, path, *argv, env)
            #   spawnv(mode, path, argv[, env])
            spawn = name.startswith("spawn")
            off = 1 if spawn else 0
            if len(args) <= off:
                return list(args)
            path = args[off]
            core = name[5:] if spawn else (name[4:] if name.startswith("exec") else "v")
            if core.startswith("l"):
                argv = list(args[off + 1:])
                if core.endswith("e") and argv:
                    argv = argv[:-1]
            else:
                argv = args[off + 1] if len(args) > off + 1 else []
                argv = list(argv) if isinstance(argv, (list, tuple)) else [argv]
            return [path] + argv[1:]

        def _make_argv_fake(name):
            def fake(*args, **kwargs):
                recorder._record(_argv_of(name, args), False)
                return 0
            return fake

        def fake_argv_call(*args, **kwargs):  # pty.spawn(argv)
            argv = next((a for a in args if isinstance(a, (list, tuple))), list(args))
            recorder._record(list(argv), False)
            return 0

        os.system = fake_system
        os.popen = fake_popen
        for name in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp",
                     "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
                     "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                setattr(os, name, _make_argv_fake(name))

        class FakeAsyncProcess:
            returncode = 0
            pid = 4242
            stdin = stdout = stderr = None

            async def communicate(self, input=None):
                return (b"", b"")

            async def wait(self):
                return 0

            def kill(self):
                pass

            def terminate(self):
                pass

        async def fake_create_shell(cmd, *a, **kwargs):
            recorder._record(cmd, True)
            return FakeAsyncProcess()

        async def fake_create_exec(program, *args, **kwargs):
            recorder._record([program, *args], False)
            return FakeAsyncProcess()

        import asyncio.subprocess as asyncio_subprocess
        import asyncio.base_events as asyncio_base_events
        # `asyncio.create_subprocess_shell` is a re-export: code that calls
        # `asyncio.subprocess.create_subprocess_shell` (or imports it from
        # there) bypasses a patch of the package attribute alone.
        for mod in (asyncio, asyncio_subprocess):
            mod.create_subprocess_shell = fake_create_shell
            mod.create_subprocess_exec = fake_create_exec

        class FakeTransport:
            def get_pid(self):
                return 4242

            def get_returncode(self):
                return 0

            def get_pipe_transport(self, fd):
                return None

            def close(self):
                pass

            def kill(self):
                pass

            def terminate(self):
                pass

        async def fake_loop_shell(self, protocol_factory, cmd, *a, **kwargs):
            recorder._record(cmd, True)
            return FakeTransport(), protocol_factory()

        async def fake_loop_exec(self, protocol_factory, program, *args, **kwargs):
            recorder._record([program, *args], False)
            return FakeTransport(), protocol_factory()

        asyncio_base_events.BaseEventLoop.subprocess_shell = fake_loop_shell
        asyncio_base_events.BaseEventLoop.subprocess_exec = fake_loop_exec

        try:
            import pty
            pty.spawn = lambda argv, *a, **k: fake_argv_call(argv if isinstance(argv, (list, tuple)) else [argv])
        except ImportError:  # Windows has no pty
            pass

        # Every tool is assumed installed: code that checks shutil.which()
        # before running ffmpeg would otherwise stop before its command is
        # built, on whichever machine lacks ffmpeg.
        shutil.which = lambda cmd, *a, **k: "/usr/bin/" + os.path.basename(str(cmd))


try:
    RECORDER_SOURCE = Path(__file__).read_text(encoding="utf-8")
except (NameError, OSError):  # pragma: no cover - only in an exec'd copy
    RECORDER_SOURCE = ""
