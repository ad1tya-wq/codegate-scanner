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
import shlex
from pathlib import Path

# Shells whose `-c` argument is itself a command line, for code that avoids
# shell=True but builds the same thing: subprocess.run(["bash", "-c", cmd]).
_POSIX_SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "ash")
_CONTROL_OPERATORS = (";", "&", "&&", "|", "||", "|&", ";;")


def shell_command_line(args, shell: bool):
    """
    The string a POSIX shell would interpret for this invocation, or None
    when no shell is involved (an argv list with shell=False is passed to
    the program verbatim, so nothing in it can be injected).

    With shell=True and a list, POSIX `subprocess` runs `/bin/sh -c args[0]`,
    so the first element is the command line.
    """
    if shell:
        if isinstance(args, (str, bytes)):
            return args.decode(errors="replace") if isinstance(args, bytes) else args
        if isinstance(args, (list, tuple)) and args:
            first = args[0]
            return first.decode(errors="replace") if isinstance(first, bytes) else str(first)
        return None
    if isinstance(args, (list, tuple)) and len(args) >= 3:
        argv = [a.decode(errors="replace") if isinstance(a, bytes) else str(a) for a in args]
        if os.path.basename(argv[0]) in _POSIX_SHELLS:
            for i, a in enumerate(argv[1:-1], start=1):
                # -c, or a short-option cluster containing c (-lc, -ec).
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                    return argv[i + 1]
    return None


def marker_runs_as_command(command_line: str, marker: str) -> bool:
    """
    True when `marker`, read by a POSIX shell lexer, is the first word of a
    command of its own -- directly after a control operator (`;`, `&`, `|`,
    `&&`, `||`). That is the definition of command injection: the input
    stopped being data inside one command and started a new one.

    Quoting is handled by the grammar: `shlex.quote`d input, or input
    inside double quotes with `"` escaped, stays one word and never fires.
    A trailing `#` in the payload comments out whatever the code appended
    after the value. Malformed command lines (an unclosed quote) do not
    count as a hit for that command.
    """
    lexer = shlex.shlex(command_line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    return any(tok == marker and i > 0 and tokens[i - 1] in _CONTROL_OPERATORS
               for i, tok in enumerate(tokens))


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
        """Whether the code got as far as trying to start any process."""
        return bool(self.calls)

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

        def fake_argv_call(*args, **kwargs):
            # os.exec*/os.spawn*/os.posix_spawn*: a path plus an argv list,
            # never a shell. Recorded so "the code reached a process" is seen.
            argv = next((a for a in args if isinstance(a, (list, tuple))), list(args))
            recorder._record(list(argv), False)
            return 0

        os.system = fake_system
        os.popen = fake_popen
        for name in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp",
                     "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
                     "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                setattr(os, name, fake_argv_call)

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

        asyncio.create_subprocess_shell = fake_create_shell
        asyncio.create_subprocess_exec = fake_create_exec

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
