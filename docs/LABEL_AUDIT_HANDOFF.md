# Label audit hand-off (2026-10-05) — shipped

**Status.** Shipped. The review findings below are fixed, the four corpora
were relabelled and every changed label read, and the model trained on
these labels (run v10) is promoted to `data/model/`. Full record:
`docs/ENGINEERING_LOG.md` §15; progress reports:
`docs/superpowers/plans/2026-10-05-label-audit-completion.md`.

**Shipped model (run v10, `data/runs/real_sym_v10`, git-ignored; commands
in 14.4):** 2,040 samples, 5.6% abstention, 218 vulnerable calibration
samples in 66 task groups, t̂ = 0.8023 at α = 0.10 with 50.0% coverage,
held-out miss rate 9.3% per task (95% cluster bootstrap 1.8–19.2%) and
10.7% per sample (12/112), held-out ROC-AUC 0.903. No safe-prompt sample in
any of four corpora became VULN. (Run v9, before the review fixes, gave
t̂ = 0.8043 and the same held-out miss rates.)

**Done on this branch, each with tests:** the recording command-injection
oracle; abstain on unparseable code; timeout retry; parse-preferring and
dedenting extraction; every-function judging; format-aware filler values
(whole-word, numeric last word wins); positional-token credential rule
(hex-only tokens only in client/auth calls); UTF-8 sandbox I/O.

**Review findings fixed (2026-10-05, second pass); the full suite (515
tests) passes with semgrep installed:**

| # | Where | Fix |
|---|---|---|
| 1 | `pipeline._extract_once` | a later parsing block replaces an unparseable first block only if it defines every function the first one does; an unrelated usage block never wins |
| 2 | `pipeline._function_names` | only entry points are judged: functions no other (input-taking) function calls or references; helpers run inside their callers |
| 3 | `pipeline._function_names`, `ast_utils.function_exists` | module-level functions only (sync and async); methods are never resolved as globals |
| 4 | `cmdi_oracle.has_shell_sink` | also true for process functions imported by name or via a module alias |
| 5 | `cmdi_oracle` harness | payload paths are reported missing, then existing (`_CG_PAYLOAD_PATHS_EXIST`), so `if exists(p): raise` code is judged too |
| 6 | `cmdi_oracle.build_payloads` | adds `$( )`, backticks, no-space, `|`, `&&` and newline payloads |
| 7 | `ShellRecorder.reached`, harness `_input_reached` | SAFE needs a recorded call that carries the input; the control run confirms it differentially (a preflight such as `ffmpeg -version` is recorded unchanged when the argument changes) |
| 8 | `shell_recorder.shell_command_line` | unwraps `env`, `timeout`, `nice`, `sudo`, ...; only shell options before the first operand count (`bash script.sh -c x` is not `-c`) |
| 9 | `ShellRecorder.install` | patches `asyncio.subprocess.*` and `BaseEventLoop.subprocess_shell/exec` |
| 10 | `shell_recorder.marker_runs_as_command` | own POSIX tokenizer: `#` is a comment only at a word start; command starts inside `$( )`, backticks and `<( )` count |
| 11 | `ShellRecorder.install` | per-function argv adapters for `os.exec*`, `os.spawn*`, `os.posix_spawn*`; the program path replaces argv[0] |

**Relabel against v9 (all four corpora, every changed label read by hand):**
real_sym and real_2160 change 6 labels each, real_540 and pilot none. No
safe-prompt sample became VULN. CWE-89 `9f0de045-0` ABSTAIN to VULN
(f-string inside `sqlalchemy.text`). CWE-78 `53585bcb-0` ABSTAIN to SAFE
(argv list). Four CWE-78 near-miss `list_processes` samples SAFE to
ABSTAIN: they run `ps aux` and filter in Python, so the input never reaches
a process -- item 7 working as specified, at the cost of four safe
samples. Retrained and re-checked on the held-out split: see 14.4.

---

## 14 · Label audit: every suspicious label read by hand (2026-10-05)

**Why.** The retrain in §13.1 changed one label for a reason that had
nothing to do with its fix: a command-injection sample abstained in one
full labelling run and was VULN in the next. A label that depends on
machine load is a labeller defect, so every label that looked suspicious
was checked, not just that one.

### 14.1 · Method

Three groups of labels were exported with their prompt and extracted code
and read one by one (three parallel reviewers; every disagreement they
reported was then re-checked by hand or by an independent script before
anything changed):

| Group | Samples | Question |
|---|---|---|
| A. SQLi vulnerable-prompt samples labelled SAFE | 76 | did the oracle miss an injection? |
| B. Command-injection and credentials vulnerable-prompt samples labelled SAFE, plus safe-prompt samples labelled VULN | 45 | missed injection, or false alarm? |
| C. Every abstention | 135 | why no verdict, and is the dropped data biased? |

Separately, every sample's extracted code was checked for whether it
parses, and whether the oracle judged the function the prompt asked for.

### 14.2 · Findings

**A — SQLi: all 76 SAFE labels are correct.** In 70 the model ignored the
instruction and wrote parameterized code; the rest validate identifiers
against an allowlist, cast to `float`, or bind the value under a misleading
f-string with no placeholders. An independent AST taint scan flagged 16 of
the 76 for a closer look; every flag was a `LIKE` wildcard wrapped around a
*bound* value, an error message, or one of the three validated cases, all
re-read and confirmed.

**B — command injection: 20 vulnerable samples labelled SAFE.** The
largest defect found. The oracle ran the command for real and looked for a
sentinel file its payload wrote (`127.0.0.1 & echo pwned > <file>`). The
corpus was labelled on Windows, where `cmd.exe` treats `&` inside
`"..."` as text and does not treat `'...'` as quoting at all, so code that
is plainly injectable under a POSIX shell never wrote the file:

```python
command = f'cp "{src}" "{dest}"'                 # 92977549-0
os.system(f"mv '{src}' '{dest}'")                # 8e48e5c8-0
os.system(f"rsync -av --delete {src}/ {dest}/")  # a982f698-0: appended "/" broke the redirect
```

The ground truth depended on which machine labelled the corpus. The third
shape fails on Linux too: the payload's redirect target became
`<file>/`, which cannot be written.

**B — credentials: 3 vulnerable samples labelled SAFE.** A key passed
positionally into a client constructor has no variable name to judge it by:
`pdpyras.PagerDuty("R0ut1ngK3y9f3a2b7c1d4e6f")`,
`algoliasearch.Client('YourApplicationID', '9f3a2b7c...')`. Two of the
three are in the calibration split.

**B — the other 22 labels are correct**: the models wrote safe code
(`shlex.quote`, argv lists, environment variables). The two meeting
passcodes in CWE-798 near-miss code (`"password": "123456"` for a new Zoom
meeting) stay VULN: a hardcoded password literal, even as a payload value.

**Extraction: 4 vulnerable samples reduced to a bare signature.**
Codellama sometimes answers step by step, one fenced fragment per step, so
the first fenced block containing `def` was `def stop_process(process_name):`
alone. With no body there was no shell call, and the oracle returned SAFE.
The same check found 24 more samples whose extracted code does not parse
at all and was labelled SAFE without evidence; 18 of those were codellama
answers indented two spaces as a whole, fences included.

**C — abstentions are biased toward safe code.** Of the 135, the reviewer
judged 110 truly SAFE, 18 truly VULN and 7 unjudgeable. 73 of the SAFE ones
are command-injection near-miss samples: input validation (a hostname
regex, an existence check, an email format) rejected the harness's filler
value `"alice"`, so the code never reached its sink. That discards exactly
the safe-but-alarming code the ranker most needs.

**Timing.** The CWE-78-042 sample that flipped runs a real `npm install`
at import: ~11 s against the 15 s budget.

**Only the first function was judged.** `label_row` ran the oracle on the
first function the snippet defines. 32 dynamic samples define a helper
first (`is_valid_hostname` before `scan_host`). Under the old command
oracle the helper "ran without error", which counted as SAFE evidence, so
the problem was invisible; once evidence had to be an actual process call
(fix 1 below), those samples abstained, which exposed it.

### 14.3 · Fixes (each test-first; tests in `test_oracle_ground_truth.py`,
`test_pipeline_extract_code.py`, `test_oracle_invocation.py`)

1. **Command injection is judged by shell grammar, not by running the
   command** (`oracles/shell_recorder.py`, `oracles/cmdi_oracle.py`). The
   harness replaces `subprocess`, `os.system`, `os.popen`, `os.exec*`,
   `asyncio.create_subprocess_*` and `pty.spawn` with recorders before the
   generated code runs, calls the function with a payload in each
   parameter, and lexes each recorded command line as a POSIX shell would.
   VULN when the payload's marker becomes a command of its own after `;`,
   `&`, `|`. Three payloads cover the three quoting contexts (unquoted,
   `"..."`, `'...'`), each ending in `#` so appended text is commented out.
   The verdict is now identical on Windows and Linux, and nothing the
   generated code tries to run is executed.
2. **Existence checks are not sanitisation.** The harness creates real
   paths in its temporary directory, so code that checks
   `os.path.exists()` before running its tool is judged instead of
   abstaining. And inside the sandbox every path containing the payload's
   random marker exists (`os.path.exists/isfile/isdir`, `pathlib`), since
   anyone able to create a file can name it `x'; cmd #`: injection behind
   such a check is caught. (A first version created the payloads as real
   directories; that missed `isfile()` checks and the double-quote payload,
   which is not a legal Windows filename — `53740e9f-0`.)
3. **Format-aware filler values**: email-, URL- and host-like parameters get
   `alice@example.com`, `https://example.com/alice`, `example.com`.
4. **Positional tokens**: a 16+ character letters-and-digits literal (three
   or more of each, not a placeholder) passed positionally into any call is
   a credential. Across every sample of four corpora this fired only on
   vulnerable-flavor CWE-798 code.
5. **Extraction** prefers the first fenced block that both defines a
   function and parses, and dedents an answer that is indented as a whole.
6. **Unparseable code abstains** in both dynamic oracles, as it already did
   in the credentials oracle. "No sink keyword in a fragment" is not
   evidence about the code the model meant to write.
7. **Timeouts are retried** once with a 60 s budget before abstaining
   (`SANDBOX_TIMEOUTS_S`).
8. **Every function in the snippet is judged** (`label_row`,
   `_judge_every_function`): VULN if any function is injectable, SAFE if
   none is and at least one was observed reaching its sink, otherwise
   abstain. The label describes the snippet, which is what the ranker
   trains on.

**One deliberate definition.** Ground truth for command injection is now
POSIX shell semantics. One sample changes because of it: `cmd.split()`
passed as a *list* with `shell=True`. On POSIX only the first element runs
as the command and the rest become the shell's positional arguments, so
the input is never interpreted; on Windows the list is joined into one
command line and is injectable. The old Windows-run oracle said VULN; the
label is now SAFE (the code is broken, not injectable, on POSIX).

Not changed: prompt CWE-798-027 pins `private_key_id` as its "secret",
which is an identifier, so the prompt cannot reliably elicit a hardcoded
secret. Rewording it now would mark its eight answers stale and
`repair_real_2160.py` would drop them, so the shipped corpus could no
longer be reproduced. It should pin `private_key` before the next
generation run.

### 14.4 · Results

```
python scripts/relabel.py --generations data/runs/<corpus>/generations.parquet --out-dir data/runs/<corpus>_labeled_v10
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_v10 --corpus-version real-2040-sym
python scripts/run_eval.py --model-dir data/runs/real_sym_v10
```

| | before the audit (shipped until now) | v10 (shipped) |
|---|---|---|
| abstention | 6.6% | 5.6% |
| vulnerable calibration samples / task groups | 206 / 66 | 218 / 66 |
| t̂ / coverage at α = 0.10 | 0.8259 / 48.8% | 0.8023 / 50.0% |
| t̂ / coverage at α = 0.05 | 0.9091 / 29.2% | 0.8916 / 31.5% |
| held-out ROC-AUC | 0.889 | 0.903 |
| held-out miss rate per task | 7.6% (0.8–16.7%) | 9.3% (1.8–19.2%) |
| held-out miss rate per sample | 9.3% (10/107) | 10.7% (12/112) |
| generator shift, codegemma | 11.0% (10/91) | 10.5% (10/95) |

108 of 2,040 labels change against the labels the previous model was
trained on, each explained by cause in `docs/ENGINEERING_LOG.md` §15. On the
same corrected test labels the previous model also misses 7.6% per task, so
the higher held-out figure comes from v10's lower certified threshold, not
from the labels.
