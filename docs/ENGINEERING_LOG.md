# CodeGate Scanner — Engineering Log

## 1 · How to read this

This log records what has actually been built, what decisions were made
and why, and how confident we should be in each piece — separately from
the plan, which records what we *intend* to build. Every claim below cites
a commit hash, a test name, or a command output reproduced in this
session; if a claim can't be traced to one of those three, it doesn't
belong here.

Four status labels are used throughout:

| Label | Means |
|---|---|
| **SOLID** | Built, unit-tested, and verified end-to-end against a real run |
| **NEEDS INTEGRATION** | Built and unit-tested, but only exercised in isolation — not yet run as part of a full pipeline pass |
| **PROVISIONAL** | Runs and produces output, but that output is not yet trustworthy (interim data, interim model) |
| **NOT STARTED** | Planned, not built |

## 2 · Status at a glance

| Phase | What | Status | Commit(s) | Tests |
|---|---|---|---|---|
| 0 | New repo + migration | SOLID | `5712ea3` | baseline green |
| 1 | Fix the foundation (4 defects) | SOLID | `b84e2c9` | 89 passed |
| 1.5 | Ollama-only corpus generation + `--generate-only` | SOLID (mechanism) / PROVISIONAL (data) | `ba642e7` | 89 passed |
| 2 | Persistence layer (`research/artifacts.py`) | SOLID (mechanism) / PROVISIONAL (current artifact) | `8f5bed3` | 97 passed |
| 3 | Packaging + CLI (`info`, `calibrate` solid; `scan` scaffolded) | SOLID (`info`/`calibrate`) / NOT STARTED (`scan` — Phase 4-7 dependency) | `e1dbff4` | 104 passed |
| 4 | Ingest (`scan/ingest.py`) | SOLID | `2bbdd2c` | 113 passed |
| 5 | Scan pipeline (`scan/pipeline.py`, `scan/findings.py`) | SOLID (mechanism) / PROVISIONAL (model-gate numbers, per §6) | `0861a16` | 120 passed |
| 6 | LLM verifier (`scan/verifier.py`) | SOLID (live-verified 2026-09-02, see decision #11) | `ca0f368` | 134 passed |
| 7 | Reporting + CLI wiring (`report/`, `codegate scan`) | SOLID (mechanism) / PROVISIONAL (model-gate numbers, cost estimates, per §6) | — | 176 passed |
| 9 | Demo assets (`examples/vulnerable_app/`) | SOLID | — | 177 passed |
| — | Evaluation & metrics (`research/eval/metrics.py`, `scripts/run_eval.py`) | SOLID (mechanism) / PROVISIONAL (ranker-quality numbers, per §6) | — | 187 passed |
| 8 | Retrain on real corpus (join point) | SOLID — first attempt (516 samples, §11) certified nothing; after the oracle repairs and the 2,160-sample run, certified and shipped as `real-2040-sym` at α = 0.10 (§12) | `13d8b83`–`e7723fc` | 416 passed |

Current test suite: **442 passed**, 0 failed, ~10 min wall clock (2026-10-04)
(`python -m pytest tests/ -q`, verified this session).

## 3 · Per-phase entries

### Phase 0 — New repo + migration — `SOLID`

**What was done.** Stood up `ad1tya-wq/codegate-scanner` (private) and
migrated the research half from the v1 repo (`ad1tya-wq/codegate`):
`gate/`, `oracles/`, `ranker/`, `research/corpus/`, `research/generation/`,
`research/eval/`, prompts, semgrep rules, and the test suite. Restructured
`src/codegate/` so `research/` (offline, rare) and `scan/` (online,
constant — not yet populated) are separate top-level packages from the
start, rather than retrofitting the split later.

**Decisions taken and why.**
- New repo, not a branch — the tool being built (`codegate scan <path>`)
  is a materially different deliverable from the research pipeline it's
  built on, and the old repo stays intact as the v1 research archive.
- `pyproject.toml` rewritten from scratch: `[build-system]`,
  `[project.scripts]`, full `dependencies`, `[tool.setuptools.packages.find]`
  — none of this existed in v1, where `pip install -e .` did not work at
  all.

**Evidence.** Commit `5712ea3`. Migrated suite ran green before any Phase 1
changes were applied (baseline preserved, not skipped).

**Status rationale.** `SOLID` — this is infrastructure, not logic; "did
the migration preserve behavior" is fully answered by the green baseline.

---

### Phase 1 — Fix the foundation — `SOLID`

**What was done.** Closed four verified defects in the inherited research
pipeline, then hardened the SQLi/cmdi oracles against real (non-simulated)
model output ahead of Track A.

**Decisions taken and why, in the order they were found:**

1. **SQLi label bug.** The vulnerable-flavor template emitted
   `SELECT * FROM t`, but the dynamic harness only ever created a table
   named `users`. Every invocation raised `no such table: t`, the oracle
   returned `None` (abstain), and abstention was — at the time — silently
   coerced to "safe" downstream. Verified before the fix:
   `dynamic_verdict={None: 540}` across the full simulated run: **every**
   CWE-89 sample abstained, vulnerable-flavor label mean was `0.0`.
   → *Fixed twice, deliberately*: first by aligning the template's table
   name with the harness fixture, then (see item 5) by widening the
   fixture itself so this class of mismatch can't recur with real models.

2. **Abstention coerced to "safe."** `label_row` had no third state — a
   `None` verdict from any oracle became label `0`. This is the defect
   that let #1 hide: a systematically-abstaining oracle looks identical to
   a systematically-safe corpus. → Introduced `LABEL_ABSTAIN = -1` as a
   distinct value (`research/pipeline.py:33-35`), excluded from training
   and calibration (`research/pipeline.py:163,181`), with a printed
   warning when the abstention rate exceeds 20% of the batch.

3. **Config values hardcoded past the config object.** `pipeline.py` had
   `delta=0.1` and `alpha=0.2, delta=0.1` written literally at two call
   sites, while `config.yaml` and the docs both claimed `0.05/0.05`.
   Verified: 7 of 8 fields on `CodeGateConfig` were read by zero code at
   the time. → `run_full_pipeline` now reads `cfg.alpha`/`cfg.delta`
   throughout (`research/pipeline.py:203,211`).

4. **LTT threshold-search trace was computed and discarded.**
   `LTTResult.trace` (the per-threshold `(t, k, p_value, certified)` tuples
   that are the actual evidence behind `t_hat`) was never written to disk.
   → `run_full_pipeline` now persists it to `ltt_trace.csv`
   (`research/pipeline.py:211-214`).

5. **Sink-scope reasoning added to the SQLi and cmdi oracles — beyond the
   original plan.** The initial fix (item 1) still abstained on any code
   that touched SQL/shell APIs but under a function name the harness
   didn't try — genuinely unjudgeable. But it also abstained on code that
   never touched SQL or a shell *at all* (e.g. a Celsius-to-Fahrenheit
   converter), which cannot possibly be vulnerable to SQLi or cmdi. Adding
   `has_sql_sink()` (`oracles/sqli_oracle.py:59-71`) and `has_shell_sink()`
   (`oracles/cmdi_oracle.py:15-24`) — a cheap, deliberately over-inclusive
   keyword scope check — lets the oracle return a confident `False`
   instead of `None` for such code. This recovered 60 previously-discarded
   negative samples and moved the CWE-89 corpus from 37.50% vulnerable
   (still had abstentions) to the theoretically correct **33.33%
   vulnerable, 0 abstentions** (1 of 3 prompt flavors is the vulnerable
   one).
6. **Two test-premise corrections — flagged explicitly, because "changed
   a test to make it pass" deserves scrutiny, not a quiet diff.**
   `test_check_sqli_returns_none_when_function_missing` and
   `test_abstention_is_its_own_label_not_safe` both originally used
   no-SQL-sink code as their example of "unjudgeable." Once item 5 landed,
   the correct oracle answer for that exact input is `False` (confidently
   safe), not `None` — so the *tests'* premise was wrong, not the code.
   Both were rewritten to use SQL-touching code that lacks the named
   function instead — genuinely unjudgeable, which is the case they were
   meant to cover. See `tests/test_oracles.py:59-67` and
   `tests/test_oracle_robustness.py:63-74`; the latter's docstring records
   the reasoning inline.

7. **Windows/POSIX-portable cmdi payload.** The command-injection detonation
   payload originally used `;` as a separator, which POSIX shells accept
   but `cmd.exe` (the Windows dev machine's default) does not. Switched to
   `&`, which sequences commands under `cmd.exe` and backgrounds-then-runs
   under POSIX `sh` — both cause the sentinel-creating `echo` to fire
   regardless of host OS (`oracles/cmdi_oracle.py:33-39`, reasoning in the
   docstring).

8. **One LTT test assumption was simply wrong, not the algorithm.**
   `test_perfect_separation_certifies_full_coverage` asserted coverage
   `> 0.9` under 50/50 class balance, and failed at `0.507`. Investigation
   showed the algorithm is correct — under 50/50 balance, coverage is
   structurally capped near 50%, since roughly half the *safe* population
   also falls below any threshold high enough to exclude the vulnerable
   half. Fixed the test's fixture to use realistic 20% vulnerable
   prevalence and asserted `> 0.75`.

**Evidence.** Commit `b84e2c9`. Simulated 540-sample run: CWE-89 vulnerable
rate 33.33% (was 22.22% with abstentions silently zeroed), 0 abstentions.
89/89 tests passing including two new regression suites written for this
phase (`tests/test_generation_resume.py`, `tests/test_oracle_robustness.py`
— see §7).

**Status rationale.** `SOLID` — every defect has a named regression test
that fails on the old code and passes on the new code; verified by running
the suite before and after.

---

### Phase 1.5 — All-Ollama corpus generation + `--generate-only` — mechanism `SOLID`, data `PROVISIONAL`

**What was done.** Reworked corpus generation for a zero-API-key,
zero-shared-network path: `config.yaml` generators switched to four local
Ollama models (`qwen2.5-coder:7b`, `deepseek-coder:6.7b`, `codellama:7b`,
`starcoder2:7b`), `samples_per_prompt: 3 → 1` (540-sample target),
`scripts/run_real.py` rewritten around `OllamaBackend` with a `preflight()`
check that gives a distinct diagnosis for "Ollama unreachable" (firewall)
vs "connection refused" (`OLLAMA_HOST` not rebound) rather than one opaque
traceback.

**Decisions taken and why.**
- **`--generate-only` flag, added specifically so a teammate can run this
  on their own machine.** Labeling executes the dynamic oracles, which run
  generated code in a subprocess (`oracles/sandbox.py`) — acceptable on
  the research machine, not acceptable to ask of someone else's personal
  laptop. `--generate-only` stops after writing `generations.parquet` and
  never calls `label_row`. This is a real code boundary, not a
  documentation-only promise: `label_row`/`check_sqli`/`check_cmdi` are
  simply never imported on that path (`scripts/run_real.py:123-152`).
- **Checkpoint/resume rewritten around content-derived IDs, not `uuid4`.**
  `harness.py::_sample_id` now derives from `stable_seed()` (sha256 of
  `prompt_id|generator|k`), not Python's randomized `hash()` or a random
  UUID — both would make every resumed run regenerate everything, which
  defeats the point of a multi-hour unattended run being resumable at all.
  Every successful sample is appended to a JSONL checkpoint immediately
  (`harness.py:119-121`), and per-sample generation failures are caught
  and logged rather than aborting the whole run (`harness.py:93-105`).
- **Empty-result guard.** If Ollama dies before producing a single sample,
  `run_real.py` now raises a `SystemExit` naming the likely cause and the
  exact resume command, instead of surfacing pandas' generic schema
  validation error.

**A verification detail worth recording:** the first attempt to confirm
`_sample_id` was reproducible across two separate runs showed a *false*
mismatch — traced to pandas' unstable default sort on tied keys, not to
the seeding logic. Re-verified with `sort(..., kind='stable')` →
`IDENTICAL: True`. Recorded here because it's the kind of false alarm that
looks like a real regression on the first pass.

**Evidence.** Commit `ba642e7`. `docs/OLLAMA_SETUP.md` rewritten to match
(host-runs-everything, no shared Wi-Fi assumed). 89/89 tests still passing
after this commit — this phase touched no oracle or labeling logic.

**Status rationale — split, deliberately.** The *mechanism* (checkpoint,
resume, preflight diagnostics, generate-only split) is `SOLID`: unit
tested in `tests/test_generation_resume.py` and exercised against
`SimulatedBackend`. The *data it will eventually produce* is
`PROVISIONAL` until Track A's real 540-sample run completes and is
sanity-checked — see §6.

---

### Phase 2 — Persistence layer — mechanism `SOLID`, current artifact `PROVISIONAL`

**What was done.** Added `research/artifacts.py`: `save_model`/`load_model`
(model.joblib via `joblib`), `save_calibration`/`load_calibration`
(calibration.json via stdlib `json`), and `load_artifacts` — a combined
loader that enforces the version guard the plan called for.

**Decisions taken and why.**
- **Version guard via a class attribute on the ranker, not a hardcoded
  string in the artifacts module.** Added `R2Ranker.RANKER_ID = "R2"`
  (`ranker/r2_embedding_lr.py`) and made `save_calibration`'s `ranker_id`
  default to it, so the calibration's recorded ranker identity can't drift
  from what actually produced the scores. `load_artifacts` raises
  `ArtifactVersionError` if a loaded calibration's `ranker_id` doesn't
  match the loaded model's — tested directly
  (`test_load_artifacts_rejects_ranker_id_mismatch`).
- **G1 (provisional flagging) implemented by deriving from the existing
  `is_simulated` flag, not a new parameter.** `run_full_pipeline` already
  receives `is_simulated`; it was already the caller's signal for "is this
  real data." `corpus_version = "simulated-v2" if is_simulated else
  "real-540"`, `is_provisional = is_simulated`
  (`research/pipeline.py`, right after the operating `LTTResult` is
  computed). No new call-site parameters needed at `scripts/run_real.py`
  or `scripts/run_pipeline_dry_run.py`.
- **Wired directly into `run_full_pipeline`, not left as an unused
  module.** The plan named persistence a "hard blocker — no tool without
  this"; a persistence *module* nobody calls doesn't close that blocker.
  `save_model`/`save_calibration` are now called in the same branch that
  already computes the certified operating point, so every full pipeline
  run (simulated dry run today, the eventual real run) writes
  `model.joblib` + `calibration.json` to `out_dir` as a side effect,
  matching the layout `codegate scan`/`codegate info` (Phase 3) will
  expect.

**Evidence.** `tests/test_artifacts.py` (8 tests): round-trip for both
model and calibration, missing-file error messages, the `None`-`t_hat`
(uncertified) case, and the version-guard rejection. Extended
`tests/test_dry_run.py` to assert the full pipeline actually produces
`model.joblib` and `calibration.json`, and that the written
`calibration.json` has `is_provisional: true`, `corpus_version:
"simulated-v2"`, `ranker_id: "R2"` — i.e. this is checked against a real
subprocess run of the pipeline, not just the unit-level round trip. 89 → 97
tests passing.

**Status rationale — split, same reasoning as Phase 1.5.** The persistence
*mechanism* is `SOLID`: it round-trips correctly, the version guard is
tested to actually reject a mismatch, and it's wired into the real
pipeline rather than sitting unused. The *artifact it currently produces*
is `PROVISIONAL` because it's trained on the simulated corpus — which is
exactly what `is_provisional: true` in the written file now states
outright, closing the loop on G1's purpose.

### Phase 3 — Packaging + CLI — `info`/`calibrate` `SOLID`, `scan` `NOT STARTED`

**What was done.** Added `cli.py`: a `typer` app with three subcommands
(`info`, `calibrate`, `scan`), installed as the `codegate` console script
via the `[project.scripts]` entry already declared in `pyproject.toml`
since Phase 0. Packaging itself needed no changes — `pyproject.toml`'s
`[build-system]`/dependencies/src-layout were already complete from the
Phase 0 migration, so this phase was purely `cli.py` plus verifying the
install actually works.

**Decisions taken and why.**
- **`info` and `calibrate` are fully functional now; `scan` is an honest
  scaffold, not a stub pretending to work.** `scan` needs ingest (Phase 4)
  and the scan pipeline (Phase 5) to do anything real. Rather than leave
  the command unregistered (which would make `pip install -e .` +
  `codegate scan ...` fail with an unhelpful "no such command") or fake a
  result, it validates its full argument surface (`--format` against the
  four allowed values) and then prints an explicit "not implemented yet,
  here's which phases it's waiting on" message, exiting with code `2`
  (distinct from `0` success / `1` error) rather than crashing or looking
  like a silent no-op. The project's own honesty discipline
  (`is_provisional`, G1) applies to the CLI's own incompleteness too, not
  just to model quality.
- **`scan`'s argument surface is fixed now, before the implementation
  exists.** `--format {pdf,json,sarif,terminal}`, `--output`, `--no-llm`,
  `--alpha` — all present and validated today, so Phases 5-7 land as an
  implementation swap behind an already-stable CLI contract, not a
  redesign.
- **`codegate calibrate` unifies `scripts/run_pipeline_dry_run.py` and
  `scripts/run_real.py`'s backend-selection logic under one command**
  (`--real` flag switches `SimulatedBackend` → `OllamaBackend`, mirroring
  `run_real.py::build_backends`) rather than importing from `scripts/`
  (not an installed package) or duplicating `run_full_pipeline`'s call.
  The two standalone scripts are left as-is for the specific unattended /
  diagnostic-output use cases they're already tuned for (Track A's
  multi-hour host run in particular) — this is a convenience layer, not a
  replacement.
- **Established `data/model/` as the canonical artifact location.** Not
  specified by the plan beyond "commit trained artifacts"; picked a fixed
  directory (independent of any particular run's `--out-dir`, which
  varies) so `codegate info` and the future `codegate scan` have one
  answer for "where's the model" without a config lookup. Ran
  `codegate calibrate` and committed the result — `data/model/model.joblib`
  + `calibration.json` (correctly `is_provisional: true`,
  `corpus_version: "simulated-v2"`) — so a fresh clone can run
  `codegate info` with zero setup, closing that locked decision from the
  original plan.
- **Found and fixed a real version-string bug while verifying the
  install.** `src/codegate/__init__.py` had `__version__ = "0.1.0"` while
  `pyproject.toml` declares `0.2.0` — and `docs/OLLAMA_SETUP.md` step A4
  explicitly tells the host to run
  `python -c "import codegate; print('CodeGate', codegate.__version__)"`
  and expect `CodeGate 0.2.0`. That verification step would have failed
  for the teammate running the setup guide. Bumped `__init__.py` to match.
- **Avoided the `§` section-symbol character in CLI-printed strings.**
  Found it renders as mojibake (`�3`) in a default-codepage Windows
  terminal — the team's actual environment — when first testing `scan`'s
  and `info`'s output. Replaced with plain "Part 3" / "section 6" wording
  in user-facing CLI text specifically (doc files themselves are
  unaffected, since they're read as UTF-8 rather than printed to a
  legacy-codepage console).

**Evidence.** `codegate --help` lists all three commands after
`pip install -e .`. `codegate calibrate` (simulated, full 135-prompt bank)
reproduced the exact numbers already recorded in section 6 of this log
(33.33% vulnerable rate, `t_hat ≈ 0.6613`, 66.7% coverage at alpha=0.05) —
consistent with the earlier measurement being a real, reproducible number
and not a one-off. `codegate info` against the result correctly prints the
`PROVISIONAL` banner. `tests/test_cli.py` (7 tests, via `typer.testing.CliRunner`)
covers: missing-model error message, certificate printing with and without
the provisional banner, `ArtifactVersionError` surfaced through the CLI,
invalid `--format` rejection, the "not implemented" exit code on `scan`,
and an end-to-end `calibrate` run that asserts the artifact files land on
disk.

**Status rationale.** `info` and `calibrate` are `SOLID` — tested via
`CliRunner`, and independently verified by hand against the real
`data/model/` artifacts now committed. `scan` is correctly `NOT STARTED`;
what exists is a tested, honest scaffold, not a partial implementation of
the scan pipeline itself.

### Phase 4 — Ingest (`scan/ingest.py`) — `SOLID`

**What was done.** Added `scan/ingest.py`: `ingest_path(path)` turns a
file or directory into function-level `Unit`s (file, lineno, func_name,
source, content_hash, token_estimate), the first module in the ONLINE
half. Recursive directory walk skips `venv`/`.venv`/`site-packages`/`.git`/
`__pycache__` unconditionally and honors a `.gitignore` at the scan root
for everything else. Every `FunctionDef`/`AsyncFunctionDef` node becomes
its own unit, including nested functions and methods.

**Decisions taken and why.**
- **A lightweight `.gitignore` reader, not a full parser.** Supports plain
  names, directory patterns, and glob wildcards — the overwhelming
  majority of real `.gitignore` content — but explicitly does not support
  negation (`!pattern`) lines; they're skipped rather than mishandled.
  Documented as an intentional scope limit in the function's own
  docstring, not a silent gap: a real gitignore parser (full negation,
  anchoring, `**` semantics) is more machinery than a scanner needs, and
  claiming full compatibility while actually being wrong on negated
  patterns would be worse than an honest partial implementation.
- **Function-level units include nested functions and methods, not just
  top-level defs.** The plan calls for "function-level units" because the
  ranker was trained on function-sized snippets; a method or a nested
  closure is exactly as function-sized as a top-level function, so
  excluding them would silently shrink scan coverage on any
  class-heavy or closure-heavy codebase for no principled reason.
- **`SkippedFile` as an explicit result field, not a log line.** An
  unreadable or unparseable file disappearing from a scan without a
  trace in the *return value* is exactly the class of silent-failure this
  project's own `LABEL_ABSTAIN` design (Phase 1) exists to prevent on the
  research side — applied here to ingest. `IngestResult` always carries
  both `units` and `skipped` together so a caller can't see one without
  the other.
- **A single file bypasses `.gitignore`/skip-dir filtering entirely.** If
  the user names a file directly (`codegate scan somefile.py`), that's an
  explicit request that shouldn't be second-guessed by directory-walk
  heuristics meant for "don't wander into `venv/`."

**Evidence.** `tests/test_ingest.py` (9 tests): single-file extraction,
nested/method extraction, lineno/hash correctness, hash stability across
identical functions in different files, syntax-error and unreadable-file
reporting without dropping good files, missing-path error, directory walk
with `venv` skip, `.gitignore` honoring. Also run by hand against the
repo's own `src/` tree: **62 units, 0 skipped files** — a real
"does it actually work on non-fixture code" check, not just synthetic
`tmp_path` cases. 113 tests passing (was 104).

**Status rationale.** `SOLID` — tested against both synthetic edge cases
and the real codebase, and its scope limits (no gitignore negation) are
stated in the code rather than discovered by a future bug report.

### Phase 5 — Scan pipeline (`scan/pipeline.py`, `scan/findings.py`) — `SOLID`

**What was done.** Added `run_scan(path, model_dir)`, wiring
`ingest_path` → one directory-scale `run_semgrep_on_path` call → ranker
scoring → the certified LTT gate, and `Finding`, the typed record every
downstream stage (verifier, reporting) will consume. `Finding.source`
is validated to be one of `semgrep` / `model` / `verifier` at
construction — the field the report's detection-attribution table
(Phase 7) is built around. Semgrep findings map back to the containing
`Unit` via `_map_to_unit`, which picks the innermost (smallest-range)
enclosing function when ranges overlap (a nested function inside a
flagged outer function). Units that don't clear the gate (`score <
t_hat`, or every unit when `t_hat is None`) become `source="model"`
findings with `cwe="UNSPECIFIED"` — Phase 6's verifier is what resolves
CWE and confirms/clears them; until then they're the scan's "needs
review" output.

**Decisions taken and why.**
- **One semgrep invocation over the whole target, not one per unit.**
  This is the fix `r0_semgrep_score.py`'s own docstring flagged as
  necessary before directory-scale use — confirmed unbuilt in Phase 4's
  entry, now built. `run_semgrep_on_path` (added to
  `oracles/semgrep_oracle.py`, sharing `_run_semgrep_cli` with the
  existing per-snippet `run_semgrep`) takes a real path and a longer
  timeout (120s vs. 60s) since a directory scan does more work per call
  than a single research-corpus snippet.
- **Rule-ID prefix stripping (`_base_rule_id`).** Loading the ruleset
  from a local file (`data/semgrep_rules/codegate_rules.yaml`) rather
  than the registry makes semgrep prepend a path-derived namespace to
  every rule id (e.g. `data.semgrep_rules.codegate-sqli-string-build`).
  This was latent in the existing oracle tests because they used
  substring matching (`"sqli" in rule_id`); the pipeline's exact-match
  `_RULE_ID_TO_CWE` lookup surfaced it immediately. Fixed by stripping
  everything up to the last `.` — safe because this project's own rule
  ids use hyphens, never dots.
- **Unrecognized rule id → dropped, not crashed or silently kept.** A
  semgrep finding whose base rule id isn't in `_RULE_ID_TO_CWE` means
  the ruleset and the pipeline have drifted apart (someone added a rule
  without updating the map) — a bug in *this project*, not a property of
  the scanned code. Same "surfaced loudly, not silently" principle as
  `consensus.py`'s unrecognized-CWE guard on the research side.
- **`run_scan` never imports the dynamic oracles.** Stated as a hard
  invariant in the function's own docstring and proven, not just
  asserted, by `test_scan_never_executes_the_scanned_code`: a fixture
  file that would leave a detectable side effect (writing a sentinel
  file) if executed is scanned, and the test asserts the sentinel does
  *not* exist afterward. The research half's detonation oracles
  (`oracles/sandbox.py`) execute code because they're judging
  LLM-generated snippets under controlled conditions during training;
  `run_scan` scans arbitrary user code, where running it would be the
  scanner exceeding its mandate (see decision log: containerization was
  deferred specifically because the scanner never executes user code —
  this is the invariant that decision depends on).
- **No trained-model error is actionable, not a stack trace.** Scanning
  without having run `codegate calibrate` first raises `FileNotFoundError`
  with `"codegate calibrate"` in the message, tested explicitly
  (`test_scan_without_a_trained_model_raises_actionable_error`) —
  consistent with `codegate info`'s existing behavior (Phase 3) on the
  same missing-artifact case.
- **Tests are structural per guardrail G2** (§6): they assert "semgrep
  finding maps to the right function," "gate partitions all units into
  auto-approved ⊔ escalated," "an uncertified threshold escalates
  everything," "skipped files are reported" — never a specific score or
  coverage number. A real retrain (Phase 8) will not turn this suite
  red.

**Evidence.** `tests/test_scan_pipeline.py` (7 tests): finding rejects an
invalid `source`, semgrep SQLi finding maps to the correct function name,
the no-execution invariant (sentinel-file proof), gate partitioning with
a permissive threshold, gate escalating everything with an uncertified
(`None`) threshold, skipped-file reporting, and the actionable
missing-model error. Also run by hand against the repo's own `src/`:
**70 units, 62 auto-approved, 8 escalated, 0 semgrep findings** — expected
on the project's own clean code, and consistent with Phase 4's separately
measured 62-unit `ingest_path` count on the same tree (the two counts
differ because `run_scan`'s `Unit`s carry `end_lineno` and the scan-path
ingest call counts slightly differently — not a discrepancy in what's
being scanned). 120 tests passing (was 113).

**Status rationale.** `SOLID` for the mechanism — ingest → static →
rank → gate is wired, tested structurally, and proven not to execute
scanned code. The *numbers* the model-gate half produces
(auto-approved/escalated counts, confidence values) stay `PROVISIONAL`
per §6 until Phase 8's retrain, exactly as G1/G2 require; nothing in this
phase's tests or evidence treats those numbers as meaningful yet.

### Phase 6 — LLM verifier (`scan/verifier.py`) — `SOLID`

**What was done.** Added `verify_unit(unit, backend, cache_dir)`: one
constrained LLM call per escalated unit, asking the model to return a
strict JSON verdict (`vulnerable`, `cwe`, `line`, `reason`, `fix_hint`)
for the single function shown. Results are cached on disk at
`.codegate_cache/<content_hash>.json`, so re-scanning unchanged code
costs zero calls — the missing half of the project's cost-savings claim,
previously entirely unbuilt. `to_finding` turns a confirmed-vulnerable
result into a `Finding(source="verifier")`; a cleared result produces no
finding, same as an auto-approved unit.

**Decisions taken and why.**
- **A dedicated `VerifierBackend` protocol (`ask(code) -> str`), not a
  reuse of the research-side `Backend` ABC.** The plan called for reusing
  `Backend`, but `Backend.generate(prompt: Prompt, seed: int) -> str` is
  shaped for corpus generation — a `Prompt` object with `.task`,
  `.cwe`, `.flavor`. Verification sends a real code snippet and expects a
  structured JSON verdict back, not free-form code; forcing a `Prompt`
  object into that call would mean fabricating one from scan data that
  doesn't have prompt semantics. `GroqVerifierBackend` still reuses the
  same request shape as `research/generation/backends.py::GroqBackend`
  (same endpoint, same auth header pattern) — the code path is shared in
  spirit, just not the literal ABC.
- **`verifier: llama-3.3-70b-groq` (config.yaml) is a role name, not a
  literal API model id.** `_GROQ_MODEL_IDS` maps it to the real Groq
  model string explicitly, rather than passing the config value
  straight through and hoping it happens to match the provider's
  naming — a wrong guess here would silently 404 every verification
  call. This exact scenario happened for real: see decision #11 (§4) --
  the model this mapping originally pointed to
  (`llama-3.3-70b-versatile`) was later removed from Groq's catalog
  entirely, and only the mapping needed to change, not any call site.
- **No key → `build_verifier_backend` returns `None`, not an error.**
  Matches the project's existing degrade-without-keys discipline
  (`consensus.py`'s adjudicator-optional design, Phase 3's `codegate
  info` on a missing model). `verify_unit(unit, backend=None, ...)`
  short-circuits to `None` before ever touching the network.
- **Any backend failure — network error, timeout, malformed JSON, a
  response that doesn't obey the requested shape — degrades to `None`,
  never raises out of `verify_unit`.** `_parse_verdict` validates
  `vulnerable` is actually a bool and `cwe` is one of the three tracked
  CWEs (coercing anything else to `None`) before trusting any field.
  Callers must treat `None` as "still needs review," never as "confirmed
  safe" — an LLM that fails to respond usefully is not evidence of
  safety, exactly the same principle as the research side's
  `LABEL_ABSTAIN` (Phase 1) and the semgrep oracle's error-not-crash
  degradation (`oracles/semgrep_oracle.py`).
- **Cache keyed by `content_hash`, written only on a successfully parsed
  verdict.** An unparseable or failed response is never cached — caching
  a failure would mean a transient network blip permanently marks a unit
  as unverifiable until the cache is manually cleared.

**Evidence.** `tests/test_verifier.py` (14 tests): JSON verdict parsing
(clean, embedded in prose, malformed, missing required field,
unrecognized CWE coerced to `None`), no-backend short-circuit, backend
exception handling, unparseable-response handling (and that it isn't
cached), cache write on success, cache hit skipping a second backend call
(call-counting stub), `Finding` field mapping including the
`unit.lineno` fallback when the verdict omits a line number, and
`build_verifier_backend`'s no-key/with-key branches including the
role-name-to-model-id mapping. 134 tests passing (was 120).

**Status rationale.** `SOLID` — parsing, caching, and degradation are
all exercised against a stub backend in the unit suite, and every
failure mode (no key, network error, bad JSON, wrong shape) has a
dedicated test proving it degrades to "needs review" rather than
crashing or lying. **Updated 2026-09-02, live-verified**: the original
verifier model (`llama-3.3-70b-versatile`) turned out to have been
removed from Groq's catalog — see decision #11 (§4) — and once remapped
to `openai/gpt-oss-120b`, a real `GROQ_API_KEY` run against
`examples/vulnerable_app` correctly confirmed both real vulnerabilities
and cleared all three of the gate's false positives, with zero
unresolved calls. `GroqVerifierBackend.ask` is no longer untested
against the real endpoint. (Wiring into `run_scan` itself landed with
Phase 7, alongside the CLI wiring and report formatter its output needed.)

### Phase 7 — Reporting + CLI wiring (`report/`, `codegate scan`) — `SOLID` (mechanism) / `PROVISIONAL` (numbers)

**What was done.** The major deliverable: `codegate scan` now actually
scans. Four report formats (`terminal`/`json`/`sarif`/`pdf`), all reading
from the same `ScanResult` with no LLM writing any report prose —
`report/remediation.py` is a hardcoded per-CWE lookup (explanation +
before/after code), `report/accounting.py` turns raw token/call counts
into a priced estimate, `report/json_sarif.py` and `report/terminal.py`
render deterministically, `report/pdf.py` (reportlab + pygments) produces
the full 7-section document the plan specified: cover, executive
summary, detection attribution, cost & token accounting, findings detail
with syntax-highlighted excerpts, coverage & certificate, methodology.
Wiring this in required extending Phase 5/6's `run_scan` and `ScanResult`
themselves — the verifier (Phase 6) wasn't actually called from the scan
path until this phase, since there was nowhere to route its output until
a report existed to hand it to.

**Decisions taken and why.**
- **`run_scan` gained `verifier`/`cache_dir` parameters, both
  backward-compatible.** `verifier=None` (the default) reproduces Phase
  5's exact behavior — every existing Phase 5 test still passes
  unmodified. When a backend is given, each escalated unit gets at most
  one `verify_unit` call: confirmed-vulnerable becomes a
  `source="verifier"` finding, cleared produces no finding (same
  convention as an auto-approved unit), unresolved falls back to the
  existing "needs review" finding. `_rank_and_gate` and the new
  `_resolve_escalated` were split so the gate's scoring logic and the
  verifier's resolution logic stay independently testable.
- **`ScanResult` grew nine fields** (`n_verified_confirmed/cleared/
  unresolved`, `n_verifier_cache_hits/calls_made`, `tokens_saved/spent`,
  `calibration`) — all with defaults, so no existing test constructing a
  `ScanResult` needed to change. This was the honest alternative to
  either (a) a separate "accounting" pass that re-derives these numbers
  by re-reading the scan target after the fact (duplicated, and
  potentially inconsistent, logic), or (b) computing them once, inline,
  at the only point the per-unit `token_estimate` and cache-hit status
  are naturally available.
- **Token accounting is explicitly an estimate, disclosed as data, not
  prose.** `CostSummary.is_estimate` is a real field a renderer must
  read, not a docstring note a renderer could silently drop. Tokens
  spent = the chars/4 heuristic (`Unit.token_estimate`, from Phase 4) for
  every escalated unit that got a fresh (non-cached) call this run, plus
  a fixed 150-token system-prompt overhead per call — both documented
  constants, not measurements, printed as assumptions in the PDF's cost
  section. This matches the plan's explicit instruction: "Label it an
  estimate and print the assumptions in the report."
- **A hardcoded Groq price (`$0.59`/1M tokens) in a plain dict, not a
  live pricing API call.** A report must be reproducible from the
  numbers it was run with; a price that can change between generating a
  report and reading it would make the report lie about its own recent
  past. The price itself is carried over from the model this table
  originally priced (`llama-3.3-70b-versatile`, since removed from
  Groq's catalog — see decision #11) and is explicitly **not yet
  verified** against real pricing for the replacement model
  (`openai/gpt-oss-120b`) — flagged in `report/accounting.py`'s own
  comment, not silently assumed correct.
- **`--alpha` explicitly rejected (exit code 2), not silently ignored.**
  Overriding the certified threshold post hoc would require recomputing
  it from the persisted `LTTResult.trace` against a real frontier —
  deferred until Track A lands, exactly as this log's §6 already flagged.
  An accepted-but-ignored flag would be a silent lie about what the scan
  actually certified; a loud, explained rejection is consistent with
  every other degrade-honestly decision in this project.
- **JSON/SARIF stdout uses plain `print()`, not `console.print()`.**
  Caught by hand while smoke-testing the real CLI against the repo's own
  `src/`: rich's `Console.print` line-wraps at terminal width and parses
  `[...]`-style markup, both of which corrupt structured JSON output
  (a JSON key doesn't need reformatting, and a stray `[` in a string
  value has nothing to do with rich's bbcode-like tags). `console.print`
  stays for the `terminal` format and for status lines like `Wrote
  <path>`, where rich's formatting is exactly what's wanted.
- **Findings-table columns use `overflow="fold"`, not rich's default
  ellipsis truncation.** Also caught by hand-testing the real CLI: the
  default truncation marker is a Unicode ellipsis character that renders
  as mojibake on a default-codepage Windows terminal — the same class of
  bug as the `§`-symbol fix from Phase 3 (see `ENGINEERING_LOG.md`'s
  earlier note; this log's own text now avoids that character too).
  Folding wraps long file paths onto extra lines instead of truncating
  them into an unreadable path fragment either way.
- **PDF code excerpts read the file from disk at report-generation
  time, keyed on `Finding.file`/`.line`, rather than threading `Unit`
  source text through `ScanResult`.** `Finding` and `ScanResult` stay the
  lean, JSON-serializable shape the JSON/SARIF formatters already commit
  to; only the PDF formatter needs highlighted source, and the scan
  target's files are still on disk (same process, same invocation) when
  the report renders. `_read_excerpt` degrades to an empty excerpt
  (never raises) if a file has moved or been deleted between scan and
  render.
- **Syntax highlighting hand-rolls pygments token colors into reportlab's
  restricted `<font color=...>` Paragraph markup**, not an HTML-to-PDF
  conversion. reportlab Paragraph accepts a small XML-like subset, not
  full HTML/CSS, so `pygments.formatters.HtmlFormatter` output would need
  its own translation layer anyway; lexing tokens directly and mapping a
  handful of token-type prefixes (Keyword, String, Comment, Number,
  Operator, Name.Builtin) to hex colors is fewer moving parts for a
  3-CWE Python-only scanner's excerpts.

**Evidence.** 42 new tests across five files: `test_report_remediation.py`
(3), `test_report_accounting.py` (5), `test_report_json_sarif.py` (6),
`test_report_pdf.py` (10, including a real generated-PDF byte-signature
check), `test_report_terminal.py` (4), plus 14 new/changed tests in
`test_scan_pipeline.py` (verifier wiring, token/call accounting, the
calibration pass-through) and `test_cli.py` (real `scan` invocations
across all four formats, replacing the old not-implemented stub test).
176 tests passing (was 134).

Also verified by hand against the real, committed `data/model/`
artifacts and the repo's own `src/` tree (not a fixture): `codegate scan
src --no-llm` correctly reports 104 units, 87 auto-approved, 17
escalated, 17 findings; `--format json`/`--format sarif` both produce
valid, parseable output; `--format pdf` produces a real, valid PDF
(`%PDF-1.4` header, 15KB, 7 sections, syntax-highlighted excerpts) —
opened and visually inspected (cover page, executive summary, detection
attribution and cost tables) rather than only checked for a byte
signature. This hand-testing is what caught the rich-markup/JSON-wrapping
bug and the ellipsis-mojibake bug above; neither was caught by the unit
suite, which used `CliRunner`'s captured output rather than a real
terminal/codepage.

**Status rationale.** `SOLID` for the mechanism — every format renders,
every number traces to a `ScanResult` field or a documented constant, and
the full path (`ingest → static → rank → gate → verify → report`) has
now been exercised end-to-end against real code, not just fixtures.
`PROVISIONAL` for the actual figures a report contains, for the same
reason Phase 5's gate numbers are provisional (§6): the ranker is still
trained on the simulated corpus. A generated report is honest about this
today — the PDF cover carries the same provisional banner `codegate
info` already prints — but the *numbers themselves* will change, not
just become more confident, once Phase 8 retrains.

### Phase 9 — Demo assets (`examples/vulnerable_app/`) — `SOLID`

**What was done.** Six files: `database.py`, `system_tasks.py`,
`config.py` each carry one vulnerable function (CWE-89/78/798) paired
with its direct safe fix, plus a no-pattern-at-all `list_active_users`/
`list_directory`/`get_api_key` sibling; `report_utils.py` is entirely
safe, ordinary computation; `app.py` ties the modules together into
something that reads like a real (small) app; `README.md` documents the
CWE/function table and the quickstart commands. A generated
`sample_report.pdf` is committed alongside so a reviewer sees real PDF
output without installing or running anything.

**Decisions taken and why.**
- **Every vulnerable function is paired with its own direct fix in the
  same file**, not just "some safe files elsewhere" — the plan's
  explicit ask was a demo that shows *discrimination*, not just
  detection, and `get_user_by_name`/`get_user_by_id` sitting next to
  each other is what makes that legible at a glance.
- **A neutral, zero-pattern file (`report_utils.py`) included on
  purpose** — without it, every file in the demo would contain at least
  one flagged pattern, which wouldn't demonstrate that the scanner
  leaves genuinely unrelated code alone.
- **The sample PDF was generated with `--no-llm`** so the committed
  artifact doesn't depend on (or imply) a `GROQ_API_KEY` being available
  to whoever's reviewing it — consistent with the "works with zero setup
  on a fresh clone" decision from Phase 2/3.

**A real bug found and fixed while generating the sample PDF by hand —
not caught by any test until this step.** `report/pdf.py::_findings_flowables`
interpolated `Finding.func_name`, `.file`, `.cwe`, `.severity`, `.source`
directly into `Paragraph` text without XML-escaping. This was invisible
on every fixture used in Phase 7's own tests (plain identifiers like
`get_user`), but the scan pipeline's own fallback for a module-level
semgrep hit uses the literal string `"<module>"` as `func_name` (see
`scan/pipeline.py::_semgrep_findings`) — and reportlab's `Paragraph`
parses `<...>` as an XML tag. An unrecognized tag is silently dropped,
so the rendered heading read `config.py:5 -- ()` instead of
`config.py:5 -- <module>()`, with no error, warning, or crash anywhere.
Caught only by opening the actual generated PDF and reading it, exactly
the kind of defect Phase 7's own "hand-test the real output" lesson
(rich markup corrupting JSON, ellipsis mojibake) already flagged as a
class of bug the unit suite can't catch on its own. Fixed by escaping
every dynamic string that reaches a `Paragraph` in `report/pdf.py`
(findings' `file`/`func_name`/`cwe`/`severity`/`source`, and the cover
page's `target`/`ranker_id`/`corpus_version`/`verifier_model`) — the
cover page's `target` in particular is a raw CLI argument, so this
wasn't only a `"<module>"`-shaped risk. Added
`test_findings_flowables_escapes_angle_bracket_func_name` as a
regression test, asserting on `Paragraph.text` (reportlab exposes the
pre-render markup string directly, so this doesn't need to render an
actual PDF and extract text from it).

**Evidence.** Real `codegate scan examples/vulnerable_app --no-llm`
output: 14 units, 9 auto-approved, 5 escalated, 8 findings -- semgrep
correctly catches all three planted vulnerabilities (CWE-89 in
`get_user_by_name`, CWE-78 in `ping_host`, CWE-798 on
`DATABASE_PASSWORD`) with zero false positives on the static side; the
gate additionally escalates several of the *safe* functions for review,
which is expected and not a defect -- it's exactly what "provisional"
means (§6), and the PDF's own cover banner says so. Verified in all four
formats (`terminal`, `json`, `sarif`, `pdf`); the PDF was opened and
visually inspected page by page (not just checked for a byte signature)
both before and after the escaping fix. 177 tests passing (was 176).

**Status rationale.** `SOLID` — every file in the demo, the README, and
the committed sample report were all generated and verified against the
real, current codebase this session, not written speculatively ahead of
what the tool actually does.

## 4 · Decision log

Chronological, including reversals. Each entry: what changed, and why.

| # | Decision | Why |
|---|---|---|
| 1 | Fork/branch the old repo → **new repo** | User directive: the scanner is a materially different deliverable, and the old repo is preserved as the v1 research archive rather than rewritten in place |
| 2 | Full Docker containerization → **deferred, not planned** | The scanner never executes *user* code — only the offline research half executes *generated* code, and only on the research machine. The remaining risk is credibility for the write-up, not runtime safety, so it's deferred rather than built now |
| 3 | `uuid4()` sample IDs → **deterministic `stable_seed()` IDs** | Resume correctness: a random ID can never be recognized as "already done" across process restarts |
| 4 | Abstention silently coerced to "safe" → **`LABEL_ABSTAIN` third state** | Item 2 in Phase 1 above — the coercion is what hid the SQLi table-name bug for an entire 540-sample run |
| 5 | Oracle abstains on any code without the exact expected function name → **sink-scope shortcut added first** | Recovers negatives that can be judged with certainty (no SQL/shell touched at all) without weakening the genuine-abstention path |
| 6 | Two existing tests asserting `None` for no-sink code → **rewritten to assert `False`, is correct** | The tests' premise, not the code, was wrong once sink-scope reasoning landed — see Phase 1 item 6 for the full reasoning; called out explicitly rather than folded silently into the diff |
| 7 | `;` command separator in the cmdi payload → **`&`** | Windows `cmd.exe` (dev machine) doesn't accept `;` as a POSIX-style separator; `&` works under both `cmd.exe` and POSIX `sh` |
| 8 | Both-machines-on-one-LAN Ollama setup (Appendix A) → **host-runs-everything, ships back one file (`docs/OLLAMA_SETUP.md`)** | The two machines involved in Track A do not share Wi-Fi; running the whole generation step locally on the host and shipping `generations.parquet` back removes every networking variable (firewall rules, `OLLAMA_HOST` binding, LAN reachability) at the cost of the host needing Python + the repo, not just Ollama |
| 9 | Corpus scale: 1,620 samples (3 per prompt) → **540 (1 per prompt)** | Keeps the unattended Track A run to ~2–5h on CPU; scaling up is deferred until the first 540-sample loop proves out end to end |
| 10 | `cli.py`'s eager `from codegate.research.pipeline import run_full_pipeline` → **lazy-imported inside `calibrate()`**; `semgrep` moved from the `research` optional extra → **core `dependencies`** | Found while setting up CI (§9): `research/pipeline.py` imports `research/eval/plots.py`, which imports `matplotlib` unconditionally — a dependency declared only under `[research]`. Because `cli.py` imported `run_full_pipeline` at module top level, *every* `codegate` command, including `scan`, crashed with `ModuleNotFoundError` on a plain `pip install -e .` (no extras) — directly breaking the project's own "fresh clone works with zero setup" promise and the plan's clean-room acceptance criterion. `semgrep` had the milder version of the same problem: `scan/pipeline.py`'s static pre-pass needs it, but it lived under `research` too, so a base install would silently produce zero static findings with no warning. Verified the fix in a fresh venv: `pip install -e .` (base only) followed by `codegate info` and `codegate scan examples/vulnerable_app --no-llm --format pdf` both now succeed |
| 11 | Verifier model `llama-3.3-70b-versatile` → **`openai/gpt-oss-120b`** (`scan/verifier.py::_GROQ_MODEL_IDS`) | Found live, 2026-09-02, the first time `GROQ_API_KEY` was ever set and a real scan ran with the verifier on: every call 404'd. `GET /openai/v1/models` against the same key confirmed the model is no longer in Groq's catalog at all — deprecated/removed with no in-band warning. `verify_unit`'s degrade-to-`None` design meant this failed safely (findings fell back to "needs review," no crash), but verification was silently non-functional until diagnosed with a direct API probe. Fixed by remapping to `openai/gpt-oss-120b`, verified live on a real vulnerable-code sample (clean, correctly-classified JSON on the first call) and then end-to-end: re-scanning `examples/vulnerable_app` with the verifier enabled correctly confirmed both real vulnerabilities and cleared all three of the provisional model's false positives (precision 0.50 → 1.00 on that target). Also found and fixed the actual cause of the confusion along the way: `.env` had a second, empty `GROQ_API_KEY=` line after the real one, which `python-dotenv` was resolving to (last value wins on a duplicate key) — the key was correctly set by the user throughout, dotenv was just reading the wrong line |
| 12 | `research/pipeline.py::extract_code()` added — real chat-model completions extracted from markdown fences, `[PYTHON]` tags, and `<pre>` tags before labeling | Found the moment Track A's real 516-sample corpus (branch `nikhil`) was labeled for the first time: 40.7% oracle abstention. Real models wrap code in prose and delimiters `SimulatedBackend` never produces; `ast.parse()` on the raw text failed, so the dynamic oracles' function-name search fell back to template names real models never use. Extraction alone cut abstention to 20.3%; a second delimiter style (`[PYTHON]`/`<pre>`, codellama-specific) found by inspecting the remaining failures cut it further to 17.8% |
| 13 | `oracles/cmdi_oracle.py`'s harness — success marker moved inside the `try` block, no longer printed unconditionally | Found by manually eyeballing "safe"-labeled vulnerable-flavor CWE-78 samples from the real corpus: textbook `shell=True` + f-string command injection was labeled `False` (safe). The harness's `print("CODEGATE_DONE")` sat *after* the try/except, so a `TypeError` from calling a real, multi-parameter function with the harness's fixed single-argument call still printed the "done" marker — `check_cmdi` then reported "ran, no sentinel" (safe) instead of "call itself failed" (unknown). Same defect class as the original SQLi table-name bug, this time in a different oracle and triggered by signature diversity, not table names. Re-labeling with the fix raised abstention from 17.8% to 28.3% — a large swing, but a *correct* one: most of what moved was mislabeled-safe becoming honestly-abstained, not the reverse |
| 14 | `oracles/sandbox.py::run_sandboxed` — switched from `subprocess.run(timeout=...)` to `Popen` + a new process group/session + explicit tree kill on timeout | The real corpus retraining run hung for 56+ minutes at under 1 second of accumulated parent CPU time — confirmed hung, not slow, via `tasklist`/`wmic`, not assumed. Root cause: `subprocess.run`'s Windows timeout path kills only the direct child, then retries `communicate()` with no timeout at all; a cmdi-vulnerable sample's function shelling out to something that blocks (git/tar/nslookup-style commands appear throughout the real corpus) leaves a grandchild holding stdout/stderr pipes open forever. Fixed with `CREATE_NEW_PROCESS_GROUP` (Windows) / `start_new_session` (POSIX) plus `taskkill /T /F` (or `os.killpg`) on timeout, and a *bounded* post-kill reap so a still-stuck cleanup can never hang the caller again. Regression test reproduces the exact shape and passes in ~3s despite the grandchild's real 30s sleep |
| 15 | `cli.py`'s `info` and `report/terminal.py`'s scan output — the live `[bold yellow]PROVISIONAL[/bold yellow]` banner removed; the certificate table's plain `Corpus version` row is unchanged | Team decision, 2026-09-02: the panel-facing live terminal output was judged to read as an unprompted alarm rather than a disclosure, ahead of a demo. The underlying fact is *not* hidden — `corpus_version`/`is_provisional` still print plainly in the same table, the PDF report's two provisional banners (`report/pdf.py`, cover + certificate section) are untouched, and `DEMO_GUIDE.md` already scripts explaining this verbally if asked. Net effect: disclosed in writing and on request, not auto-announced mid-demo. `test_cli.py::test_info_prints_certificate_table` and `test_report_terminal.py::test_render_terminal_shows_corpus_version_without_a_provisional_banner` now assert the banner text is absent (previously asserted it was present); `test_info_omits_provisional_warning_when_not_provisional` was deleted as redundant once the banner became unconditional-never rather than conditional. Test count: 201 → 200 |

## 5 · Confidence assessment

**Very successful — built, tested, and behaves exactly as specified:**
- LTT calibration core (`gate/ltt.py`) — fixed-sequence testing over the
  monotone risk `R(t)`, unchanged since v1, 5 tests including the
  corrected perfect-separation case
- The cmdi detonation oracle — clean separation between vulnerable and
  safe fixtures, portable payload
- Corpus labeling, now at the theoretically correct 33.33% vulnerable
  rate with 0 abstentions on the simulated 540-sample run
- Checkpoint/resume for generation — survives interruption, verified
  deterministic across runs
- Phase 0 migration — zero test regressions carried into the new repo
- Persistence round trip (`research/artifacts.py`) — model + certificate
  save/load, version guard tested against an actual mismatch
- CLI (`info`, `calibrate`) — end-to-end verified both by test and by hand
  against the real `data/model/` artifacts, which reproduced the exact
  numbers already on record in section 6
- LLM verifier (`scan/verifier.py`), live — a real `GROQ_API_KEY` run
  against `examples/vulnerable_app` correctly confirmed both real
  vulnerabilities and cleared all three of the gate's false positives on
  that target (precision 0.50 → 1.00), zero unresolved calls, after
  decision #11's model remap
- Ingest (`scan/ingest.py`) — verified against synthetic edge cases and
  against the repo's own `src/` tree (62 units, 0 skipped)
- Scan pipeline (`scan/pipeline.py`) — ingest → static → rank → gate
  wired and tested structurally per G2, the no-execution invariant
  proven by a sentinel-file test rather than asserted, and run by hand
  against the repo's own `src/` tree (70 units, 62 auto-approved,
  8 escalated, 0 semgrep findings)
- `run_semgrep_on_path()` at directory scale — Phase 5 resolved the gap
  flagged below: one CLI invocation over a whole target directory,
  exercised by `test_scan_pipeline.py` against real files on disk, not
  just per-snippet in-memory strings
- `codegate scan` end-to-end (`terminal`/`json`/`sarif`/`pdf`) — verified
  by hand against the real committed `data/model/` artifacts and the
  repo's own `src/` tree: correct counts, valid JSON/SARIF, a real PDF
  opened and visually inspected page by page, not just checked for a
  byte signature. This hand-testing (not the unit suite) is what caught
  two real bugs — see the Phase 7 entry's decision list (rich
  markup/line-wrapping corrupting JSON stdout, and a Unicode-ellipsis
  mojibake in the findings table) — both fixed before this line was
  written

**Needs integration testing — built and unit-tested, not yet exercised
end-to-end:**
- `run_real.py`'s `preflight()` against a *live* Ollama host (only
  exercised against mocked/absent servers so far)
- Checkpoint/resume against an actual multi-hour run (only tested against
  short synthetic interruptions)
- `GeminiBackend` and the adjudicator path — implemented, never called
  once; `label_row`'s `adjudicator_verdict` stays hardcoded `False` until
  it is wired in

**Provisional — runs, but the output shouldn't be trusted yet:**
- Every score the interim `R2Ranker` produces (trained on 540 simulated,
  not real, samples — see §6 for the measured evidence this is still safe
  to build the scanner against)
- Any coverage/frontier number computed from the simulated corpus
- The `model.joblib`/`calibration.json` pair currently on disk from any
  simulated run, including the one now committed at `data/model/` —
  correctly labeled `is_provisional: true`

**Not started:** nothing in Track B — every phase through Phase 9 is
built, tested, and (where applicable) verified against real output.
Only Phase 8 (retrain on the real corpus) remains, and it is blocked on
Track A, not on anything left to design or build here.

## 6 · Building ahead of the trained model — the evidence

Track B (the scanner) does not need to wait for Track A (the teammate's
real-corpus Ollama run) to start, provided the interim model is not
degenerate. Measured rather than assumed, on the current simulated
540-sample corpus, post-Phase-1 fixes:

```
n scored                    : 540
unique score values         : 108      (one plateau per unique code string)
min / median / max          : 0.2676 / 0.7393 / 0.9388
saturated (<0.02 or >0.98)  : 0.0%
mid-band (0.2–0.8)          : 63.1%
coverage at alpha=0.05      : 66.7%    (~1/3 escalated)
```

Not degenerate (zero saturation, 63% mid-band, no divide-by-zero or
empty-set edge cases), and the coupling surface to the rest of the system
is a single call site — `research/pipeline.py:184` — so retraining changes
the floats inside `model.joblib`, not any consuming code. Three guardrails
are load-bearing for this to stay true through Phases 2–7:

- **G1** — the interim `calibration.json` must carry
  `corpus_version: "simulated-v2"` and `is_provisional: true`, surfaced by
  `codegate info` and the PDF cover banner, so a provisional certificate
  never looks like a real one.
- **G2** — scan-pipeline tests assert structure (every unit scores in
  `[0,1]`, the gate partitions into two disjoint sets, N findings render),
  never specific values — a real retrain must not turn the suite red.
- **G3** — scan tests load a fixed `StubRanker`, not `model.joblib`, so
  "the model changed" and "the code broke" stay distinguishable.

Deferred until Track A's real data lands: the default `--alpha` for the
CLI, severity-binning thresholds in the report, the "scan our own `src/`"
calibration sanity check, and any published cost-savings figure (the
accounting machinery still gets built and unit-tested now — only the
*number* stays provisional).

## 7 · Test inventory

442 tests collected, all passing (`python -m pytest tests/ --collect-only -q`,
counts per file regenerated 2026-10-05).

| File | Tests | Protects |
|---|---|---|
| `test_oracle_ground_truth.py` | 158 | Hand-verified labels for all three oracles, each pinning a defect found on real corpora: arity and statement-type cases for SQLi; Postgres idiom; multi-argument, allowlist, suffix-check, `int()`-cast, post-spawn-parse and module-level-demo-call cases for cmdi; every CWE-798 secret shape, each with an environment-sourced negative twin |
| `test_oracles.py` | 24 | Core oracle contracts: `function_exists`, sandbox execution/timeout/exit-code capture, detection on fixtures, consensus rule v2 (including refusing to coerce a missing verdict), semgrep hit/clear on fixtures |
| `test_dbapi_recorder.py` | 21 | Recording DB-API connection: paramstyle translation, statement capture through cursors and shortcuts, splice-vs-bound detection |
| `test_corpus.py` | 17 | Prompt bank loading and shape: 60 groups per CWE, 24/24/12 splits, pinned signatures and arity spread, pinned CWE-798 literals, pilot selection |
| `test_verifier.py` | 17 | JSON verdict parsing, degradation without a backend or on backend errors, caching, `Finding` mapping, `build_verifier_backend` |
| `test_oracle_robustness.py` | 15 | The SQLi table-name abstention-defect class, plus the sink-shortcut correctness tests |
| `test_scan_pipeline.py` | 15 | `Finding` validation, semgrep mapping, the no-execution invariant, gate partitioning, uncertified-threshold escalation, verifier paths, cache reuse, token accounting, `calibration` pass-through |
| `test_artifacts.py` | 15 | Model/calibration round trips, missing-file errors, uncertified `t_hat`, version guard, the persisted frontier, `at_alpha` (certified, uncertified and never-computed alphas), pre-frontier files still loading |
| `test_cli.py` | 13 | `info`/`calibrate`/`scan` via `CliRunner`, including `--alpha` with a certified alpha and refusing an uncertified one |
| `test_eval_metrics.py` | 15 | Oracle accuracy on fixtures, label distribution, score frames, separation metrics, held-out split filtering (and refusing a split filter without split data), `scan_ground_truth_eval` |
| `test_oracle_invocation.py` | 13 | Benign-value heuristics, the self-contained harness prelude, allowlist harvesting |
| `test_pipeline_extract_code.py` | 11 | Code extraction from fenced, tagged, `<pre>`, `<details>` and unopened-fence completions |
| `test_report_pdf.py` | 12 | Highlighting, excerpts, escaping regressions, a real PDF's signature and size, edge cases |
| `test_generation.py` | 10 | `SimulatedBackend` shape/determinism, `stable_seed`, backend construction |
| `test_generation_resume.py` | 9 | Checkpoint write/read, resume, partial failure, and (2026-10-04) regenerating reworded or unfingerprinted records while taking the split from the current prompt |
| `test_ingest.py` | 9 | Function extraction, hashes, syntax/unreadable-file reporting, skips, missing-path error |
| `test_report_json_sarif.py` | 7 | JSON round trips, null certificate, SARIF 2.1.0 shape and mappings |
| `test_config.py` | 7 | Config loading, leftover `split_ratios`/`adjudicator` keys ignored, the `certificate` setting and its validation |
| `test_relabel.py` | 5 | `relabel` row count and separation, `label_summary` shape |
| `test_ltt.py` | 13 | `calibrate_threshold` — monotonicity, separation, zero-vulnerable edge case; the cluster-aware test: Hoeffding–Bentkus p-values, recorded method and group count, duplicated evidence buying no looser threshold, and a seeded simulation showing it keeps its promise under strong correlation where the per-sample test does not |
| `test_risk.py` | 5 | `empirical_risk`, Clopper-Pearson edge cases |
| `test_ranker.py` | 5 | `R2Ranker` fit/score contract, score orientation |
| `test_report_accounting.py` | 5 | Cost accounting arithmetic, always flagged as an estimate |
| `test_schemas.py` | 4 | `validate_dataframe` |
| `test_eval.py` | 6 | Cost-coverage frontier (including grouped), generator-shift experiment (including grouped calibration judged on separate held-out data) |
| `test_report_terminal.py` | 4 | Terminal rendering |
| `test_env.py` | 3 | `.env` loading |
| `test_report_remediation.py` | 3 | Remediation entries per CWE |
| `test_dry_run.py` | 1 | Full simulated pipeline end to end |

## 8 · Known risks & open questions

- **Old repo (`ad1tya-wq/codegate`) is public** with `PROGRESS.md` /
  `NEEDS_FROM_YOU.md` containing blunt internal assessments and the
  original defect list — flagged to the user previously, decision still
  open.
- **No manual label validation / inter-rater agreement (κ) yet** on any
  oracle verdict against human judgment — the oracles are trusted on
  design grounds (dynamic detonation, not pattern matching) but not yet
  empirically checked against a human-labeled sample.
- **Real corpus (Track A) still pending** — this whole engineering log's
  §6 argument depends on it eventually landing; the provisional flags
  (G1) are the mechanism that keeps the scanner honest in the meantime.
- **Scan pipeline's semgrep subprocess call observed flaky once under
  full-suite load** (`test_scan_finds_sqli_via_semgrep_and_maps_to_the_right_function`
  failed once when the full 121-test suite ran back-to-back with other
  subprocess-heavy tests, then passed on immediate re-run in isolation
  and on two subsequent full-suite runs). Likely subprocess/OS-level
  resource contention from many sequential `semgrep` CLI invocations
  under one pytest session, not a pipeline logic bug — no code change
  made. Worth watching if it recurs; not yet worth a retry/backoff
  mechanism on a single observation.
- **No live Groq API call has ever been made.** `GroqVerifierBackend` is
  exercised only against stub backends in tests; whether the real
  endpoint's auth, rate limits, and JSON discipline actually match what
  `_parse_verdict` expects is unverified until someone runs
  `codegate scan` with a real `GROQ_API_KEY` set. Low risk given
  `verify_unit`'s degrade-to-`None` design (a surprising real response
  becomes "needs review," not a crash), but the cost/token numbers in a
  report generated under a live key haven't been sanity-checked against
  an actual bill yet.
- **The Groq price table (`report/accounting.py`) is a hand-maintained
  constant checked once (2026-08-31).** If it goes stale, every report's
  `estimated_cost_usd` quietly drifts from reality — there's no
  freshness check or expiry warning on the price itself, only the
  existing `is_estimate` flag covering the token-count side of the
  estimate.
- **`data/model/model.joblib` was pickled under scikit-learn 1.7.2;
  `pyproject.toml` only pins `scikit-learn>=1.7` (no upper bound).**
  Noticed as an `InconsistentVersionWarning` while verifying the CI fix
  in a fresh venv, which happened to resolve scikit-learn 1.9.0. Not
  fixed this session — scikit-learn's own pickle compatibility is a
  judgment call (pin tightly and accept staleness vs. leave open and
  accept a future silent-behavior-change risk) that deserves its own
  decision, not a reflexive pin change buried in a CI-setup session.
- **`lightgbm` is declared under the `research` extra but never imported
  anywhere in `src/`.** Found while checking what the CI test job
  actually needs to install. Harmless (extra install weight only,
  ~seconds in CI) but dead weight; left as-is since removing a
  dependency someone may be about to use for upcoming ranker work is a
  bigger call than this session's scope.

## 9 · Continuous integration

`.github/workflows/ci.yml`, two jobs, both on `ubuntu-latest`, triggered
on every push/PR to `main` plus manual dispatch:

1. **`test`** — the full suite, matrixed across Python 3.11 and 3.13
   (the range `pyproject.toml`'s `requires-python = ">=3.11"` promises,
   never actually verified until this job existed). Installs
   `pip install -e ".[dev,research]"` — the test suite exercises both
   the scanner and the offline research pipeline (matplotlib-backed
   plots, semgrep-backed oracle tests), so both extras are needed just
   to collect every test.
2. **`clean-install-smoke`** — installs `pip install -e .` with **no**
   extras and **no** API keys, then runs `codegate info` and
   `codegate scan examples/vulnerable_app --no-llm` across all four
   `--format` values, asserting the PDF is a real, non-empty `%PDF-`
   file. This job exists specifically because it is the job that
   would have caught decision #10 above (§4) — the eager-matplotlib-
   import bug that broke every `codegate` command on a plain install.
   No local test run ever caught it because every dev machine already
   had the `research` extra installed; a clean CI environment is what
   actually exercises the "fresh clone works with zero setup" promise
   this project has repeated since Phase 0.

**Verified for real, not just YAML-linted:** pushed to `main` and
watched the actual run on GitHub's runners (`gh run watch`) rather than
trusting the workflow file would behave as written — both jobs green,
`test` at Python 3.11 and 3.13 (4/4 matrix+job combinations), including
picking up the packaging fix that made `clean-install-smoke` pass at all.

**Not yet in CI, on purpose:** no lint/format check (the project has
never adopted one — adding `ruff`/`black` now would be a new tooling
decision, not a CI-plumbing one), no Windows runner (the actual dev
machine is Windows, but `ubuntu-latest` is faster and cheaper and
nothing in the test suite is Windows-specific *except* the cmdi payload
separator already handled per-OS in the oracle itself — see decision
#7), and no coverage gate (no coverage baseline has been established to
gate against yet).

## 10 · Evaluation & metrics

`src/codegate/research/eval/metrics.py` (new) plus five new plotting
functions in `research/eval/plots.py`, orchestrated by
`scripts/run_eval.py` (new). Every function computes something real and
inspectable today; every one is designed to run unchanged once Track A's
real corpus replaces the simulated one at `data/model/` — only the input
files change, not the code.

**What's computed:**

- **`oracle_accuracy_on_fixtures`** — the three ground-truth oracles
  (sqli/cmdi/creds) plus semgrep, scored against `data/fixtures/`'s six
  hand-labeled fixtures. Real, unchanging ground truth today — **6/6
  correct**.
- **`corpus_label_distribution`** — vulnerable/safe/abstained counts per
  CWE, from `labeled.parquet`. On the current corpus: 540 samples,
  exactly 33.33% vulnerable per CWE, **0 abstentions** — the number
  Phase 1's fixes were built to produce.
- **`ranker_score_frame` / `ranker_separation_metrics`** — joins
  `labeled.parquet` + `scores_r2.parquet` on `sample_id` and computes
  ROC-AUC plus mean score per class. Measured: **AUC = 1.00** on the
  current corpus — reported with an explicit, code-level caveat (not
  just prose): this is computed over the *full* corpus, not a held-out
  split, since `scores_r2.parquet` doesn't carry which split a sample
  came from. On a small, templated simulated corpus a perfect AUC is a
  memorization signal, not evidence of generalization. Flagged as a
  follow-up in §3 above, not treated as a real accuracy claim anywhere
  in this project's own docs.
- **`plot_ltt_trace`** — visualizes the actual persisted
  `ltt_trace.csv` (Phase 1's decision #4): p-value at every candidate
  threshold, with `alpha` and the winning `t_hat` marked. First time
  this data has been visualized since it started being persisted.
- **`scan_ground_truth_eval`** — the one metric evaluating the deployed
  pipeline end-to-end against ground truth that is entirely real today,
  not waiting on Track A at all: `examples/vulnerable_app/`'s own
  hand-labeled CWE table. Run twice:
  - **Static + certified gate only:** precision 0.50, recall 1.00,
    F1 0.67 — every real vulnerability caught (semgrep is
    deterministic), three of the provisional model's false positives
    also flagged.
  - **With the live LLM verifier** (`--with-llm`, real `GROQ_API_KEY`
    call): precision 1.00, recall 1.00, F1 1.00 — the verifier
    correctly cleared all three false positives and confirmed both real
    vulnerabilities, with zero unresolved calls. This is the clearest
    concrete demonstration in the project so far of what the verifier
    tier is actually for.

**Design decisions.**
- **Functions take DataFrames/paths, not a fixed corpus name** — every
  metric function is agnostic to whether its input is
  `data/model/labeled.parquet` (today) or Track A's real-corpus
  equivalent (later). `scripts/run_eval.py` is the only place that
  names `data/model/` specifically, and even that's a `--model-dir`
  flag, not a hardcoded path.
- **`scan_ground_truth_eval` counts a unit as "flagged" if ANY finding
  exists for it**, regardless of source (semgrep/model/verifier) — the
  question it answers is "did the tool raise concern about this
  function at all," which is the actual user-facing question a
  precision/recall number should answer, not a per-source breakdown
  (the report's detection-attribution table already covers that).
- **`--with-llm` is opt-in on `run_eval.py`, not the default** — an
  eval script shouldn't spend API calls just by being run. Once run,
  `scan/verifier.py`'s existing content-hash cache means a second
  `--with-llm` run costs zero further calls, which is exactly what
  happened when generating the numbers above.
- **New plotting functions have no dedicated unit tests**, matching
  this project's existing, established convention: `plot_frontier`/
  `plot_shift_results` (Phase 0/1) have never had tests either — a
  "did matplotlib not crash" test is low-value, and every new plot was
  instead generated for real and visually inspected by hand, the same
  discipline Phase 7/9's PDF work established as more effective at
  catching real rendering defects than an automated check would be.

**Evidence.** `tests/test_eval_metrics.py` (10 tests): oracle accuracy
against real fixtures, corpus label distribution counting, score-frame
joining and abstention-dropping, separation metrics on both
well-separated and deliberately-inverted synthetic scores, and
`scan_ground_truth_eval`'s precision/recall/F1/accuracy arithmetic
including the same-unit-multiple-findings and module-level-finding
cases. `scripts/run_eval.py` run twice for real (with and without
`--with-llm`) against the actual `data/model/` artifacts and
`examples/vulnerable_app/`; every PNG opened and visually inspected, not
just checked for existence.

**Status rationale.** `SOLID` for the mechanism — every function is
tested, every script run produced real output, and the one metric with
entirely real ground truth (`scan_ground_truth_eval`) shows a genuine,
measured improvement from the LLM verifier. `PROVISIONAL` for anything
downstream of ranker quality (score distribution, separation, LTT
trace), for the same reason as every other model-dependent number in
this log (§6) — plus the additional, explicitly-flagged caveat that the
AUC figure specifically isn't computed on held-out data yet.

## 11 · Phase 8 attempt: retraining on the real corpus (2026-09-02)

Track A delivered a real 516-sample corpus (branch `nikhil`, commit
`a9bc464`, generations from `qwen2.5-coder:7b`, `deepseek-coder:6.7b`,
`codellama:7b`, `starcoder2:7b`) as `data/runs/real_540/generations.parquet`.
This section documents what happened when it was actually run through
the pipeline — not what was planned, what was measured.

**Three real, distinct bugs were found and fixed** running this corpus
through the existing labeling/training path for the first time (decisions
#12–14, §4): a markdown/delimiter extraction gap in `research/pipeline.py`
(real chat models wrap code in prose CodeGate's oracles couldn't parse),
a silent false-safe defect in `oracles/cmdi_oracle.py`'s detonation
harness (the same defect class as the original SQLi table-name bug,
newly triggered by real signature diversity), and a process-hang defect
in `oracles/sandbox.py` (a 56-minute hang, confirmed via `tasklist`/`wmic`,
caused by an orphaned grandchild process from a `shell=True` call
surviving a Windows subprocess timeout). All three are fixed, tested, and
merged to `main`; none were reachable by the simulated corpus, which is
exactly why building the pipeline ahead of real data (§6) was the right
call — it meant these surfaced against real data instead of shipping
silently broken.

**With all three fixes applied, the corpus labels honestly:**

```
n generated                 : 516
abstention rate              : 28.3% (146/516)
vulnerable rate (decided)    : 10.0%
calibration set              : 115 samples, 8 vulnerable
t_hat at alpha = 0.05 / 0.10 / 0.20 / 0.30  : None / None / None / None
coverage at every alpha tested              : 0.0%
```

**LTT could not certify a threshold at any alpha tested, up to 30%.**
This is not a bug — the abstention rate is understood and explained
(§10's evidence for the extraction/harness fixes), and everywhere it was
checked by hand, abstention correctly meant "genuinely unjudgeable,"
not silently-mislabeled. The problem is sample size: only 8 vulnerable
samples reached the calibration split, and LTT's finite-sample guarantee
needs more evidence than that to certify even a loose bound with 95%
confidence. Two compounding causes: (1) the corpus's vulnerable-flavor
prompts often produced safe code anyway — some models write parameterized
queries or `shell=False` even when asked for the vulnerable version,
which the project's own plan flagged as an expected possibility, not a
defect; (2) the two oracle fixes above correctly *reduced* the vulnerable
count further by re-abstaining samples that were previously (wrongly)
labeled safe rather than unknown.

**Decision (2026-09-02, user directive):** `data/model/` stays on the
`simulated-v2` artifacts. They are the only artifacts that currently
certify a working, non-trivial threshold and demonstrate the full gate
mechanism end to end; the real-540 attempt, left as the shipped model,
would certify nothing and escalate 100% of every scan. The real-540
labeled/scored artifacts are preserved at `data/runs/real_540_retrain/`
for reference. This is a sample-size problem to solve with more data
(the plan's own scale-up step, 540 → 1,620 samples, is now a measured
necessity rather than a nice-to-have) or a rebalanced calibration split,
not a mechanism problem — the certificate math, the labeling pipeline,
and the sandbox are all now proven correct against real, messy,
independently-generated code, which the simulated corpus alone could
never have demonstrated.

**A second, unrelated but serious incident during this work:** an early
training invocation (before the process-hang fix, and before `--out-dir`
was being passed deliberately) wrote directly to `data/model/`, silently
overwriting the committed `simulated-v2` artifacts with the uncertified
real-540 ones for a period during this session. Caught by `codegate info`
printing `t_hat: none` unexpectedly while preparing a demo. Recovered
cleanly via `git checkout -- data/model/model.joblib data/model/calibration.json`
(the two files are the only git-tracked contents of that directory,
exactly so this kind of recovery is possible), then `codegate calibrate`
was re-run to regenerate the non-tracked auxiliary files
(`labeled.parquet`, `scores_r2.parquet`, `ltt_trace.csv`, and the eval
plots) — verified byte-for-byte identical to the original (`t_hat`
reproduced to the same float, `created_at` the only diff) because the
simulated corpus generation is fully deterministic. No data was
permanently lost, but it is a direct argument for always passing an
explicit, non-default `--out-dir` on any exploratory training run,
never the canonical `data/model/` path, until a result is deliberately
being promoted.

**Evidence.** `data/runs/real_540_retrain/` holds the full labeled/scored
real-540 artifacts. `data/eval/real540_snapshot/` holds the metrics.json
and plots computed against them, kept separate from `data/eval/`'s
plots (which reflect the shipped `simulated-v2` model, regenerated and
re-verified after the recovery above).

## 12 · Oracle repair: the calibration failure was the labeller, not the corpus size (2026-09-14)

Section 11 closed by attributing the `t_hat = None` result to sample size
and prescribing a bigger corpus. **That diagnosis was wrong**, or at least
badly incomplete. Re-measuring the real-540 corpus and testing the oracles
directly found four defects in the labeller, three of them putting *wrong
labels* into the corpus rather than merely dropping samples.

### 12.1 · What was actually broken

**Defect A — both dynamic harnesses called functions with a fixed arity.**
`sqli_oracle` called `f(conn, PAYLOAD)`, exactly two arguments;
`cmdi_oracle` called `f(payload)`, exactly one. Any generated function with
a different signature raised `TypeError` and abstained. 7 of 15 SQLi task
groups and 6 of 15 cmdi task groups ask for other signatures — about 44% of
the dynamic prompt bank, structurally incapable of ever producing a label.
Measured on the real corpus, vulnerable flavor only:

| CWE-89 (harness sent 2 args) | ABSTAIN | SAFE | VULN |
|---|---|---|---|
| prompts requesting 2 params | 13 | 14 | 4 |
| prompts requesting 3 params | 19 | 0 | **0** |
| prompts requesting 4 params | 7 | 1 | **0** |

| CWE-78 (harness sent 1 arg) | ABSTAIN | SAFE | VULN |
|---|---|---|---|
| prompts requesting 1 param | 5 | 7 | 22 |
| prompts requesting 2 params | 17 | 2 | **0** |
| prompts requesting 3 params | 3 | 0 | **0** |

Every vulnerable label in the entire CWE-78 corpus came from a
one-argument prompt.

**Defect B — the SQLi oracle judged by row count**, so it could only see
injections that widened a `SELECT`. Verified by direct test against the
pre-fix oracle:

```
2-arg injectable SELECT           -> True    (correct)
3-arg injectable SELECT           -> None    (defect A)
2-arg injectable DELETE           -> False   FALSE NEGATIVE
2-arg SAFE parameterized COUNT(*) -> True    FALSE POSITIVE
```

`COUNT(*)` always returns exactly one row, so every parameterized
aggregate read as vulnerable. Two of the four CWE-89 `near_miss` samples
labelled VULN in the real corpus were the *correctly parameterized*
version of `count_by_category` — measurable label noise in the training
set. Of 15 SQLi task groups, only three ever produced a vulnerable label.

**Defect C — the creds oracle gated on Shannon entropy > 3.0.** Direct
test: `hunter2` (2.81), `letmein` (2.52), `P@ssw0rd` (2.75), `admin123`
(3.00) and `s3cr3t` (2.25) were all rejected; five of nine realistic
secrets. Real passwords are low-entropy by nature, which is what makes
them bad passwords, not what makes them safe.

**Defect D — `check_creds` returned `False` on unparseable input.** A model
that answered with prose instead of code was recorded as *safe*. This is
the same silent-failure path as decision #2 ("abstention is not safety"),
surviving in a third place, and it is why CWE-798 reported exactly **zero**
abstentions across 516 samples — a number that should have looked
suspicious on its face. `check_creds` now returns `bool | None`.

### 12.2 · The arithmetic nobody had done

LTT certifies iff `binom.cdf(k, n, alpha) <= delta`. Even in the best case
(`k = 0`, no vulnerable sample above the threshold), the minimum
`n_vuln_calib` is:

| alpha | minimum n |
|---|---|
| 0.05 | **59** |
| 0.10 | 29 |
| 0.20 | 14 |
| 0.30 | **9** |

The run had **8**. It missed the loosest bound tested by a single sample.
Headroom matters too: at n = 59 the certificate dies if even one vulnerable
sample scores above `t_hat`. Tolerance at alpha = 0.05 is `k <= 1` at
n = 100, `k <= 2` at n = 150, `k <= 4` at n = 200. The working target is
therefore **n_vuln_calib >= 120**, not 59.

### 12.3 · What the repairs recovered, measured on the same 516 samples

`scripts/relabel.py` re-runs the oracles over an existing
`generations.parquet`, so an oracle change is measured against real data
without regenerating anything. Reproduce with:

```bash
python scripts/relabel.py --generations data/runs/real_540/generations.parquet \
                          --out-dir data/runs/real_540_relabeled --no-semgrep
```

| | before | after |
|---|---|---|
| abstention rate | 28.3% | 24.4% |
| vulnerable rate (decided) | 10.0% | 17.7% |
| **n_vuln_calib** | **8** | **24** |
| CWE-78 vulnerable -> VULN | 22 / 56 | **38 / 56** |
| CWE-89 vulnerable -> VULN | 4 / 58 | **21 / 58** |
| CWE-798 vulnerable -> VULN | 9 / 58 | 10 / 58 |
| CWE-89 near_miss -> VULN (label noise) | 2 | **0** |
| CWE-798 near_miss -> VULN (label noise) | 0 | **0** |

**Three times the usable calibration evidence from the identical corpus.**
No new generation. The `near_miss` and `neutral` flavors produce zero
vulnerable labels across all three CWEs, which is the check that the
repairs did not simply loosen the oracles into flagging everything.

Two mechanisms were added to the harnesses and both earned their place:

- **A benign control run** precedes the payload runs in both dynamic
  oracles, so a `SAFE` verdict rests on having *observed* the function
  execute rather than on the absence of a crash. Near-miss code validates
  its input and rejects the payload outright — a regex whitelist raising
  `ValueError` is the canonical safe shape — so without a control run the
  oracle sees nothing and abstains. This alone accounted for 33 of 58
  CWE-78 near-miss samples.
- **`FileNotFoundError` counts as evidence of safety** in the cmdi oracle.
  It can only arise on the `shell=False` path, because `shell=True` execs a
  shell and a shell always exists (verified: `shell=True` returns a
  non-zero exit code for a missing binary and never raises). Without it,
  every near-miss sample invoking a tool the labelling machine lacks —
  `ffmpeg`, `gzip`, `git` — abstained. That was an environment artifact
  masquerading as unjudgeable code.

### 12.4 · An over-correction, caught and reverted

The first creds repair added a name-independent sweep flagging any literal
of 20+ characters with entropy above 3.5. It immediately produced **three
false positives in the CWE-798 `near_miss` flavor**: it was flagging
`https://thirdpartyapi.com` and MongoDB connection strings. Near-miss
samples are precisely the ones that teach the ranker to separate
alarming-looking safe code from the real thing, so poisoning them is worse
than missing a positive. The sweep was removed; only the unambiguous
`AKIA[0-9A-Z]{16}` key shape remains name-independent.

This is recorded because it is the failure mode this section is otherwise
about: loosening a detector until the numbers improve. The gate that caught
it was checking `near_miss` and `neutral` yield, not the headline count.

### 12.5 · What is still short, and why it is not a sample-size problem either

`n_vuln_calib` is **24** against a target of 120. Two causes, both
identified, neither solved by generating more samples against the current
setup:

1. **The sqlite3 fixture cannot execute Postgres-style code.** 19 of the 25
   remaining CWE-89 vulnerable abstentions are models writing `psycopg2`
   idiom — `%s` paramstyle, `with conn.cursor() as cur:` — which sqlite3
   rejects, so no statement is ever prepared and the trace callback sees
   nothing. Fixing this needs a recording DB-API shim that accepts both
   paramstyles and captures the SQL string as passed to `execute()`,
   rather than relying on SQLite having successfully prepared it.
2. **The CWE-798 vulnerable prompts do not produce hardcoded secrets.** The
   models are trained not to write them: asked to hardcode a password they
   write `password = "your_password"`, `YOUR_API_KEY`,
   `Bearer <hardcoded_api_key>`. These are placeholders and are correctly
   labelled safe — the prompt bank's own near-miss for task 003 uses a
   placeholder fallback as a *safe* shape, so calling placeholders
   vulnerable would collide two flavors. The fix is in the prompt, which
   must pin the literal ("written directly as the string literal
   `hunter2`"), not in the oracle.

A third, smaller gap: `check_creds` only inspects `ast.Assign` targets and
`ast.keyword` arguments, so a secret passed positionally —
`jwt.encode(payload, "my_jwt_secret_key_12345")` — is missed. Matching the
secret-name pattern against the literal's own text was considered and
rejected as too false-positive-prone. Recorded as a known limitation.

**Status:** oracle mechanism `SOLID` (89 oracle tests, including a
ground-truth suite pinning every defect above). Corpus yield `NEEDS WORK` —
the two causes in 12.5 come before any new generation run.

### 12.6 · The recording DB-API shim (2026-09-14)

Cause 1 from 12.5 is fixed. `src/codegate/oracles/dbapi_recorder.py` gives
the SQLi oracle a connection object that runs generated code against real
SQLite while capturing the SQL string each `execute()` was actually handed.

**Why the observation point moved twice.** The original oracle judged by
row count. The first repair moved to SQLite's own trace callback. Both
require SQLite to have *accepted* the statement — and models answer in
Postgres idiom regardless of the prompt naming sqlite3: `%s` paramstyle,
`with conn.cursor() as cur:`, `import psycopg2`. SQLite rejects all of it,
so nothing is prepared, the callback never fires, and an injectable
function is discarded as unjudgeable.

Recording at the call boundary decides the question the oracle actually
asks — did the caller's input reach the query as *text* or as a bound
parameter — before SQLite sees anything:

```
execute("... WHERE u = '" + name + "'")   -> payload in the SQL string
execute("... WHERE u = ?",  (name,))      -> payload in the parameters
execute("... WHERE u = %s", (name,))      -> payload in the parameters
```

It is still a dynamic oracle: the code genuinely runs, and SQL assembled
across f-strings, helper calls or loops is observed as finally built, which
no static match can do. A useful simplification falls out — detection no
longer needs valid SQL, so the second column-shaped payload and the
literal-aware quote scanner the trace-callback design required for
`ORDER BY` injection are both gone. One payload, one rule.

**A second, independent blocker.** `import psycopg2` raises at module level
*before* the target function is defined, so the sample died on the import.
The harness now installs a `sys.meta_path` finder that stubs only modules
that are genuinely absent — appended last, so every real finder gets first
refusal. Stub classes subclass `Exception` so `except psycopg2.Error:` is
legal, and carry `__path__` so `import mysql.connector` resolves. A
`NEVER_STUB` denylist covers `subprocess`, `os`, `sqlite3` and friends:
stubbing one of those would make the oracle observe a fake sink and report
SAFE for injectable code, which is the worst output this labeller can
produce. Those are all stdlib and always importable, so the guard should be
unreachable — it exists because being wrong there corrupts the corpus
silently rather than crashing.

Ordering is load-bearing and was got wrong once: the preamble must precede
the generated code, or the stub finder does not exist yet when the code's
imports run. `from __future__` statements are stripped from both embedded
fragments, since neither is the file's first statement any more.

**Measured on the same 516 samples:**

| | s11 baseline | after 12.3 | after the shim |
|---|---|---|---|
| abstention rate | 28.3% | 24.4% | **19.2%** |
| vulnerable rate (decided) | 10.0% | 17.7% | 18.7% |
| CWE-89 vulnerable -> VULN | 4 / 58 | 21 / 58 | **30 / 58** |
| CWE-89 vulnerable -> ABSTAIN | 39 / 58 | 25 / 58 | **7 / 58** |
| CWE-89 near_miss -> ABSTAIN | 38 / 58 | 21 / 58 | **12 / 58** |
| n_vuln_calib | 8 | 24 | 25 |

`n_vuln_calib` barely moved because the recovered samples landed mostly in
the train and test splits — calibration is only 5 of 15 task groups. That
is a prompt-bank allocation problem, not an oracle one, and it is what the
60-group expansion addresses.

**Projection for the expanded bank.** Per-CWE vulnerable-flavor yield now
measures 68% (CWE-78), 52% (CWE-89), 17% (CWE-798). At 60 task groups per
CWE with a 24/24/12 split, the calibration split carries 24 groups x 4
generators = 96 vulnerable-flavor samples per CWE, giving roughly
65 + 50 + 16 = **131 vulnerable calibration samples** against the target of
120. Raising CWE-798's yield by pinning the literal in its prompts (cause 2
in 12.5) would put it near 170.

**Status:** SQLi oracle `SOLID`. 125 oracle tests, including 21 for the
shim alone covering both paramstyles, cursor context managers, invalid SQL,
and the never-stub guard.

### 12.7 · Prompt bank expanded to 60 task groups per CWE (2026-09-14)

Cause 2 from 12.5 is fixed, and the bank is now sized for the certificate
rather than for convenience.

**Size and allocation.** 15 -> 60 task groups per CWE, split 24 train /
24 calib / 12 test by the rule `id %% 5 -> {1,2: train, 3,4: calib,
0: test}`. That is 540 prompts, and at 4 generators x 1 sample,
**2,160 samples**. The interleaved rule keeps thematically adjacent groups
from landing in the same split.

Calibration now carries 24 vulnerable-flavor prompts per CWE — 96 samples
each. At the yields measured in 12.6:

| CWE | calib vulnerable-flavor samples | measured yield | projected |
|---|---|---|---|
| CWE-78 | 96 | 68% | 65 |
| CWE-89 | 96 | 52% | 50 |
| CWE-798 | 96 | 17% | 16 |
| | | | **131** |

against a floor of 59 and a working target of 120. If the CWE-798 prompt
change below lifts that CWE to ~60%, the projection is 172.

**`samples_per_prompt` stays at 1.** The original plan's route to a bigger
corpus was 3 completions per prompt (540 -> 1,620). That would have been
the wrong kind of growth: LTT's binomial p-value assumes the calibration
samples are exchangeable draws, and three completions of the same prompt
from the same model are highly correlated, so n=300 of those is worth much
less than n=300 independent ones — the certificate would be quietly
optimistic rather than merely weak. New task groups are genuine new draws.

**CWE-798's prompts now pin the literal.** This is the fix for the 17%
yield. Asked simply to "hardcode the password", models write
`your_password`, `YOUR_API_KEY`, `Bearer <hardcoded_api_key>` — they are
trained not to emit real-looking secrets. Those are placeholders, the
oracle correctly clears them, and the bank's own near-miss for task 003
used a placeholder fallback as a *safe* shape, so relabelling them
vulnerable would have collided two flavors. Every vulnerable CWE-798 prompt
now names its secret ("...written as the string literal `hunter2`"), with
64 distinct literals, each verified against `check_creds` to confirm it is
actually detectable and contains no placeholder marker.
`tests/test_corpus.py` enforces the pinning.

**Statement-type and arity coverage.** The old CWE-89 bank was SELECT-heavy
because the old oracle could only see injections that widened a SELECT.
With that constraint gone the new groups span INSERT, UPDATE, DELETE,
ORDER BY, LIKE, BETWEEN, IN, JOIN, GROUP BY/HAVING, aggregates and
LIMIT/OFFSET. Arity is now deliberate rather than accidental — CWE-89
vulnerable prompts span 2/3/4 parameters (32/24/4 groups), CWE-78 spans
1/2/3 — and a test asserts the spread, so a regression in signature
handling shows up as failed labels instead of silence.

**`starcoder2:7b` dropped from `config.yaml`**, replaced by
`codegemma:7b-instruct`. It is a base completion model, not
instruction-tuned, and produced zero vulnerable samples across 163 attempts
in the real-540 run — volume without signal. Four distinct model families
are still required for the generator-shift experiment, so this is a swap,
not a removal.

**`split_ratios` removed from `config.yaml` and `CodeGateConfig`.** It was
parsed and validated to sum to 1.0 and read by nothing: splits come from
each task group's `split:` key, which is what `load_prompt_bank` reads.
Dead config that reads as live is how the hardcoded alpha/delta defect
(decision #3) went unnoticed. An old config still carrying the key loads
fine — it is now simply ignored, and a test pins that.

**Status:** prompt bank `SOLID` as a structure; its yield is `PROVISIONAL`
until the pilot run measures it. The projections above are extrapolations
from 516 samples, not results.

### 12.8 · Pilot corpus (2026-09-14, reviewed 2026-10-04)

The teammate's pilot (`origin/corpus/pilot`, commit `27b4598`) has 107 of
108 samples: groups 001–003 of each CWE × 3 flavors × 4 generators, with
one codellama sample missing. Full review: `docs/PILOT_REVIEW.md`.

Labelled with the oracles as they stood at `7583347`:
`python scripts/relabel.py --generations data/runs/pilot/generations.parquet --out-dir data/runs/pilot_labeled`

| Gate (plan Task 9) | Threshold | Result |
|---|---|---|
| Abstention | < 10% | 9.3% |
| Vulnerable flavor → VULN | ≥ 35% | 80.6% (29/36) |
| near_miss / neutral → VULN | 0 | 0 / 71 |
| Every generator ≥ 1 VULN | yes | min 5 (deepseek) |
| Unique code | > 90% | 100% |

Every gate passed, and `starcoder2`'s replacement, `codegemma`, was the
strongest generator (9/9). Reading all 17 non-ideal samples by hand found
three oracle problems, all fixed in 12.9: the credentials oracle missed
secrets in dict values, in positional `.login()` arguments, and passed via
a local variable (3 of 12 CWE-798 vulnerable samples, all labelled SAFE).
Allowlist-validated near-miss code abstained for every generator. Two
codellama output wrappers defeated `extract_code`.

### 12.9 · The full corpus, a resume defect, and the second oracle round (2026-10-04)

**What arrived.** `origin/corpus/real-540`, commit `54ab6e1`: 2,156 rows in
`data/runs/real_540/generations.parquet`. The guide said
`data/runs/real_2160/`, but the run was written into the directory that
still held the September checkpoint.

**The resume defect.** `run_generation` reused any checkpointed record
whose `sample_id` matched. That id hashes prompt id + generator only, not
the prompt's wording or split. So the run silently reused September's
answers for groups 001–015 from the three generators the runs share:
**404 rows byte-identical to the September corpus.** 78 of them answer
CWE-798 prompts that have been reworded since (the pinned-literal change
in 12.7), and 189 carry a split that has been reassigned since. Fixed in
`generation/harness.py`: every checkpoint record now stores
`prompt_fingerprint` (SHA-256 of the wording), resume reuses a record
only when it matches, and the split always comes from the current prompt.
Legacy records with no fingerprint are regenerated. Three tests in
`tests/test_generation_resume.py` pin this.

**The repair.** `scripts/repair_real_2160.py` (reproducible: it reads the
September corpus and the September prompt bank from git). It drops the 78
stale rows, re-derives every split from the bank, and writes a
fingerprinted checkpoint so the 82 missing samples (78 + 4 generation
failures) can be topped up by resuming. That gives 2,078 usable rows.
**Decision (2026-10-04):** assume the top-up never arrives, and make the
corpus symmetric across generators instead. `--symmetric` keeps only
prompts answered by all four models and drops 38 more rows, leaving
**2,040 rows = 510 prompts × 4 generators**. Without this, the gaps
cluster in CWE-798 groups 001–015 for three of the four models, which
skews the per-generator shift experiment. The rows are missing because
prompts were reworded, not because of anything about the code, so
dropping them does not bias the miss-rate.

**Second oracle round**, each change test-first, measured by relabelling:

- *CWE-798.* On the full corpus, 51 of 60 vulnerable-flavor samples
  labelled SAFE contained the pinned secret verbatim. They were in shapes
  the oracle never reached: bytes literals and `.encode()`, (user,
  password) tuples, `set_config("license_key", ...)` pairs, the trailing
  password of connect/auth calls, names like `routing_key`/`X-Routing-Key`,
  passwords in URLs or connection strings, webhook URLs, vendor key
  prefixes, and secrets returned from `get_jwt_secret()`. All were added,
  each with an environment-sourced negative twin. Guard: against the
  oracle at `7583347`, every changed CWE-798 verdict across all three
  corpora moved False → True, with none moving toward SAFE.
  One over-tightening was caught and reverted: treating the bare word
  "password" as a placeholder everywhere un-flagged
  `ftp.login("username", "password")` (3 real-540 samples). It is now a
  template word only inside URL and connection-string matches.
- *CWE-78.* A written sentinel is now VULNERABLE unconditionally. Code
  that parses the command's output (`int(out.split()[0])`) raised after
  the payload had run, and that used to read as no evidence. Generated
  code now runs inside a guard (`invocation.guarded_exec_source`), so a
  crashing module-level demo call no longer kills the harness. Payloads
  carry the code's own required suffix or prefix
  (`invocation.harvest_affixes`).
- *Both dynamic oracles.* The control run tries benign values harvested
  from the code's own allowlists and suffix checks, then a type flip
  (`benign_vectors`). This also exposed real injection beside an
  allowlisted parameter (`e5ce81d4-0`, a CWE-89 near-miss whose `keyword`
  is f-string-spliced; it used to abstain).
- *`extract_code`.* Fallbacks for `<details>` blocks and an unopened
  closing fence. Across all 2,701 real samples this changed 16
  extractions, none of which had parsed before; 15 now parse.

**Results** (`python scripts/relabel.py --generations <corpus> --out-dir <dir>`):

| Corpus | Measure | Earlier relabel¹ | Final |
|---|---|---|---|
| 2,078 (repaired) | abstention | 10.1% | **6.5%** |
| | `n_vuln_calib` | 192 | **212** |
| | CWE-798 vulnerable → VULN | 129 / 195 | **177 / 195** |
| | near_miss / neutral → VULN | 3 | 3 (all checked by hand: real) |
| real-540 (516) | abstention | 19.2% | 14.1% |
| pilot (107) | abstention | 9.3% | 0% |

¹ For the 2,078 corpus: its first relabel, which already had the 12.8 fixes. For real-540 and the pilot: the oracles at `7583347`.

The three safe-flavor VULN labels are code the model really wrote
vulnerable despite a safe prompt: `e5ce81d4-0` above, plus two CWE-798
near-misses that hardcode a meeting passcode (`"password": "123456"`).

**Still open.** CWE-78 near-miss abstains on 76/239 (32%). The safe code
validates input in ways no harvested value satisfies: an existing
destination directory, a path under a caller-supplied base directory, an
integer size range. These are lost hard negatives, not wrong labels. The
remaining CWE-798 misses are 3 vendor constructors taking the key
positionally (`PagerDuty("...")`, Algolia `Client(app, key)`), left alone
because catching a bare positional string needs guesswork that would risk
false positives.

**Removed as unused**, after confirming that nothing reads it: the label
adjudicator (config key, `GeminiBackend`, the `semgrep_hit AND
adjudicator_verdict` consensus fallback, and both labelled-schema
columns). The fallback could never fire, because `label_row` abstains
before consulting consensus. Also removed: the never-constructed
`OpenRouterBackend` and research-side `GroqBackend`, and the dead
`_shannon_entropy`. Labelling no longer runs semgrep, which was most of
its runtime.

**Also changed:** the held-out ranker AUC is reported beside the
full-corpus figure (`run_eval.py`). `codegate scan --alpha` is implemented
from a frontier persisted in `calibration.json`, accepting only alphas LTT
actually certified. `corpus_version` is a parameter instead of a
hardcoded `"real-540"`. `train_from_pregenerated.py` requires `--out-dir`,
because its default was `data/model/`.

### 12.10 · First certified threshold on real data (2026-10-04), not yet promoted

```
python scripts/repair_real_2160.py --generations data/runs/real_2160/generations.as_received.parquet --out-dir data/runs/real_sym --symmetric
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_train --corpus-version real-2040-sym
```

2,040 samples (510 prompts × 4 generators), 6.7% abstention, 26.9% vulnerable
among decided samples.

| α | t̂ | coverage (calib) | n_vuln_calib |
|---|---|---|---|
| **0.05** | **0.828** | **48.9%** | 206 |
| 0.10 | 0.776 | 56.4% | 206 |
| 0.20 | 0.744 | 63.0% | 206 |
| 0.30 | 0.698 | 69.3% | 206 |

Checked independently from the saved scores: 4 of 206 vulnerable
calibration samples score above t̂, and `binom.cdf(4, 206, 0.05) = 0.022 ≤ δ`.
Generator shift: calibrating on three models and testing on the fourth
holds for all four (realized risk 2.7% codegemma, 3.5% codellama, 2.2% deepseek,
4.5% qwen, against α = 5%).
Ranker ROC-AUC 0.891 on the held-out test split (0.926 including training
data).

**Not promoted to `data/model/`**, for two reasons that need a decision:

1. *Held-out test split: realized miss rate 8.4% (9 of 107).* That alone is
   not significant: P(≥ 9 | true rate 5%) = 0.088. But 7 of the 9 come
   from two CWE-798 task groups (webhook HMAC secrets, signing-key bytes).
   Those are shapes the labeller first recognised on 2026-10-04, and the
   ranker scores them as ordinary crypto code.
2. *Clustering.* The 206 vulnerable calibration samples come from only 67
   prompts. Four models answering the same prompt are correlated, while
   LTT's binomial test assumes independent draws, so the certificate is
   somewhat optimistic. This is the same concern that ruled out
   `samples_per_prompt > 1` (§12.7), in milder form. A task-group cluster
   bootstrap puts the test-split miss rate between 0.9% and 18.4%.

### 12.11 · Promoted at α = 0.10 (2026-10-04)

Decision: ship the real-corpus model at α = 0.10 (option 2 of 12.10), and
treat a cluster-aware certificate as the follow-up (branch
`feat/cluster-aware-certificate`).

No retraining was needed. The ranker and the calibration scores do not
depend on α, and LTT at 0.10 on the saved calibration scores reproduces
the frontier row exactly (t̂ = 0.7763, coverage 56.4%). `calibration.json` is
the trained certificate restated with `Calibration.at_alpha(0.10)`, and its
frontier is kept, so `codegate scan --alpha 0.05` still uses the certified
0.05 threshold. `ltt_trace.csv` was recomputed at 0.10. `config.yaml` now
says `alpha: 0.10`, so a fresh calibration run reproduces the shipped
operating point.

| Measure (`python scripts/run_eval.py`) | Simulated model | Real model at α = 0.10 |
|---|---|---|
| Ranker ROC-AUC, held-out test split | not measurable | **0.891** (n = 391) |
| Ranker ROC-AUC, including training data | 1.00 | 0.926 |
| Demo app, static + gate only | P 0.50 / R 1.00 | **P 0.33 / R 1.00** |
| Calib vulnerable auto-approved | — | 13 / 206 (binom.cdf = 0.043 ≤ δ) |
| Test split vulnerable auto-approved | — | 14 / 107 = 13.1% |

The real model still catches every vulnerable function in the demo app,
but escalates more safe ones to the verifier. That is a conservative
failure, and it costs LLM calls, not misses. The test-split figure
exceeds α. As at 0.05 this is not significant on its own (P(≥ 14 | 107,
0.10) = 0.18 under independence), but it is the same clustering
effect described in 12.10, and it is the reason the cluster-aware
certificate is next. The live-verifier row of the README was not re-run.
It needs a Groq key and spends API calls.

## 13 · Cluster-aware certificate (2026-10-04)

Branch `feat/cluster-aware-certificate`. Plan: `docs/cluster-aware-certificate/README.md`.

**The problem.** LTT's per-sample test counts every vulnerable calibration
sample as an independent Bernoulli draw. Four models answer each task, so
the shipped corpus's 206 vulnerable calibration samples are 66 task
groups. Their scores correlate within a group: ICC(1) = 0.57 (one-way
ANOVA on vulnerable calibration scores by task group, k₀ = 3.12), so the
design effect is 2.2 and the evidence is worth about 94 independent
samples, not 206. On held-out data the per-sample α = 0.10 threshold
auto-approved 13.1% of vulnerable code (§12.11).

**The method.** `gate/ltt.py::calibrate_threshold(..., groups=...)`. A
group's loss at threshold `t` is the fraction of its vulnerable samples
scoring ≥ `t`. The risk is the mean over groups holding a vulnerable
sample, and each threshold in the fixed sequence is tested with the
Hoeffding–Bentkus p-value for bounded losses (`hoeffding_bentkus_p_value`,
the p-value of Angelopoulos et al.'s "Learn then Test"). Validity needs
only task groups to be exchangeable; samples within a group may be
arbitrarily correlated. Groups are task groups (prompt id minus flavor),
so every model's answer to one task, in any flavor, is one group.
Selected by `certificate: cluster` in `config.yaml` (the default);
`certificate: sample` keeps the old test.

**Candidates compared first** (on the shipped scores, task group as unit;
test-split miss rate per sample / per group):

| α | per-sample binomial (old) | group any-miss, exact binomial | **group fraction, Hoeffding–Bentkus (chosen)** |
|---|---|---|---|
| 0.05 | t̂ 0.8276, 48.9%, test 8.4% / 6.8% | t̂ 0.9088, 29.2%, test 0 / 0 | t̂ 0.9088, 29.2%, test 0 / 0 |
| 0.10 | t̂ 0.7763, 56.4%, test 13.1% / 11.1% | t̂ 0.8313, 47.5%, test 7.5% / 6.1% | **t̂ 0.8276, 48.9%, test 8.4% / 6.8%** |
| 0.15 | t̂ 0.7524, 61.1%, test 16.8% / 14.6% | t̂ 0.8098, 50.4%, test 12.1% / 10.4% | t̂ 0.7772, 56.0%, test 13.1% / 11.1% |
| 0.20 | t̂ 0.7444, 63.0%, test 16.8% / 14.6% | t̂ 0.7907, 53.9%, test 13.1% / 11.1% | t̂ 0.7559, 60.6%, test 16.8% / 14.6% |

The fraction-based test was chosen: it bounds the same quantity as before
(share of vulnerable code auto-approved, weighted per task), it is the
bounded-loss form LTT itself prescribes, and it covers more than any-miss
at every α except 0.05, where they tie.

**Validity, by simulation.** Group sizes copied from the shipped corpus (66
groups), scores with within-group correlation ρ, 400 replications at
α = 0.10, δ = 0.05; failure means certifying a threshold whose true miss
rate exceeds α (allowed: ≤ δ):

| ρ | per-sample (old) | group any-miss | group fraction HB |
|---|---|---|---|
| 0.00 | 0.020 | 0.000 | 0.000 |
| 0.50 | **0.085** | 0.000 | 0.000 |
| 0.80 | **0.092** | 0.000 | 0.000 |
| 0.95 | **0.120** | 0.003 | 0.000 |

The per-sample test breaks its own δ once samples correlate. A seeded
version of this is a test
(`test_grouped_certificate_keeps_its_promise_under_strong_correlation`),
as is the mechanism behind it: copying every vulnerable sample four times
inside its own group loosens the per-sample threshold and leaves the
grouped one unchanged
(`test_duplicating_samples_inside_a_group_buys_no_looser_threshold`).

**Also fixed: the generator-shift experiment used training data.** It
calibrated on every split of three generators and measured every split of
the fourth, so the ranker's own training samples, which score
optimistically, were on both sides. It now calibrates on the calibration
split and judges the held-out generator on its samples the ranker never
trained on. Same honest experiment, α = 0.10:

| Held out | per-sample (old) | cluster-aware (new) |
|---|---|---|
| codegemma:7b-instruct | 12/91 = 13.2% | 10/91 = 11.0% (P(≥ 10 \| 10%) = 0.43) |
| codellama:7b | 5/69 = 7.2% | 2/69 = 2.9% |
| deepseek-coder:6.7b | 5/82 = 6.1% | 2/82 = 2.4% |
| qwen2.5-coder:7b | 5/71 = 7.0% | 4/71 = 5.6% |

The earlier "held for all four, 2.2–4.5%" (§12.10) was at α = 0.05 and
included training data; it is superseded.

**Shipped.**
```
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_cluster --corpus-version real-2040-sym
python scripts/run_eval.py
```
The ranker is byte-identical to §12.11's (`model.joblib` compared with
`cmp`); only the certificate changed. `calibration.json` now records
`method: cluster-hb` and `n_vuln_groups: 66`, and every report names the
method.

| | per-sample (§12.11) | **cluster-aware (now)** |
|---|---|---|
| t̂ at α = 0.10 | 0.7763 | **0.8276** |
| coverage (calib) | 56.4% | **48.9%** |
| held-out vulnerable auto-approved | 13.1% per sample | **8.4% per sample, 6.8% per group** (95% cluster bootstrap 0.8–15.2%) |
| α = 0.05 also certified | t̂ 0.8276, 48.9% | t̂ 0.9088, 29.2% |
| demo app, static + gate | 6 auto-approved / 8 escalated; P 0.33, R 1.00 | 3 / 11; P 0.25, R 1.00 |

**Also corrected:** the PDF's guarantee sentence said "for any function
scored at or above t_hat, the probability it is actually vulnerable is at
most α". That is not what LTT bounds. It now says of vulnerable
functions, at most α are auto-approved.

**Status:** `SOLID`. 435 tests pass.

### 13.1 · Retrain after the creds-oracle review fixes (2026-10-05)

A code review of the branch found two false-positive shapes in
`check_creds`, both fixed test-first (commit `2c88e71`):

- A name ending in a pointer word (`TOKEN_URL`, `SECRET_KEY_FILE`,
  `private_key_id`) was read as holding a secret. `_is_secret_name` now
  rejects names whose last word is in `_POINTER_SUFFIXES`.
- `connect(host, 22, "deploy", password=os.environ["PW"])` flagged the
  username, because the last positional argument of a credential call was
  taken as the password even when the password came by keyword.

Fixing the first exposed a gap: a full PEM private key was never matched,
because its newlines fail the no-whitespace rule. Five service-account
samples had been caught only through their `private_key_id` field. PEM
private-key headers are now a known key shape.

```
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_retrain --corpus-version real-2040-sym
python scripts/run_eval.py --model-dir data/runs/real_sym_retrain
```

**Labels.** Three of 2,040 changed, all in the train split, so the
calibration data is unchanged:

| sample | prompt | old → new | why |
|---|---|---|---|
| `fc92eb38-0` | CWE-798-027-vulnerable | VULN → SAFE | holds only `private_key_id` and a `YOUR_PRIVATE_KEY` placeholder |
| `6c2e3eaf-0` | CWE-798-027-vulnerable | VULN → SAFE | same |
| `76aba915-0` | CWE-78-042-vulnerable | ABSTAIN → VULN | timing, not the fix (below) |

`76aba915-0` is genuinely injectable (`os.system(f"npm install
{package_name}")`), but its example call runs a real `npm install express`
at import. That takes about 11 s against the oracle's 15 s timeout, so
under the load of a full labelling run it can time out and abstain. It is
the only sample of 2,040 whose label differed between two full runs. A
timeout is an abstention, never a SAFE, so the failure mode is safe.

Prompt CWE-798-027 pins `private_key_id` as its secret. That is an
identifier, so the prompt cannot reliably elicit a hardcoded secret. It
should pin `private_key` before any future generation run.

**Promoted.** The retrained model does marginally worse on held-out data:
one more vulnerable test sample crosses the threshold. It was promoted
anyway, because its labels are more correct, and keeping the old model on
the strength of its test-split numbers would be selecting a model on the
test set.

| | before (§13) | **after** |
|---|---|---|
| t̂ at α = 0.10 / coverage (calib) | 0.8276 / 48.9% | **0.8259 / 48.8%** |
| α = 0.05 | t̂ 0.9088, 29.2% | t̂ 0.9091, 29.2% |
| held-out vulnerable auto-approved | 8.4% per sample (9/107), 6.8% per group (CI 0.8–15.2%) | **9.3% per sample (10/107), 7.6% per group** (CI 0.8–16.7%) |
| ranker ROC-AUC, held-out (full corpus) | 0.891 (0.926) | 0.889 (0.925) |
| generator shift: codegemma / codellama / deepseek / qwen | 11.0 / 2.9 / 2.4 / 5.6% | 11.0 / 2.9 / 3.7 / 7.0% |
| demo app, static + gate | 3 / 11; P 0.25, R 1.00 | 4 auto-approved / 10 escalated; P 0.27, R 1.00 |
| corpus: abstentions / vulnerable among decided | 136 (6.7%) / 26.9% | 135 (6.6%) / 26.8% |

Ranker scores moved by a median of 0.002; the largest moves (up to 0.16)
are the relabelled CWE-798-027 samples and their siblings.

**Status:** `SOLID`. 442 tests pass.
