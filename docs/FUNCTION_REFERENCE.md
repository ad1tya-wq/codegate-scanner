# CodeGate — Function Reference

This document is a flat, per-function technical reference for the CodeGate
codebase. It exists for a different purpose than `docs/ENGINEERING_LOG.md`:
the engineering log is a narrative (phases, decisions, why things changed
over time), while this document is a lookup table — "what does `X` do,
who calls it, what does it call" — so a teammate, a guide, or a grader can
answer that question without reading the source. Every function and method
in `src/codegate/` and `scripts/` gets exactly one entry below, in source
order, grouped by file and package. Trivial one-line `__init__`/`__repr__`
methods and pure dataclass containers with no behavior are skipped when
there is genuinely nothing to say about them; this is noted inline where it
happens.

Architecture reference (used by every entry's "Fits in" field):

```
OFFLINE (research, rare, produces artifacts):
  prompts -> LLM generation -> code samples
       -> oracles label each sample (detonation-based dynamic execution + static checks)
       -> train ranker (features -> risk score)
       -> calibrate via LTT (Learn-Then-Test) -> produces t_hat threshold
       -> both persisted as data/model/model.joblib + data/model/calibration.json

ONLINE (scanner, runs constantly, consumes artifacts):
  target directory -> ingest (walk .py files, ast.parse into function-level units)
       -> static pre-pass (semgrep + AST creds scan)
       -> rank (score each unit via the trained ranker)
       -> gate (score >= t_hat ? auto-approve : escalate) -- uses calibration.json
       -> verify (escalated units only: one constrained LLM call each, cached by content hash)
       -> report (PDF/JSON/SARIF/terminal, deterministic, no LLM writes report prose)
```

---

## config.py

### `config.load_config(path: str = "config.yaml") -> CodeGateConfig`
**Does:** Reads `config.yaml`, validates one cross-field invariant (the
adjudicator model must not also appear in the generators list), and returns
an immutable `CodeGateConfig` built from the raw YAML. A `split_ratios`
key was also parsed and validated here until 2026-09-14; it was read by
nothing, since splits are assigned per task group by the `split:` key in
each prompt YAML. An old config still carrying the key loads fine — it is
simply ignored.
**Talks to:** Called by `cli.py::calibrate` and `cli.py::scan` (to look up
the verifier model name), and by every entry-point script
(`scripts/run_real.py::main`, `scripts/run_pipeline_dry_run.py::main`,
`scripts/train_from_pregenerated.py::main`). Calls nothing else in the
codebase — reads the file itself via `pathlib.Path` and `yaml.safe_load`.
**Tech:** `pathlib.Path`, `yaml` (PyYAML).
**Fits in:** Shared by both halves — it's the one piece of config both the
OFFLINE research pipeline (`calibrate`) and the ONLINE scanner (`scan`,
for the verifier model name only) read from.

*(`CodeGateConfig` itself is a frozen dataclass with no methods — plain
data, nothing to document beyond the fields `load_config` populates.)*

---

## env.py

### `env._ensure_env_loaded() -> None`
**Does:** Loads `.env` from the repo root into `os.environ` exactly once
per process, using a module-level `_loaded` flag so repeated calls are
cheap no-ops.
**Talks to:** Called only by `get_env` and `require_env` in this same
module, as their shared first step. Calls `dotenv.load_dotenv`.
**Tech:** `python-dotenv` (`load_dotenv`), `pathlib.Path`.
**Fits in:** Infrastructure used by both halves — anywhere an API key or
host URL is read from the environment.

### `env.get_env(name: str, default: str) -> str`
**Does:** Returns environment variable `name` (loading `.env` first),
falling back to `default` if unset or empty. For optional settings where a
missing value shouldn't stop the run.
**Talks to:** Called by `cli.py::calibrate` (for `OLLAMA_BASE_URL`) and
`scan/verifier.py::build_verifier_backend` (for `GROQ_API_KEY`, with
`default=""` so a missing key degrades to "no verifier" rather than an
error). Calls `_ensure_env_loaded`.
**Tech:** `os.environ`.
**Fits in:** Shared infrastructure — OFFLINE (Ollama host URL for
generation) and ONLINE (Groq API key for the LLM verifier).

### `env.require_env(name: str) -> str`
**Does:** Returns environment variable `name` (loading `.env` first), or
raises a `RuntimeError` with an actionable message pointing at `.env` and
the README if it's missing. For settings that have no sensible default and
whose absence should stop the run immediately rather than fail later with
a confusing error.
**Talks to:** Not currently called anywhere in `src/codegate` or
`scripts/` — the two real callers of environment values
(`cli.py::calibrate`, `scan/verifier.py::build_verifier_backend`) both use
the softer `get_env` instead, since both need to degrade gracefully rather
than hard-fail. `require_env` is available for a future required-secret
case but is presently unused outside its own module. Calls
`_ensure_env_loaded`.
**Tech:** `os.environ`.
**Fits in:** Shared infrastructure, currently unexercised.

---

## schemas.py

### `schemas.validate_dataframe(df: pd.DataFrame, schema_name: str) -> None`
**Does:** Checks a DataFrame against one of the three named schemas
(`"generations"`, `"labeled"`, `"scores"`) — missing columns, unexpected
extra columns, and dtype mismatches (with numeric/bool-like tolerance,
e.g. `int32` accepted where `int64` is declared) — and raises `SchemaError`
listing every problem found, or returns silently if the frame is valid.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` (on the
generations DataFrame, right after generation) and
`scripts/run_real.py::main` (also on the generations DataFrame, in the
`--generate-only` path before writing `generations.parquet`). Calls
nothing else — pure pandas dtype introspection.
**Tech:** `pandas`.
**Fits in:** OFFLINE — a data-integrity gate between pipeline stages,
catching a malformed generations frame before it's labeled or trained on.

*(`SchemaError` is a one-line `ValueError` subclass with no body — nothing
to document beyond its role as the raised exception type.)*

---

## cli.py

The `codegate` command-line entry point (Typer app, three commands:
`info`, `calibrate`, `scan`). Imports from both halves of the system but
keeps the OFFLINE import (`research.pipeline`) lazy — see `calibrate`'s
docstring-comment for why.

### `cli.info(model_dir: Path = DEFAULT_MODEL_DIR) -> None`
**Does:** Loads the currently-installed model and calibration and prints
them as a Rich table (ranker id, corpus version, t_hat, alpha, delta,
calibration sample count, creation timestamp), with an extra yellow
warning banner if the certificate is provisional (calibrated on the
simulated corpus rather than a real one).
**Talks to:** Invoked directly by Typer when the user runs `codegate
info`. Calls `research/artifacts.py::load_artifacts`.
**Tech:** `typer`, `rich.console.Console`, `rich.table.Table`.
**Fits in:** ONLINE — a read-only inspection command over the artifacts
the scanner would use; doesn't scan anything itself.

### `cli.calibrate(config, out_dir, real, base_url, limit) -> None`
**Does:** Re-runs the OFFLINE research pipeline end-to-end: loads config
and the prompt bank, builds either `SimulatedBackend`s (default) or
`OllamaBackend`s (`--real`) per configured generator, then calls
`run_full_pipeline` and prints a one-line summary (vulnerable rate,
t_hat, coverage) plus where the artifacts were written.
**Talks to:** Invoked by Typer for `codegate calibrate`. Calls
`config.py::load_config`, `research/corpus/prompts.py::load_prompt_bank`,
`env.py::get_env`, `research/generation/backends.py::OllamaBackend`/
`SimulatedBackend`/`stable_seed`, and (lazily imported, not at module
level) `research/pipeline.py::run_full_pipeline`.
**Tech:** `typer`, `rich.console.Console`.
**Fits in:** OFFLINE — this command *is* the offline pipeline's
command-line trigger. The `research.pipeline` import is deliberately
deferred to inside the function body: it transitively imports
`matplotlib` (via `research/eval/plots.py`), which is only declared in the
optional `research` extra, so a plain `pip install -e .` must not crash on
every `codegate` invocation just because `calibrate` needs it.

### `cli.scan(path, format, output, no_llm, alpha, model_dir, config) -> None`
**Does:** Validates `--format`, rejects `--alpha` (not yet implemented —
overriding the certified threshold requires recomputing it from the
calibration trace, deferred), optionally builds a verifier backend from
the configured verifier model, runs the scan, and renders the result in
the requested format (terminal/json/sarif/pdf) — writing to `--output` or
an appropriate default (stdout for json/sarif, `codegate_report.pdf` for
pdf).
**Talks to:** Invoked by Typer for `codegate scan`. Calls
`config.py::load_config`, `scan/verifier.py::build_verifier_backend`,
`scan/pipeline.py::run_scan`, and one of
`report/terminal.py::render_terminal`, `report/json_sarif.py::to_json`/
`to_sarif`, `report/pdf.py::generate_pdf` depending on `--format`.
**Tech:** `typer`, `rich.console.Console`.
**Fits in:** ONLINE — this command *is* the scanner's command-line entry
point, covering ingest through report in one call.

---

## gate/

The statistical core: Learn-Then-Test calibration (`ltt.py`) and the
supporting risk-estimation helpers used by the eval/shift code (`risk.py`).

### gate/ltt.py

#### `gate.ltt.calibrate_threshold(scores, labels, alpha, delta, thresholds=None) -> LTTResult`
**Does:** Runs Learn-Then-Test fixed-sequence testing over a descending
grid of candidate thresholds (largest/most-conservative first, `+inf`
prepended as a trivially-valid starting point) to find the
least-conservative `t_hat` such that the miss-rate on vulnerable
calibration samples is certified `<= alpha` with confidence `>= 1 - delta`.
For each threshold it computes `k = count(vuln_scores >= t)` and a p-value
via `scipy.stats.binom.cdf(k, n, alpha)` for the null hypothesis "true risk
>= alpha"; a small p-value (`<= delta`) certifies the threshold. Stops at
the first threshold that fails certification, since monotonicity of the
risk function guarantees every less-conservative threshold also fails.
Returns `t_hat=None` when even the most conservative threshold can't be
certified, meaning "escalate everything."
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` (at the
project's configured alpha/delta, to produce the certificate that gets
persisted) and `research/eval/frontier.py::compute_frontier` (swept
across a range of alphas) and `research/eval/shift.py::run_shift_experiment`
(per generator-holdout). Calls nothing else in the codebase — pure
numpy/scipy.
**Tech:** `numpy`, `scipy.stats.binom`.
**Fits in:** OFFLINE — the calibration step that turns ranker scores +
labels into the `t_hat` threshold persisted in `calibration.json`, which
the ONLINE gate (`scan/pipeline.py::_rank_and_gate`) later reads and
compares scores against.

*(`LTTResult` is a frozen dataclass holding `t_hat`/`alpha`/`delta`/
`n_vuln_calib`/`coverage`/`trace` — no methods of its own.)*

### gate/risk.py

#### `gate.risk.empirical_risk(scores: np.ndarray, labels: np.ndarray, t: float) -> float`
**Does:** Computes `R_hat(t)` — the fraction of vulnerable-labeled samples
whose score is `>= t` (i.e. would be auto-approved at threshold `t`).
Returns `nan` if there are no vulnerable samples to measure against.
**Talks to:** Called by `research/eval/shift.py::run_shift_experiment`, to
measure the realized risk on a held-out generator's own data after
calibrating on everyone else. Calls nothing else — pure numpy.
**Tech:** `numpy`.
**Fits in:** OFFLINE — the generator-shift robustness experiment that
checks whether an LTT certificate calibrated on some generators still
holds when applied to a different one.

#### `gate.risk.clopper_pearson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]`
**Does:** Returns the exact binomial confidence interval `(lo, hi)` for
`k` successes out of `n` trials, via the beta-distribution inversion
(Clopper-Pearson method). Returns `(0.0, 1.0)` for `n == 0`.
**Talks to:** Not called anywhere in `src/codegate` or `scripts/` today —
a standalone statistical utility with no current caller in this codebase
(not referenced by `gate/ltt.py`'s own certification logic, which uses the
binomial CDF directly rather than a confidence interval). Calls nothing
else — pure scipy.
**Tech:** `scipy.stats.beta`.
**Fits in:** OFFLINE — available as a general risk/coverage utility;
presently unexercised by the pipeline.

---

## oracles/

Ground-truth labelers for the OFFLINE research corpus: two dynamic
(detonation-based) oracles for CWE-89/CWE-78, one static oracle for
CWE-798, a sandbox executor they share, an AST helper, a consensus-voting
rule that combines oracle output with semgrep/adjudicator signal, and the
semgrep wrapper itself (used by both this package's consensus step and,
separately, the ONLINE scanner's static pre-pass).

### oracles/ast_utils.py

#### `oracles.ast_utils.function_exists(code: str, function_name: str) -> bool`
**Does:** Parses `code` and returns `True` if it defines a (possibly
nested) function named `function_name`; returns `False` on a syntax error
or if no such function exists.
**Talks to:** Called by `oracles/sqli_oracle.py::check_sqli` and
`oracles/cmdi_oracle.py::check_cmdi`, both as a pre-check before attempting
to detonate the snippet (no point sandboxing code whose target function
doesn't exist). Calls `ast.parse`, `ast.walk`.
**Tech:** `ast`.
**Fits in:** OFFLINE — a shared precondition check used by the dynamic
oracles before detonation.

### oracles/sandbox.py

#### `oracles.sandbox._kill_process_tree(pid: int) -> None`
**Does:** Kills a process and every descendant it spawned — on Windows via
`taskkill /F /T /PID`, on POSIX via `os.killpg` with `SIGKILL`. Exists
because `Popen.kill()` only signals the direct child; if the sandboxed
snippet itself shells out (exactly what the cmdi detonation payload does),
that grandchild process survives the parent's death and can hold
stdout/stderr pipes open forever, hanging `communicate()` even after the
wall-clock timeout fired. The module docstring records a real 56+ minute
hang this was written to fix.
**Talks to:** Called only by `run_sandboxed` in this same module, on
timeout. Calls `subprocess.run` (Windows) or `os.killpg`/`os.getpgid`
(POSIX).
**Tech:** `subprocess`, `platform`, `os`, `signal`.
**Fits in:** OFFLINE — process-isolation plumbing under the detonation
oracles.

#### `oracles.sandbox.run_sandboxed(code: str, harness: str, timeout_s: float = 5.0) -> SandboxResult`
**Does:** Writes `harness + code` to a temp file and runs it as a fresh
Python subprocess with a wall-clock timeout, in its own process
group/session so the whole tree can be killed together. Returns captured
stdout/stderr/returncode, or a `timed_out=True` result with empty output if
the timeout fires (after killing the process tree and doing a bounded reap
so no zombie lingers). Documented as best-effort process-level isolation
only (no network disable, no container, no read-only filesystem) — the
docstring is explicit that this must be swapped for a real container
sandbox before running against untrusted LLM-generated code at scale.
**Talks to:** Called by `oracles/sqli_oracle.py::check_sqli` and
`oracles/cmdi_oracle.py::check_cmdi`, each with its own detonation harness
appended to the target code. Calls `subprocess.Popen`, `_kill_process_tree`.
**Tech:** `subprocess`, `tempfile`, `pathlib.Path`, `sys`, `platform`.
**Fits in:** OFFLINE — the shared execution engine both dynamic oracles
detonate code through. Explicitly never used by the ONLINE scanner (see
`scan/pipeline.py::run_scan`'s docstring: scanning arbitrary user code must
never execute it).

*(`SandboxResult` is a frozen dataclass — `stdout`/`stderr`/`returncode`/
`timed_out` — no methods.)*

### oracles/sqli_oracle.py

#### `oracles.sqli_oracle.has_sql_sink(code: str) -> bool`
**Does:** Cheap lexical scope check — does `code` contain any marker that
suggests it might execute SQL at all (`.execute`, `cursor`, `select `,
`sqlite3`, `sqlalchemy`, etc., case-insensitive)? Deliberately
over-inclusive: any hint of SQL routes to the real dynamic oracle rather
than being short-circuited.
**Talks to:** Called only by `check_sqli` in this same module, as the
first check. Calls nothing else — a plain substring scan.
**Tech:** none beyond stdlib string methods.
**Fits in:** OFFLINE — lets `check_sqli` return a confident `False`
("safe", not "unknown") for code that plainly can't touch a database,
instead of needlessly discarding a valid negative sample as an abstention.

#### `oracles.sqli_oracle.check_sqli(code: str, function_name: str) -> bool | None`
**Does:** The CWE-89 dynamic oracle. If `has_sql_sink` is `False`, returns
`False` immediately (confidently safe). Otherwise, if the named function
doesn't exist, returns `None` (abstain — no evidence). Otherwise builds an
in-memory SQLite fixture (a union of every plausible table name a model
might pick — `users`, `accounts`, `t`, etc. — so the harness doesn't fail
just because the model chose an unexpected table name) and detonates the
function with a classic `' OR '1'='1` payload via `run_sandboxed`. Returns
`True` if the payload widened the result set beyond a legitimate
single-user lookup (the injection "fired"), `False` if the function ran
but neutralized it, and `None` if the sandbox timed out or the function
raised before printing evidence.
**Talks to:** Called by `research/pipeline.py::label_row` (in production,
for every `CWE-89` sample, trying each candidate function name in turn)
and `research/eval/metrics.py::oracle_accuracy_on_fixtures` (against the
hand-labeled fixtures). Calls `has_sql_sink`,
`oracles/ast_utils.py::function_exists`, `oracles/sandbox.py::run_sandboxed`.
**Tech:** stdlib `sqlite3` (only inside the generated harness template, not
imported by this module directly).
**Fits in:** OFFLINE — the ground-truth labeler for CWE-89 samples in the
research corpus.

### oracles/cmdi_oracle.py

#### `oracles.cmdi_oracle.has_shell_sink(code: str) -> bool`
**Does:** Cheap lexical scope check — does `code` contain any marker
suggesting it might invoke a shell or spawn a process (`subprocess`,
`os.system`, `os.popen`, `pty.spawn`, `shell=true`, etc.,
case-insensitive)? Same over-inclusive rationale as
`sqli_oracle.has_sql_sink`.
**Talks to:** Called only by `check_cmdi` in this same module. Calls
nothing else.
**Tech:** none beyond stdlib string methods.
**Fits in:** OFFLINE — lets `check_cmdi` return a confident `False` for
code that can't plausibly invoke a shell.

#### `oracles.cmdi_oracle.check_cmdi(code: str, function_name: str) -> bool | None`
**Does:** The CWE-78 dynamic oracle. If `has_shell_sink` is `False`,
returns `False` immediately. If the function doesn't exist, returns
`None`. Otherwise detonates the function with a shell-metacharacter
payload (`127.0.0.1 & echo pwned > <sentinel file>`) via `run_sandboxed`
and checks whether the sentinel file was created — proof the payload
reached a real shell. Uses `&` rather than `;` as the separator
deliberately, so the same payload works identically whether the sandboxed
code's `shell=True` call runs through POSIX sh or Windows `cmd.exe`.
Returns `None` if the sandbox timed out or the function errored before
confirming it ran.
**Talks to:** Called by `research/pipeline.py::label_row` (for every
`CWE-78` sample) and `research/eval/metrics.py::oracle_accuracy_on_fixtures`.
Calls `has_shell_sink`, `oracles/ast_utils.py::function_exists`,
`oracles/sandbox.py::run_sandboxed`.
**Tech:** `tempfile`, `uuid`, `pathlib.Path`.
**Fits in:** OFFLINE — the ground-truth labeler for CWE-78 samples in the
research corpus.

### oracles/creds_oracle.py

#### `oracles.creds_oracle._shannon_entropy(s: str) -> float`
**Does:** Computes the Shannon entropy (bits per character) of string `s`,
used as a crude randomness signal to distinguish a plausible secret
(`"Sup3rSecretPassw0rd!"`, high entropy) from an obviously non-secret
literal (`"changeme"`, low entropy — though that case is also caught
separately by the placeholder-marker check).
**Talks to:** Called only by `check_creds` in this same module, twice (once
per literal-collection loop). Calls nothing else — pure math.
**Tech:** `math.log2`.
**Fits in:** OFFLINE — a scoring primitive inside the static CWE-798
oracle.

#### `oracles.creds_oracle.check_creds(code: str) -> bool`
**Does:** The CWE-798 static oracle (no dynamic execution). Walks the AST
looking for string-literal assignments, keyword arguments, and default
parameter values whose target name matches a secret-ish pattern
(`password`, `api_key`, `token`, `credential`, etc.). For each candidate,
skips obvious placeholders (`"changeme"`, `"xxx"`, `"<..."`, etc.) and
flags it as a hardcoded credential if the literal's Shannon entropy exceeds
a threshold (3.0 for assignments/kwargs, 2.5 for default-arg literals) or
it matches a known key-shape regex (an AWS access-key-id pattern or a
40-char base64-shaped string). Returns `False` on a syntax error.
**Talks to:** Called by `research/pipeline.py::label_row` (as the
`static_verdict` for every `CWE-798` sample) and
`research/eval/metrics.py::oracle_accuracy_on_fixtures`. Calls
`_shannon_entropy`.
**Tech:** `ast`, `re`, `math`.
**Fits in:** OFFLINE — the ground-truth labeler for CWE-798 samples. Also
notable as the only oracle whose logic is structurally close to what the
ONLINE scanner's static pre-pass does (AST pattern matching, no
execution) — though the scanner itself uses semgrep rules for this, not
this function directly.

### oracles/consensus.py

#### `oracles.consensus.consensus_label(cwe, semgrep_hit, dynamic_verdict, static_verdict, adjudicator_verdict) -> int`
**Does:** Applies "consensus rule v1" to combine oracle/semgrep/adjudicator
signal into a final binary label. For the two CWEs with a dynamic oracle
(CWE-89, CWE-78): the dynamic verdict is authoritative when it returned
one (not `None`); otherwise falls back to `semgrep_hit AND
adjudicator_verdict`. For the static-only CWE (CWE-798): the static
verdict is authoritative when present, same fallback otherwise. Raises
`ValueError` for any CWE not in its known sets — treated as a
ruleset/pipeline-drift bug, not silently defaulted.
**Talks to:** Called by `research/pipeline.py::label_row`, as the final
step turning per-sample oracle output into the `label` column. Calls
nothing else.
**Tech:** none beyond plain conditionals — no external libraries.
**Fits in:** OFFLINE — the labeling policy that turns multiple oracle
signals into the single ground-truth label the ranker is trained on and
the LTT gate is calibrated against.

### oracles/semgrep_oracle.py

#### `oracles.semgrep_oracle._run_semgrep_cli(target: Path, ruleset_path: Path | None = None, timeout: int = 60) -> dict`
**Does:** The shared CLI invocation both public functions below delegate
to. Runs the `semgrep` binary against `target` (file or directory) using
CodeGate's local hand-written ruleset (`data/semgrep_rules/codegate_rules.yaml`)
by default — chosen over the free community registry packs, which were
verified empirically to produce zero findings on this project's raw-stdlib
corpus. Parses the JSON output into a normalized `{"hit": bool,
"findings": [...]}" shape (each finding: rule_id, severity, path,
start_line, end_line, message). Degrades to `{"hit": False, "findings":
[], "error": ...}` rather than raising if the binary is missing or times
out, or if its output doesn't parse as JSON.
**Talks to:** Called only by `run_semgrep` and `run_semgrep_on_path` in
this same module. Calls `subprocess.run`, `json.loads`.
**Tech:** `subprocess`, `json`, `pathlib.Path`.
**Fits in:** Shared by both halves — the common semgrep execution path.

#### `oracles.semgrep_oracle.run_semgrep(code: str, ruleset_path: Path | None = None) -> dict`
**Does:** Runs semgrep against one in-memory code snippet by writing it to
a temp file first. Used wherever the caller has synthetic code rather than
a real file already on disk.
**Talks to:** Called by `research/pipeline.py::label_row` (as the semgrep
signal feeding `consensus_label`), `ranker/r0_semgrep_score.py::score_r0`
(per-row, to build the R0 danger score), and
`research/eval/metrics.py::oracle_accuracy_on_fixtures` (against the
fixture files, read into memory first). Calls `_run_semgrep_cli`.
**Tech:** `tempfile`, `pathlib.Path`.
**Fits in:** OFFLINE — semgrep-as-a-labeling-signal for the research
corpus.

#### `oracles.semgrep_oracle.run_semgrep_on_path(target: Path, ruleset_path: Path | None = None) -> dict`
**Does:** Runs semgrep directly against a real file or directory already
on disk — one CLI invocation covering the whole target, rather than one
per unit. Findings carry real file paths and line numbers so they can be
mapped back to specific ingested `Unit`s. Uses a longer timeout (120s vs.
60s) than `run_semgrep`, since a directory scan is heavier than a
single-snippet one.
**Talks to:** Called by `scan/pipeline.py::_semgrep_findings`, the ONLINE
scanner's static pre-pass. Calls `_run_semgrep_cli`.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE — the static pre-pass step, run once per scan over the
whole target directory before ranking/gating begins.

---

## ranker/

Two rankers implementing the `scores` schema contract (`sample_id`,
`ranker_id`, `score`, higher = safer): `R0` (cheap semgrep-derived score,
research-only) and `R2` (a trained logistic-regression classifier over a
hashed bag-of-tokens embedding — the one actually used by the pipeline and
the scanner).

### ranker/r0_semgrep_score.py

#### `ranker.r0_semgrep_score.score_r0(generations_df: pd.DataFrame) -> pd.DataFrame`
**Does:** The cheapest ranker: runs semgrep on every row's code, turns the
finding count/severity into a monotone "danger" score (severity-weighted
sum: ERROR=3, WARNING=2, INFO=1) and negates it to a safety score (higher
= safer, matching the LTT gate's convention). One semgrep subprocess
invocation per row.
**Talks to:** Not called by `research/pipeline.py::run_full_pipeline` or
any other production code path — the pipeline trains and scores with
`R2Ranker` instead. Presently exercised only by `tests/test_ranker.py`.
Calls `oracles/semgrep_oracle.py::run_semgrep`.
**Tech:** `pandas`.
**Fits in:** OFFLINE (ranker stage) — implemented and tested but not
wired into the production calibration path. The function's own docstring
flags a known scaling problem (row-by-row semgrep calls cost ~1-10s of
process startup each, so it doesn't scale past a few hundred samples)
that would need fixing (batched semgrep calls) before it could replace or
supplement R2 at full corpus scale.

### ranker/r2_embedding_lr.py

#### `ranker.r2_embedding_lr._embed(code_series: pd.Series) -> np.ndarray`
**Does:** Converts a Series of code strings into a dense 512-dimension
hashed bag-of-tokens embedding matrix via a module-level
`HashingVectorizer`. Explicitly a stand-in for a real code embedding
(CodeBERT/UniXcoder via `transformers`) — the docstring notes this is a
drop-in swap that wouldn't change `R2Ranker`'s public interface or any
downstream consumer; it exists so the ranker is fully functional and
testable offline with zero model download.
**Talks to:** Called by `R2Ranker.fit` and `R2Ranker.score`. Calls
`sklearn.feature_extraction.text.HashingVectorizer.transform`.
**Tech:** `sklearn.feature_extraction.text.HashingVectorizer`, `numpy`.
**Fits in:** OFFLINE (ranker stage) / ONLINE (rank stage) — this is the
feature representation used at both training time and scan time.

**`class ranker.r2_embedding_lr.R2Ranker`** — the production ranker. Wraps
a `sklearn.linear_model.LogisticRegression` over the `_embed` features.
`RANKER_ID = "R2"` identifies this ranker's fit/score contract to a
persisted calibration (see `research/artifacts.py`), so a stale
`calibration.json` calibrated for a different ranker contract is rejected
rather than silently paired with the wrong model. (`__init__` is a plain
attribute assignment — `random_seed` and an unset `_model` — and isn't
documented separately.)

#### `ranker.r2_embedding_lr.R2Ranker.fit(train_df, labels) -> R2Ranker`
**Does:** Embeds `train_df["code"]`, fits a `LogisticRegression` (max_iter
1000, seeded from `self._random_seed`) against the aligned labels, and
returns `self` for chaining.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`, on the
`train` split, once per calibration run. Calls `_embed`,
`sklearn.linear_model.LogisticRegression.fit`.
**Tech:** `sklearn.linear_model.LogisticRegression`.
**Fits in:** OFFLINE — the "train ranker" stage.

#### `ranker.r2_embedding_lr.R2Ranker.score(df) -> pd.DataFrame`
**Does:** Embeds `df["code"]` and returns a `scores`-schema DataFrame
(`sample_id`, `ranker_id="R2"`, `score`), where `score` is
`predict_proba[:, 0]` — the model's probability of the *safe* class,
oriented so higher score means safer. Raises `RuntimeError` if called
before `fit`.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` (scoring
the whole merged corpus after training) and by
`scan/pipeline.py::_rank_and_gate` (scoring every ingested `Unit` at scan
time — the same method, same model, used both to build the calibration
data and to rank live scan targets). Calls `_embed`,
`LogisticRegression.predict_proba`.
**Tech:** `sklearn.linear_model.LogisticRegression`, `pandas`.
**Fits in:** OFFLINE (scoring the calibration set) and ONLINE (the "rank"
stage of every scan) — the one ranker method called from both halves of
the system.

---

## research/

The OFFLINE pipeline itself: prompt bank loading, code generation
(simulated + real backends), the orchestration function that runs
generation through calibration end-to-end, artifact persistence, and the
evaluation/plotting subpackage.

### research/pipeline.py

#### `research.pipeline.extract_code(raw: str) -> str`
**Does:** Pulls the actual function implementation out of a real LLM's
delimiter-wrapped completion. Tries three delimiter styles in order
(markdown fences ```` ```python ... ``` ````, `[PYTHON]...[/PYTHON]` tags,
`<pre>...</pre>` tags) and returns the *first* matched block that actually
contains a `def` — not just the first block found, because some models
(codellama, observed in the real corpus) emit a second block that's a
usage example rather than the implementation, and picking the wrong one
would hand the oracle a function call instead of a function definition.
Falls back to `raw` unchanged if no delimited block contains a `def`,
which covers both a model that emits bare unwrapped code (starcoder2) and
one that emits no usable code at all (a genuine non-answer that should
abstain downstream rather than be forced into a false extraction). The
module-level comment records the empirical motivation: 40.7% oracle
abstention on the real 516-sample corpus before this existed, because
`ast.parse` on raw prose-wrapped text raised `SyntaxError` and the dynamic
oracles fell back to names real models essentially never use.
**Talks to:** Called by `run_full_pipeline`, unconditionally (not
branched on `is_simulated` — it's a no-op on `SimulatedBackend`'s already
clean output, so one code path serves both). Calls nothing else — pure
regex.
**Tech:** `re`.
**Fits in:** OFFLINE — a generation-output cleanup step, between raw
generation and oracle labeling.

#### `research.pipeline._first_function_name(code: str) -> str | None`
**Does:** Returns the name of the first top-level function defined in
`code`, or `None` on a syntax error or if there is none. Used to build a
realistic candidate function name for a real model's output, since real
models don't reliably use `SimulatedBackend`'s four template names
(`handler`, `process`, `run_task`, `do_work`).
**Talks to:** Called only by `label_row` in this same module. Calls
`ast.parse`, `ast.walk`.
**Tech:** `ast`.
**Fits in:** OFFLINE — a labeling-time helper.

#### `research.pipeline.label_row(row: pd.Series, use_semgrep_and_adjudicator: bool = False) -> dict`
**Does:** Runs the appropriate oracle(s) for one generated snippet and
applies the consensus rule, returning one `labeled`-schema row. Builds a
candidate function-name list (the real first-defined function name,
if found, tried first, then the four simulated-template names as
fallback) and tries each against the dynamic oracle for CWE-89/CWE-78
until one returns a non-`None` verdict; for CWE-798 runs the static
`check_creds` oracle directly. When `use_semgrep_and_adjudicator=True`
(real runs), also runs semgrep for the consensus signal (the adjudicator
verdict itself is left `False` — a Gemini-based adjudicator call was never
wired in, per the code comment). Returns `LABEL_ABSTAIN` (`-1`) when no
oracle reached a verdict at all — the docstring is explicit this must
never be silently treated as safe, since that's exactly what hid a real
bug where 540/540 CWE-89 samples abstained (wrong table names) and were
all mislabeled safe before this distinction existed.
**Talks to:** Called by `run_full_pipeline` (once per generated row) and
directly by `tests/test_oracle_robustness.py`. Calls
`_first_function_name`, `oracles/sqli_oracle.py::check_sqli`,
`oracles/cmdi_oracle.py::check_cmdi`, `oracles/creds_oracle.py::check_creds`,
`oracles/semgrep_oracle.py::run_semgrep` (conditionally), and
`oracles/consensus.py::consensus_label`.
**Tech:** none directly beyond stdlib; delegates all real work to the
oracle modules above.
**Fits in:** OFFLINE — the "oracles label each sample" stage, applied
per-row.

#### `research.pipeline.run_full_pipeline(cfg, prompts, backends, is_simulated, out_dir, use_semgrep_and_adjudicator=False, checkpoint_path=None, pregenerated_df=None) -> dict`
**Does:** The full OFFLINE orchestration: generate (or accept
`pregenerated_df` and skip generation entirely) -> validate schema ->
`extract_code` -> write `generations.parquet` -> `label_row` every row ->
write `labeled.parquet` -> drop abstentions, warn if abstention rate
exceeds 20% -> fit `R2Ranker` on the train split, score everyone -> write
`scores_r2.parquet` -> compute the cost-coverage frontier across a set of
alphas (`compute_frontier`) bracketing the configured alpha -> plot it ->
run `calibrate_threshold` at the configured operating point, persist its
trace to `ltt_trace.csv` -> save the model and calibration together
(`save_model`, `save_calibration`) tagged with `corpus_version` and
`is_provisional` (provisional iff `is_simulated`) -> run a per-generator
holdout shift experiment (`run_shift_experiment`) for every generator with
at least 2 generators and >0 vulnerable calibration samples -> plot and
persist shift results. Returns a summary dict (`n_generated`, `vuln_rate`,
`n_abstain`, `n_vuln_calib`, `t_hat`, `coverage`, `corpus_version`,
`is_provisional`, `n_shift_experiments`). Writes placeholder plots instead
of real ones when there's insufficient data (zero vulnerable calibration
samples, or fewer than 2 generators) rather than crashing.
**Talks to:** Called by `cli.py::calibrate` and every pipeline-running
script (`scripts/run_real.py::main`, `scripts/run_pipeline_dry_run.py::main`,
`scripts/train_from_pregenerated.py::main`) — the single shared
orchestration function all four never drift apart from. Calls
`research/generation/harness.py::run_generation`, `schemas.py::validate_dataframe`,
`extract_code`, `label_row`, `ranker/r2_embedding_lr.py::R2Ranker`,
`research/eval/frontier.py::compute_frontier`, `gate/ltt.py::calibrate_threshold`,
`research/artifacts.py::save_model`/`save_calibration`,
`research/eval/shift.py::run_shift_experiment`,
`research/eval/plots.py::plot_frontier`/`plot_shift_results`,
`_write_placeholder_plot`.
**Tech:** `pandas`, `numpy`.
**Fits in:** OFFLINE — this function *is* the research pipeline, spanning
generation through calibration.

#### `research.pipeline._write_placeholder_plot(path: Path, message: str) -> None`
**Does:** Writes a PNG containing just centered text — used when a real
plot can't be produced (e.g. zero vulnerable calibration samples), so
downstream tooling that expects a PNG at that path always finds one.
**Talks to:** Called only by `run_full_pipeline`, in its two
insufficient-data fallback branches. Calls `matplotlib.pyplot`.
**Tech:** `matplotlib` (`Agg` backend, headless).
**Fits in:** OFFLINE — a graceful-degradation helper for the frontier/shift
plotting steps.

### research/artifacts.py

#### `research.artifacts.save_model(ranker: R2Ranker, path: Path) -> None`
**Does:** Serializes a fitted `R2Ranker` to `path` via `joblib`, creating
parent directories as needed.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`, once
per successful calibration run. Calls `joblib.dump`.
**Tech:** `joblib`.
**Fits in:** OFFLINE — persists the trained model as
`data/model/model.joblib`.

#### `research.artifacts.load_model(path: Path) -> R2Ranker`
**Does:** Loads a serialized ranker from `path`, raising `FileNotFoundError`
with an actionable message ("Run `codegate calibrate` first") if it
doesn't exist, or `TypeError` if the deserialized object isn't an
`R2Ranker`.
**Talks to:** Called only by `load_artifacts` in this same module. Calls
`joblib.load`.
**Tech:** `joblib`.
**Fits in:** Shared — the model side of the artifact pair the ONLINE
scanner reads at the start of every scan.

#### `research.artifacts.save_calibration(result, path, corpus_version, is_provisional, ranker_id=R2Ranker.RANKER_ID) -> None`
**Does:** Builds a `Calibration` record from an `LTTResult` plus
provenance fields (corpus version, provisional flag, ranker id, a fresh
UTC timestamp) and writes it to `path` as indented JSON.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`. Calls
nothing else beyond `json.dumps` and `dataclasses.asdict`.
**Tech:** `json`, `datetime` (`timezone.utc`).
**Fits in:** OFFLINE — persists the certificate as
`data/model/calibration.json`.

#### `research.artifacts.load_calibration(path: Path) -> Calibration`
**Does:** Loads and reconstructs a `Calibration` from JSON at `path`,
raising `FileNotFoundError` with an actionable message if missing.
**Talks to:** Called by `load_artifacts` (this module) and directly by
`scripts/run_eval.py::main` (to read `alpha`/`t_hat` for the LTT-trace
plot). Calls `json.loads`.
**Tech:** `json`.
**Fits in:** Shared — the calibration side of the artifact pair.

#### `research.artifacts.load_artifacts(model_path: Path, calibration_path: Path) -> tuple[R2Ranker, Calibration]`
**Does:** Loads the model and its calibration together and refuses the
pair (`ArtifactVersionError`) if `calibration.ranker_id` doesn't match the
loaded ranker's `RANKER_ID` — preventing a stale calibration from being
silently paired with an incompatible model. This is the function to use
anywhere both artifacts are needed together; `load_model`/`load_calibration`
individually skip this check.
**Talks to:** Called by `cli.py::info` and `scan/pipeline.py::_rank_and_gate`
— every real consumer of "the currently installed model + certificate"
goes through this function, not the individual loaders. Calls
`load_model`, `load_calibration`.
**Tech:** none beyond what `load_model`/`load_calibration` use.
**Fits in:** Shared boundary function — this is literally where the
OFFLINE-produced artifacts hand off to the ONLINE scanner.

### research/corpus/prompts.py

#### `research.corpus.prompts.load_prompt_bank(prompts_dir: str) -> list[Prompt]`
**Does:** Reads every `*.yaml` file in `prompts_dir`, and for each task
group within each file, expands it into three `Prompt` records — one per
flavor (`vulnerable`, `neutral`, `near_miss`) — with a deterministic
`prompt_id` of the form `{cwe}-{task_num}-{flavor}`. Raises
`FileNotFoundError` if the directory doesn't exist.
**Talks to:** Called by `cli.py::calibrate`,
`scripts/run_real.py::main`, `scripts/run_pipeline_dry_run.py::main`
(`train_from_pregenerated.py` skips this, passing `prompts=[]` since
generation is bypassed). Calls `yaml.safe_load`.
**Tech:** `yaml` (PyYAML), `pathlib.Path`.
**Fits in:** OFFLINE — the very first stage, "prompts."

### research/generation/backends.py

#### `research.generation.backends.stable_seed(*parts: object) -> int`
**Does:** Derives a deterministic integer seed from arbitrary parts by
joining them with `|` and taking the first 8 hex digits of their SHA-256
digest. Exists specifically because Python's builtin `hash()` randomizes
string hashes per-process (`PYTHONHASHSEED`) and is unsafe for
reproducible seeding across separate runs.
**Talks to:** Called by `cli.py::calibrate` and
`scripts/run_pipeline_dry_run.py::main` (seeding each `SimulatedBackend`),
by `SimulatedBackend._stable_seed` (this module) and
`research/generation/harness.py::run_generation`/`_sample_id` (deriving
per-sample seeds and ids). Calls `hashlib.sha256`.
**Tech:** `hashlib`.
**Fits in:** OFFLINE — reproducibility plumbing used throughout
generation.

**`class research.generation.backends.Backend`** (ABC) — the interface
every code-generation backend implements: `name: str` plus one abstract
method.

#### `research.generation.backends.Backend.generate(self, prompt: Prompt, seed: int) -> str`
**Does:** Abstract contract: given a `Prompt` and a seed, return generated
Python source as a string. Not implemented here — every concrete subclass
below overrides it.
**Talks to:** The contract point `research/generation/harness.py::run_generation`
calls polymorphically on whatever backend it was given. Raises
`NotImplementedError` if reached directly.
**Tech:** `abc.abstractmethod`.
**Fits in:** OFFLINE — the generation-stage interface.

**`class research.generation.backends.SimulatedBackend`** — deterministic,
offline, no-network generator. Draws from hand-written templates keyed by
`(cwe, flavor)` in `_SIM_TEMPLATES`, with light randomized
variable/function naming so outputs aren't byte-identical across samples.
Used to exercise the full pipeline before real LLM backends were wired in,
and still the default for `codegate calibrate` without `--real`.
(`__init__` just stores `name`/`seed` — not documented separately.)

#### `research.generation.backends.SimulatedBackend.generate(self, prompt, seed) -> str`
**Does:** Picks the template list for `(prompt.cwe, prompt.flavor)`
(falling back to a generic identity function if the pair is unrecognized),
seeds a local `random.Random` from `_stable_seed`, and formats the chosen
template with randomly-picked function/argument names.
**Talks to:** Called polymorphically by
`research/generation/harness.py::run_generation`. Calls `_stable_seed`,
`random.Random.choice`.
**Tech:** `random`.
**Fits in:** OFFLINE — the simulated generator implementation.

#### `research.generation.backends.SimulatedBackend._stable_seed(self, prompt_id, seed) -> int`
**Does:** Combines the backend's own name and instance seed with the
per-call `prompt_id`/`seed` into one deterministic seed for this specific
generation call.
**Talks to:** Called only by `SimulatedBackend.generate`. Calls
`stable_seed` (module-level function).
**Tech:** none beyond `stable_seed`'s own (`hashlib`).
**Fits in:** OFFLINE.

**`class research.generation.backends.OllamaBackend`** — real backend:
local Ollama server (`/api/generate`). Requires Ollama running. (`__init__`
stores `name`/`model`/`base_url`, not documented separately.)

#### `research.generation.backends.OllamaBackend.generate(self, prompt, seed) -> str`
**Does:** POSTs `prompt.task` to `{base_url}/api/generate` with
`stream=False` and the given seed, raises on a non-2xx response, and
returns `response["response"]`.
**Talks to:** Called polymorphically by
`research/generation/harness.py::run_generation` whenever the caller built
`OllamaBackend` instances (`cli.py::calibrate --real`,
`scripts/run_real.py::build_backends`). Calls `requests.post`.
**Tech:** `requests`.
**Fits in:** OFFLINE — the real generation backend used for producing the
actual research corpus (`scripts/run_real.py`).

**`class research.generation.backends.OpenRouterBackend`** — real backend:
OpenRouter free-tier models via their OpenAI-compatible chat completions
endpoint. Requires an API key. (`__init__` stores `name`/`model`/`api_key`.)

#### `research.generation.backends.OpenRouterBackend.generate(self, prompt, seed) -> str`
**Does:** POSTs a chat-completions request to
`https://openrouter.ai/api/v1/chat/completions` with a single user message
and the given seed, and returns the first choice's message content.
**Talks to:** Not currently instantiated anywhere in `src/codegate` or
`scripts/` — `config.yaml`'s generators today are all Ollama models, so
this backend exists as an available option but has no current production
caller. Calls `requests.post`.
**Tech:** `requests`.
**Fits in:** OFFLINE — an alternative real generation backend, unused by
the current configuration.

**`class research.generation.backends.GeminiBackend`** — real backend:
Google Gemini free tier, intended specifically as the label adjudicator
(never a code generator, so it never adjudicates its own output — see
`config.py::load_config`'s role-reuse validation). Requires an API key.
(`__init__` stores `name`/`model`/`api_key`.)

#### `research.generation.backends.GeminiBackend.generate(self, prompt, seed) -> str`
**Does:** POSTs to
`https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
with `prompt.task` as the content and the seed set in `generationConfig`,
returning the first candidate's text.
**Talks to:** Not currently instantiated anywhere in `src/codegate` or
`scripts/` — `research/pipeline.py::label_row`'s `adjudicator_verdict` is
hardcoded `False` because this call was never wired in (per the code
comment). No production caller today.
**Tech:** `requests`.
**Fits in:** OFFLINE — reserved for the not-yet-wired-in adjudicator role.

**`class research.generation.backends.GroqBackend`** — real backend: Groq
free-tier inference via their OpenAI-compatible chat completions endpoint.
Requires an API key. (`__init__` stores `name`/`model`/`api_key`. Distinct
from `scan/verifier.py::GroqVerifierBackend`, which implements a different
interface — `ask(code) -> str` for verification, not `generate(Prompt,
seed) -> str` for corpus generation.)

#### `research.generation.backends.GroqBackend.generate(self, prompt, seed) -> str`
**Does:** POSTs a chat-completions request to
`https://api.groq.com/openai/v1/chat/completions` with a single user
message and the seed, returning the first choice's message content.
**Talks to:** Not currently instantiated anywhere in `src/codegate` or
`scripts/` as a *generation* backend — `config.yaml`'s generators are
Ollama models. (Groq is used elsewhere, but only as the scan verifier via
the separate `GroqVerifierBackend` class in `scan/verifier.py`.)
**Tech:** `requests`.
**Fits in:** OFFLINE — an alternative real generation backend, unused by
the current configuration.

### research/generation/harness.py

#### `research.generation.harness._sample_id(prompt_id: str, generator_name: str, k: int) -> str`
**Does:** Builds a deterministic id (`{stable_seed(...):08x}-{k}`) for one
`(prompt, generator, replicate)` triple. Must be stable across process
runs — resume works by checking which sample ids are already on disk in
the checkpoint, so a random id (the code comment notes this used to be
`uuid4`) would make every resumed run regenerate everything.
**Talks to:** Called only by `run_generation` in this same module. Calls
`research/generation/backends.py::stable_seed`.
**Tech:** none beyond `stable_seed`'s own.
**Fits in:** OFFLINE — generation-stage id assignment, load-bearing for
resumability.

#### `research.generation.harness._load_checkpoint(checkpoint_path: Path) -> dict[str, dict]`
**Does:** Reads a JSONL checkpoint file into a `{sample_id: record}` dict,
skipping any line that fails to parse as JSON (a half-written final line
from an interrupted run — that sample simply regenerates).
**Talks to:** Called only by `run_generation`. Calls `json.loads`.
**Tech:** `json`, `pathlib.Path`.
**Fits in:** OFFLINE — resume support for multi-hour generation runs.

#### `research.generation.harness.run_generation(prompts, backends, samples_per_prompt, is_simulated, checkpoint_path=None, on_progress=None) -> pd.DataFrame`
**Does:** Generates code for every `(prompt x generator x replicate)`
combination. If `checkpoint_path` is given, appends each successful
sample to a JSONL file as it's produced and skips regenerating anything
already present there — making a multi-hour Ollama run survive a dropped
connection or Ctrl-C. A generation call that raises is logged to stderr
and skipped rather than aborting the whole run (so one bad sample out of
hundreds doesn't cost all the others); skipped samples are absent from the
checkpoint and retried on the next resume. Returns a `generations`-schema
DataFrame.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` (unless
`pregenerated_df` was supplied, bypassing this entirely) and directly by
`scripts/run_real.py::main` in its `--generate-only` mode. Calls
`_load_checkpoint`, `_sample_id`,
`research/generation/backends.py::stable_seed`, and each backend's
`.generate(...)`.
**Tech:** `pandas`, `json`, `sys` (for stderr warnings).
**Fits in:** OFFLINE — the "LLM generation -> code samples" stage.

### research/eval/frontier.py

#### `research.eval.frontier.compute_frontier(scores, labels, alphas: list[float], delta: float) -> pd.DataFrame`
**Does:** For each candidate alpha, certifies an LTT threshold and records
the coverage it buys, producing the headline cost-coverage curve — the
fraction of traffic that never needs an LLM call, as a function of the
certified miss-rate.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`, swept
across alphas that bracket the configured operating point. Calls
`gate/ltt.py::calibrate_threshold`.
**Tech:** `pandas`, `numpy`.
**Fits in:** OFFLINE — produces `frontier.csv`/`frontier.png`.

### research/eval/metrics.py

#### `research.eval.metrics.oracle_accuracy_on_fixtures(fixtures_dir) -> pd.DataFrame`
**Does:** Runs each ground-truth oracle (dynamic sqli/cmdi, static creds)
and semgrep against the six hand-labeled fixtures in `data/fixtures/`
(one vulnerable/safe pair per tracked CWE), returning a per-fixture
correctness table. Deliberately small (n=2 per CWE) — this checks "does
the oracle still agree with its own textbook example," not statistical
accuracy at scale (which lives in `tests/test_oracle_robustness.py`).
**Talks to:** Called by `scripts/run_eval.py::main`. Calls
`oracles/sqli_oracle.py::check_sqli`, `oracles/cmdi_oracle.py::check_cmdi`,
`oracles/creds_oracle.py::check_creds`, `oracles/semgrep_oracle.py::run_semgrep`.
**Tech:** `pandas`, `pathlib.Path`.
**Fits in:** OFFLINE (eval) — real, unchanging ground truth, unlike every
other metric in this module (which is trained/evaluated on the still-
provisional simulated corpus).

#### `research.eval.metrics.corpus_label_distribution(labeled_df: pd.DataFrame) -> pd.DataFrame`
**Does:** Counts samples by `(cwe, outcome)` where outcome is
`"vulnerable"`, `"safe"`, or `"abstained"` — the shape any labeled corpus
produced by `research/pipeline.py::label_row` has, simulated or real.
**Talks to:** Called by `scripts/run_eval.py::main` (on
`data/model/labeled.parquet`). Calls nothing else — pandas groupby.
**Tech:** `pandas`.
**Fits in:** OFFLINE (eval).

#### `research.eval.metrics.ranker_score_frame(labeled_df, scores_df) -> pd.DataFrame`
**Does:** Joins a labeled corpus with a ranker's per-sample scores on
`sample_id`, dropping abstentions (they were excluded from training and
calibration upstream, so they shouldn't count as "safe" here either).
**Talks to:** Called by `scripts/run_eval.py::main`. Calls nothing else —
a pandas merge.
**Tech:** `pandas`.
**Fits in:** OFFLINE (eval).

#### `research.eval.metrics.ranker_separation_metrics(score_frame: pd.DataFrame) -> dict`
**Does:** Computes ROC-AUC (against `1 - label`, since higher score means
safer/class-0) plus mean score per class. The docstring carries an
explicit caution: as currently fed (`labeled.parquet` + `scores_r2.parquet`
directly, with no train/test split threaded through those files), this
scores the ranker partly against samples it was trained on — on the small
templated simulated corpus this reads as a suspiciously perfect AUC=1.0,
a memorization signal rather than a generalization one, and is flagged
as not to be quoted as "the ranker's accuracy" without that caveat.
**Talks to:** Called by `scripts/run_eval.py::main`. Calls
`sklearn.metrics.roc_auc_score`.
**Tech:** `sklearn.metrics.roc_auc_score`.
**Fits in:** OFFLINE (eval).

#### `research.eval.metrics.scan_ground_truth_eval(scan_result: ScanResult, ground_truth: dict[tuple[str, str], bool]) -> dict`
**Does:** Computes precision/recall/F1/accuracy of a scan's findings (any
source — semgrep, model, verifier) against a hand-labeled
`{(filename, func_name): is_vulnerable}` ground truth, where
`func_name="<module>"` matches a module-level finding the same way
`scan/pipeline.py::_semgrep_findings` itself falls back to it. The one
metric in this module evaluating the deployed pipeline end-to-end rather
than one component in isolation, and the one whose ground truth is
entirely real today (not waiting on a real corpus at all).
**Talks to:** Called by `scripts/run_eval.py::main`, against
`examples/vulnerable_app/`. Calls nothing else beyond dict/set operations.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE-facing eval — measures the scanner end to end, though
the function itself lives in the OFFLINE eval subpackage.

### research/eval/plots.py

All seven functions below share the same shape: build a matplotlib
figure, save it as a PNG, close it. All use the `Agg` backend (set once at
module import) since these run headless.

#### `research.eval.plots.plot_frontier(frontier_df, out_path) -> None`
**Does:** Line plot of coverage vs. alpha — the cost-coverage frontier.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE.

#### `research.eval.plots.plot_shift_results(results: list, out_path) -> None`
**Does:** Bar chart of realized risk per held-out generator, colored green
if the certificate held and red if not, with the certified alpha as a
reference line.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE.

#### `research.eval.plots.plot_oracle_accuracy(accuracy_df, out_path) -> None`
**Does:** One bar per fixture, green if the oracle's verdict matched
ground truth, red if not.
**Talks to:** Called by `scripts/run_eval.py::main`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE (eval).

#### `research.eval.plots.plot_corpus_label_distribution(dist_df, out_path) -> None`
**Does:** Stacked bar chart of vulnerable/safe/abstained counts per CWE.
**Talks to:** Called by `scripts/run_eval.py::main`.
**Tech:** `matplotlib.pyplot`, `pandas` (`.pivot`).
**Fits in:** OFFLINE (eval).

#### `research.eval.plots.plot_score_distribution_by_label(score_frame, out_path) -> None`
**Does:** Overlapping histograms of ranker score, vulnerable vs. safe —
visualizes how well-separated the two classes are.
**Talks to:** Called by `scripts/run_eval.py::main`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE (eval).

#### `research.eval.plots.plot_ltt_trace(trace_df, alpha, t_hat, out_path) -> None`
**Does:** Plots the LTT threshold search itself — p-value at every
candidate threshold, the certified alpha line, and the winning t_hat
marked.
**Talks to:** Called by `scripts/run_eval.py::main`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE (eval).

#### `research.eval.plots.plot_scan_ground_truth(eval_dict, out_path) -> None`
**Does:** Confusion-matrix-style bar chart (TP/FP/TN/FN) for a
`scan_ground_truth_eval` result, with precision/recall/F1 in the title.
**Talks to:** Called by `scripts/run_eval.py::main`.
**Tech:** `matplotlib.pyplot`.
**Fits in:** OFFLINE (eval), evaluating the ONLINE scanner's output.

### research/eval/shift.py

#### `research.eval.shift.run_shift_experiment(scores_by_generator, labels_by_generator, held_out, alpha, delta) -> ShiftResult`
**Does:** The headline "does the certificate survive a generator switch"
experiment. Calibrates an LTT threshold on every generator *except*
`held_out`, pooled together, then measures the realized empirical risk on
`held_out`'s own data at that threshold. `certificate_held` is `True` iff
the realized risk stayed `<= alpha`. Raises `ValueError` if there's no
non-held-out generator to calibrate on. Returns `certificate_held=False`
(with `t_hat=None`, risk `nan`) if no threshold could even be certified on
the calibration generators.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`, once
per generator (each held out in turn), when there are >=2 generators and
>0 vulnerable calibration samples. Calls `gate/ltt.py::calibrate_threshold`,
`gate/risk.py::empirical_risk`.
**Tech:** `numpy`.
**Fits in:** OFFLINE — the robustness experiment behind
`shift_results.csv`/`shift_results.png`.

---

## scan/

The ONLINE scanner: turning a target path into function-level `Unit`s
(`ingest.py`), running static semgrep + ranking + gating + LLM
verification over them (`pipeline.py`), the `Finding` data shape
(`findings.py`), and the Groq-backed verifier with its content-hash cache
(`verifier.py`).

### scan/ingest.py

#### `scan.ingest._load_gitignore_patterns(root: Path) -> list[str]`
**Does:** Reads simple patterns from `root/.gitignore` — plain names,
directory patterns (trailing `/` stripped), glob wildcards — skipping
blank lines, comments, and negation patterns (`!pattern`, not supported;
a full gitignore parser is explicitly out of scope). Returns `[]` if no
`.gitignore` exists.
**Talks to:** Called only by `_ingest_directory` in this same module.
Calls nothing else — plain file reading.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE — ingest-stage filtering.

#### `scan.ingest._is_ignored(rel_path: Path, patterns: list[str]) -> bool`
**Does:** Checks whether `rel_path` matches any gitignore-style pattern,
either as a whole-path match or a match against any individual path
component.
**Talks to:** Called only by `_ingest_directory`. Calls `fnmatch.fnmatch`.
**Tech:** `fnmatch`.
**Fits in:** ONLINE — ingest-stage filtering.

#### `scan.ingest._estimate_tokens(source: str) -> int`
**Does:** A documented `chars/4` heuristic token-count estimate (minimum
1), used consistently on both sides of the later cost-savings calculation
rather than an exact tokenizer — `tiktoken` is deliberately not a
dependency.
**Talks to:** Called only by `_ingest_files`, once per unit. The resulting
`Unit.token_estimate` is later read by `scan/pipeline.py::_rank_and_gate`/
`_resolve_escalated` and `report/accounting.py::compute_cost_summary`.
**Tech:** none beyond `len()`.
**Fits in:** ONLINE — feeds Phase 7's token/cost accounting.

#### `scan.ingest._ingest_files(paths: list[Path]) -> IngestResult`
**Does:** For each path: reads the file (recording a `SkippedFile` on a
decode/OS error), parses it with `ast.parse` (recording a `SkippedFile` on
`SyntaxError`), then walks the AST for every `FunctionDef`/`AsyncFunctionDef`
node and builds a `Unit` from its source segment (line range, name,
content hash, token estimate). Skips a node if
`ast.get_source_segment` can't recover its source text. Files disappearing
from a scan silently is deliberately avoided — every skip is recorded with
a reason, not dropped.
**Talks to:** Called by `_ingest_directory` and `ingest_path` (for a
single file). Calls `ast.parse`, `ast.walk`, `ast.get_source_segment`,
`_estimate_tokens`, `hashlib.sha256`.
**Tech:** `ast`, `hashlib`.
**Fits in:** ONLINE — the core of the ingest stage: file/directory to
function-level `Unit`s.

#### `scan.ingest._ingest_directory(root: Path) -> IngestResult`
**Does:** Walks `root` for `*.py` files (via `rglob`), skipping any file
under a hardcoded set of directory names (`venv`, `.venv`,
`site-packages`, `.git`, `__pycache__` — skipped unconditionally,
regardless of `.gitignore` content) and any file matched by
`.gitignore` patterns, then delegates the rest to `_ingest_files`.
**Talks to:** Called only by `ingest_path`, for a directory target. Calls
`_load_gitignore_patterns`, `_is_ignored`, `_ingest_files`.
**Tech:** `pathlib.Path` (`rglob`).
**Fits in:** ONLINE — directory-walk stage of ingest.

#### `scan.ingest.ingest_path(path: Path) -> IngestResult`
**Does:** The public entry point: ingests a single file (always, ignoring
`.gitignore`/skip-dir rules — those only apply when walking a directory
the caller didn't individually name) or a directory (via
`_ingest_directory`). Raises `FileNotFoundError` if `path` doesn't exist.
**Talks to:** Called by `scan/pipeline.py::run_scan`, as the very first
step of every scan. Calls `_ingest_files`, `_ingest_directory`.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE — "ingest" in the architecture diagram.

*(`Unit`, `SkippedFile`, and `IngestResult` are frozen dataclasses with no
methods of their own.)*

### scan/pipeline.py

#### `scan.pipeline._base_rule_id(rule_id: str) -> str`
**Does:** Recovers a semgrep rule id as written in `codegate_rules.yaml`
from the path-derived namespace prefix semgrep adds when loading a local
ruleset file (e.g. `data.semgrep_rules.codegate-sqli-string-build` ->
`codegate-sqli-string-build`). Works because this project's own rule ids
use hyphens, never dots, so the segment after the last `.` is always the
real id regardless of the caller's working directory.
**Talks to:** Called only by `_semgrep_findings`. Calls nothing else — a
string split.
**Tech:** none.
**Fits in:** ONLINE — static-pre-pass result normalization.

#### `scan.pipeline._map_to_unit(units: list[Unit], file: Path, line: int) -> Unit | None`
**Does:** Finds which ingested `Unit` a `(file, line)` finding belongs to
— the unit whose file matches (resolved to an absolute path) and whose
line range contains `line`. When multiple units overlap (a nested
function inside its enclosing function), picks the one with the smallest
line range as the more specific match. Returns `None` if no unit matches
(a module-level finding).
**Talks to:** Called only by `_semgrep_findings`. Calls nothing else.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE — maps raw semgrep line numbers back to scored units.

#### `scan.pipeline._semgrep_findings(target: Path, units: list[Unit]) -> list[Finding]`
**Does:** Runs semgrep once over the whole scan target and converts each
raw finding into a `Finding`, mapping the semgrep rule id to a tracked
CWE via `_RULE_ID_TO_CWE` (an unrecognized rule id is dropped — treated as
ruleset/pipeline drift, not a scan-target problem, mirroring
`oracles/consensus.py`'s unrecognized-CWE guard) and resolving `func_name`
via `_map_to_unit` (falling back to `"<module>"` for a finding with no
enclosing unit). `source="semgrep"`, `confidence=1.0` (deterministic
pattern match), `fix_hint` from the short built-in hint table.
**Talks to:** Called only by `run_scan`. Calls
`oracles/semgrep_oracle.py::run_semgrep_on_path`, `_base_rule_id`,
`_map_to_unit`, constructs `scan/findings.py::Finding`.
**Tech:** none beyond what its callees use.
**Fits in:** ONLINE — the "static pre-pass" stage of the architecture
diagram.

#### `scan.pipeline._rank_and_gate(units: list[Unit], model_dir: Path) -> tuple[list[tuple[Unit, float]], int, int, Calibration | None]`
**Does:** Loads the model+calibration pair, scores every unit, and
applies the LTT gate (`score >= t_hat` -> auto-approve). Returns the
escalated units paired with their score, the auto-approved count, the
summed `token_estimate` of the auto-approved units (zero LLM tokens were
needed for those under the certificate — the accounting baseline), and the
loaded `Calibration` itself (so the report can show the certificate the
scan actually ran under). Returns `([], 0, 0, None)` immediately if there
are no units at all (nothing to score, so nothing is loaded — no
artifact-missing error on an empty scan). `calib.t_hat is None` means
everything escalates, per `gate/ltt.py::LTTResult`'s own documented
semantics.
**Talks to:** Called only by `run_scan`. Calls
`research/artifacts.py::load_artifacts`, `ranker/r2_embedding_lr.py::R2Ranker.score`.
**Tech:** `pandas`.
**Fits in:** ONLINE — the "rank" and "gate" stages combined into one
function.

#### `scan.pipeline._needs_review_finding(unit: Unit, score: float) -> Finding`
**Does:** Builds the `Finding` for an escalated unit that either had no
verifier backend to ask, or that the verifier couldn't resolve.
`source="model"` (the model's gate decision is why this is reported, not
any LLM verdict), `severity="REVIEW"`, `confidence=round(1.0 - score, 4)`.
**Talks to:** Called by `_resolve_escalated`, in both its no-verifier and
unresolved-verdict branches. Calls `scan/findings.py::Finding`.
**Tech:** none.
**Fits in:** ONLINE — the "needs review" fallback finding shape.

#### `scan.pipeline._resolve_escalated(escalated, verifier, cache_dir) -> _VerificationTally`
**Does:** Attempts to resolve every escalated unit with the verifier. A
cleared unit (verifier says not vulnerable) produces no finding at all —
same convention as an auto-approved one. `verifier=None` resolves nothing:
every escalated unit becomes a `_needs_review_finding` and every
count/token field stays 0 — identical to the scanner's behavior before
LLM verification existed. Tracks cache hits vs. fresh calls (via
`is_cached`, checked before calling `verify_unit`) and attributes
`tokens_saved`/`tokens_spent` accordingly — a cache miss counts as
"spent" regardless of whether the response ultimately parsed, since the
API call itself is what costs money.
**Talks to:** Called only by `run_scan`. Calls
`scan/verifier.py::is_cached`, `verify_unit`, `to_finding`,
`_needs_review_finding`.
**Tech:** none beyond its callees.
**Fits in:** ONLINE — the "verify" stage.

#### `scan.pipeline.run_scan(path, model_dir=DEFAULT_MODEL_DIR, verifier=None, cache_dir=DEFAULT_CACHE_DIR) -> ScanResult`
**Does:** The scanner's top-level orchestration: `ingest_path` -> one
semgrep pass over the whole target (`_semgrep_findings`) -> `_rank_and_gate`
-> `_resolve_escalated` -> merge and sort all findings by
`(file, line)`. Assembles the full `ScanResult`, including the token
savings (auto-approved units' tokens plus any cache-hit savings from
verification). The docstring states a hard invariant: no dynamic oracle
ever runs on this path — nothing in `scan/` imports `oracles/sandbox.py`,
`sqli_oracle.py`, or `cmdi_oracle.py`, because those detonate code
specifically for controlled research labeling, and executing arbitrary
scanned user code would be a fundamentally different (and unacceptable)
risk. `verifier=None` (the default, also what `--no-llm` or a missing
`GROQ_API_KEY` produce) skips LLM verification entirely.
**Talks to:** Called by `cli.py::scan` and directly by
`scripts/run_eval.py::main` (against `examples/vulnerable_app/`, with and
without a verifier). Calls `scan/ingest.py::ingest_path`,
`_semgrep_findings`, `_rank_and_gate`, `_resolve_escalated`.
**Tech:** none directly beyond its callees.
**Fits in:** ONLINE — this function *is* the scan pipeline end to end
(everything in the architecture diagram from "ingest" through "verify").

*(`ScanResult` and `_VerificationTally` are frozen dataclasses with no
methods of their own.)*

### scan/findings.py

#### `scan.findings.Finding.__post_init__(self) -> None`
**Does:** Validates that `source` is one of the three recognized values
(`"semgrep"`, `"model"`, `"verifier"`), raising `ValueError` immediately on
construction otherwise — a `Finding` can never exist in an invalid state,
which matters because `source` drives the report's detection-attribution
breakdown.
**Talks to:** Invoked automatically by the dataclass machinery on every
`Finding(...)` construction — in `scan/pipeline.py::_semgrep_findings`/
`_needs_review_finding`, `scan/verifier.py::to_finding`, and every report
module that constructs test fixtures. Calls nothing else.
**Tech:** none — a dataclass `__post_init__` hook.
**Fits in:** ONLINE — a correctness guard on the `Finding` data shape
shared by every report format.

### scan/verifier.py

**`class scan.verifier.VerifierBackend`** (Protocol) — the minimal
interface a verifier backend must implement: `ask(code: str) -> str`,
returning the raw LLM completion text for one code-review prompt. Distinct
from `research/generation/backends.py::Backend`'s `generate(Prompt, seed)`
contract deliberately — verification sends a code snippet and expects a
structured verdict back, not a generation task built from a `Prompt`
object.

**`class scan.verifier.GroqVerifierBackend`** — the real verifier
backend: Groq's OpenAI-compatible chat completions API, using the fixed
`_SYSTEM_PROMPT` that instructs the model to answer with only a JSON
verdict object. (`__init__` stores `api_key`/`model`, not documented
separately.)

#### `scan.verifier.GroqVerifierBackend.ask(self, code: str) -> str`
**Does:** POSTs `code` as the user message (with `_SYSTEM_PROMPT` as the
system message, `temperature=0`) to Groq's chat completions endpoint and
returns the raw completion text.
**Talks to:** Called by `verify_unit`, on any real (non-cached) escalated
unit. Calls `requests.post`.
**Tech:** `requests`.
**Fits in:** ONLINE — the actual network call behind the "verify" stage.

#### `scan.verifier.build_verifier_backend(model: str) -> VerifierBackend | None`
**Does:** Returns a ready `GroqVerifierBackend` if `GROQ_API_KEY` is set
(mapping a config-file role name like `"llama-3.3-70b-groq"` to the real
current Groq model id via `_GROQ_MODEL_IDS` — the module comment records
that the original model this role pointed to,
`llama-3.3-70b-versatile`, was removed from Groq's catalog and replaced
with `openai/gpt-oss-120b`), or `None` if no key is present. `None` is
explicitly not an error case — the scanner must degrade cleanly (static +
ranker + gate still produce a full report; escalated units just stay
unconfirmed) rather than refuse to run without a key.
**Talks to:** Called by `cli.py::scan` (unless `--no-llm`) and
`scripts/run_eval.py::main` (`--with-llm`). Calls `env.py::get_env`.
**Tech:** none beyond `get_env`.
**Fits in:** ONLINE — the verifier-backend factory, gating whether
verification runs at all.

#### `scan.verifier._parse_verdict(raw: str) -> VerifierResult | None`
**Does:** Extracts the first `{...}` JSON object from `raw` via regex,
parses and validates its shape (`vulnerable` must be a bool; `cwe` must be
one of the three tracked CWEs or else nulled to `None`; `line` must be an
int or else nulled). Returns `None` — never raises — on any parse or shape
failure, since a model that doesn't obey the requested format is exactly
as untrustworthy as one that answers incorrectly, and both must degrade to
"needs review" rather than crash the scan or pass through unvalidated
data.
**Talks to:** Called only by `verify_unit`. Calls `re.search`, `json.loads`.
**Tech:** `re`, `json`.
**Fits in:** ONLINE — response validation for the verify stage.

#### `scan.verifier._cache_path(cache_dir: Path, content_hash: str) -> Path`
**Does:** Returns `cache_dir / f"{content_hash}.json"` — the naming
convention every cache read/write in this module shares.
**Talks to:** Called by `_load_cached` and `_save_cache`. Calls nothing
else.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE — cache-path convention.

#### `scan.verifier._load_cached(cache_dir: Path, content_hash: str) -> VerifierResult | None`
**Does:** Reads and reconstructs a cached `VerifierResult`, returning
`None` (not raising) if the file doesn't exist, isn't valid JSON, or
doesn't match the `VerifierResult` shape (e.g. written by an older code
version) — a corrupted or stale cache entry falls through to a fresh
billed call rather than crashing.
**Talks to:** Called by `is_cached` and `verify_unit`. Calls `_cache_path`,
`json.loads`.
**Tech:** `json`.
**Fits in:** ONLINE — cache read path.

#### `scan.verifier.is_cached(content_hash: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> bool`
**Does:** Whether `verify_unit` would resolve this `content_hash` without
a fresh LLM call. Deliberately delegates to `_load_cached` rather than a
bare `Path.exists()` check — the docstring explains this matters because a
cache file can exist but fail to load, in which case `verify_unit` falls
through to a real billed call; `is_cached` must report the same outcome or
a caller counting hits vs. calls for cost accounting would misclassify a
paid call as a free hit.
**Talks to:** Called by `scan/pipeline.py::_resolve_escalated`, to count
cache hits vs. fresh calls for the token/cost savings estimate without
duplicating the cache's file-naming scheme. Calls `_load_cached`.
**Tech:** none beyond `_load_cached`'s.
**Fits in:** ONLINE — exposes cache state to the accounting layer.

#### `scan.verifier._save_cache(cache_dir: Path, content_hash: str, result: VerifierResult) -> None`
**Does:** Writes `result` as JSON to the cache path, creating `cache_dir`
if needed.
**Talks to:** Called only by `verify_unit`, after a successful fresh call.
Calls `_cache_path`, `dataclasses.asdict`, `json.dumps`.
**Tech:** `json`.
**Fits in:** ONLINE — cache write path.

#### `scan.verifier.verify_unit(unit: Unit, backend: VerifierBackend | None, cache_dir: Path = DEFAULT_CACHE_DIR) -> VerifierResult | None`
**Does:** Resolves one escalated unit with at most one LLM call, cached by
`unit.content_hash` so re-scanning unchanged code costs zero further
calls. Returns the cached result if present; if not and `backend is None`,
returns `None`; otherwise calls `backend.ask`, catching
`requests.RequestException`/`KeyError`/`IndexError`/`ValueError` and
returning `None` on any of them; parses the response via `_parse_verdict`
(also `None` on failure); saves and returns the result on success.
Callers must treat `None` as "needs review," never as "confirmed safe."
**Talks to:** Called only by `scan/pipeline.py::_resolve_escalated`. Calls
`_load_cached`, `backend.ask` (polymorphic), `_parse_verdict`,
`_save_cache`.
**Tech:** `requests` (exception types only, at this layer).
**Fits in:** ONLINE — the single-call, cached verification step per
escalated unit.

#### `scan.verifier.to_finding(unit: Unit, result: VerifierResult) -> Finding`
**Does:** Converts a confirmed-vulnerable `VerifierResult` into a
`source="verifier"` `Finding` (`severity="ERROR"`, `confidence=1.0`, line
from the verdict if given, else the unit's own line). Callers only invoke
this when `result.vulnerable` is `True` — a cleared unit produces no
finding at all, same as an auto-approved one.
**Talks to:** Called only by `scan/pipeline.py::_resolve_escalated`. Calls
`scan/findings.py::Finding`.
**Tech:** none.
**Fits in:** ONLINE — turns a confirmed LLM verdict into the shared
`Finding` shape.

---

## report/

Deterministic report rendering in four formats (PDF, JSON, SARIF,
terminal) plus the shared cost-accounting and hardcoded-remediation
lookups they all draw from. Every module here is explicit that no LLM
writes any report prose — all text is hand-written, all numbers trace back
to a `ScanResult`.

### report/pdf.py

#### `report.pdf._token_color(ttype) -> str | None`
**Does:** Looks up the hex color for a pygments token type from the
hand-picked `_TOKEN_COLORS` palette (keyword/builtin/string/number/comment/
operator), returning `None` for anything unmatched (rendered uncolored).
**Talks to:** Called only by `_highlight`. Calls nothing else.
**Tech:** `pygments.token`.
**Fits in:** ONLINE (report stage) — PDF code-excerpt syntax highlighting.

#### `report.pdf._highlight(code: str) -> str`
**Does:** Turns Python source into reportlab `Paragraph` markup (a
restricted XML subset — `<font>`, `<br/>`, no full HTML) with per-token
colors from pygments' lexer, preserving leading whitespace as non-breaking
spaces since `Paragraph` collapses runs of plain spaces.
**Talks to:** Called by `_findings_flowables`, for both the finding
excerpt and the before/after remediation snippets. Calls `pygments.lex`
(with `PythonLexer`), `_token_color`, `xml.sax.saxutils.escape`.
**Tech:** `pygments.lex`, `pygments.lexers.PythonLexer`,
`xml.sax.saxutils.escape`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._read_excerpt(file: Path, line: int, context: int = 3) -> tuple[str, int]`
**Does:** Returns the lines around `line` in `file` (`context` lines of
padding on each side) plus the first line number of the excerpt, or
`("", 0)` if the file can no longer be read — it may have moved or changed
between the scan and report generation.
**Talks to:** Called only by `_findings_flowables`. Calls `Path.read_text`.
**Tech:** `pathlib.Path`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._styles() -> dict[str, ParagraphStyle]`
**Does:** Builds the named `ParagraphStyle` set the rest of the module
renders with (Title/Heading1/Heading2/Body/Small/Banner/Code), extending
reportlab's sample stylesheet with a few custom ones (a yellow warning
`Banner` style, a monospace `Code` style).
**Talks to:** Called only by `generate_pdf`, once, and the resulting dict
threaded into every `_*_flowables` function. Calls
`reportlab.lib.styles.getSampleStyleSheet`.
**Tech:** `reportlab.lib.styles`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._cover_flowables(styles, result, target, verifier_model) -> list`
**Does:** Builds the cover page: title, target path, scan timestamp,
CodeGate version, ranker/corpus/verifier line (if a certificate exists), a
one-line finding/skip count, and — if the certificate is provisional — a
yellow warning banner, followed by a page break.
**Talks to:** Called only by `generate_pdf`. Calls reportlab flowable
constructors (`Paragraph`, `Spacer`, `PageBreak`).
**Tech:** `reportlab.platypus`, `datetime` (`timezone.utc`),
`xml.sax.saxutils.escape`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._attribution_flowables(styles, result, cost) -> list`
**Does:** Builds the "Detection Attribution" table — counts of findings by
source (semgrep, escalated, verifier-confirmed, needs-manual-review,
auto-approved) with a one-line explanation of what each row means.
**Talks to:** Called only by `generate_pdf`. Calls `_table_style`,
reportlab `Table`/`Paragraph`.
**Tech:** `reportlab.platypus.Table`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._table_style() -> TableStyle`
**Does:** Returns the one shared `TableStyle` (dark header row, white
header text, grid lines, alternating row backgrounds) every table in the
PDF uses.
**Talks to:** Called by `_attribution_flowables`, `_executive_summary_flowables`,
`_cost_flowables`, `_certificate_flowables`. Calls nothing else.
**Tech:** `reportlab.lib.colors`, `reportlab.platypus.TableStyle`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._executive_summary_flowables(styles, result, cost) -> list`
**Does:** Builds the "Executive Summary" section — a by-severity count
table, plus a sentence summarizing units scanned, auto-approved,
escalated, and how many of those went to the LLM verifier this run vs.
were resolved without one.
**Talks to:** Called only by `generate_pdf`. Calls `_table_style`.
**Tech:** `reportlab.platypus`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._cost_flowables(styles, cost) -> list`
**Does:** Builds the "Cost & Token Accounting" table (tokens
saved/spent, calls avoided/made, estimated cost, price used) plus a
methodology footnote disclosing the chars/4 token estimate and the
tokens-saved baseline definition.
**Talks to:** Called only by `generate_pdf`. Calls `_table_style`.
**Tech:** `reportlab.platypus`.
**Fits in:** ONLINE (report stage) — renders `report/accounting.py`'s
`CostSummary`.

#### `report.pdf._findings_flowables(styles, result) -> list`
**Does:** Builds the "Findings Detail" section — one block per finding,
each with a heading (`file:line — func()`), CWE/severity/source/confidence
line, message, a syntax-highlighted excerpt (`_read_excerpt` +
`_highlight`), and either a full before/after remediation (if
`get_remediation` returned one with content) or the finding's own
`fix_hint`. Prints "No findings." if the list is empty.
**Talks to:** Called only by `generate_pdf`. Calls `_read_excerpt`,
`_highlight`, `report/remediation.py::get_remediation`.
**Tech:** `reportlab.platypus`, `xml.sax.saxutils.escape`.
**Fits in:** ONLINE (report stage).

#### `report.pdf._certificate_flowables(styles, result) -> list`
**Does:** Builds the "Coverage & Certificate" section — a field table
(ranker, corpus version, provisional flag, t_hat, alpha, delta,
calibration sample count, creation date) plus a plain-language explanation
of what the certificate guarantees (and doesn't), with an extra
provisional-corpus warning banner when applicable. Renders a short "no
certificate" message instead if `result.calibration is None` (nothing was
scored).
**Talks to:** Called only by `generate_pdf`. Calls `_table_style`.
**Tech:** `reportlab.platypus`.
**Fits in:** ONLINE (report stage) — renders the `Calibration` artifact
directly.

#### `report.pdf._methodology_flowables(styles) -> list`
**Does:** Static "Methodology & Limitations" section text — what CodeGate
is, its scope (Python only, three CWEs, intraprocedural analysis,
benign-accident threat model, never executes scanned code), and how
static/model/verifier findings differ.
**Talks to:** Called only by `generate_pdf`. Calls nothing else — no
inputs beyond `styles`.
**Tech:** `reportlab.platypus`.
**Fits in:** ONLINE (report stage).

#### `report.pdf.generate_pdf(result, target, output_path, verifier_model=None) -> Path`
**Does:** Renders the complete PDF report by assembling every
`_*_flowables` section in order (cover -> executive summary -> attribution
-> cost -> findings -> page break -> certificate -> methodology) into a
reportlab `SimpleDocTemplate` and building it.
**Talks to:** Called by `cli.py::scan` (for `--format pdf`). Calls
`report/accounting.py::compute_cost_summary`, `_styles`, every
`_*_flowables` function, `reportlab.platypus.SimpleDocTemplate.build`.
**Tech:** `reportlab.platypus.SimpleDocTemplate`,
`reportlab.lib.pagesizes.letter`, `reportlab.lib.units.inch`.
**Fits in:** ONLINE — the "report" stage, PDF format.

### report/remediation.py

#### `report.remediation.get_remediation(cwe: str) -> Remediation`
**Does:** Looks up the hand-written `Remediation` (title, explanation,
before/after code) for `cwe` from a hardcoded three-entry table (CWE-89,
CWE-78, CWE-798). Never raises — an unrecognized or `"UNSPECIFIED"` cwe
(an escalated-but-unconfirmed finding) gets a generic manual-review entry
with empty `before`/`after`, since every report format must render
*something* for every finding it lists, confirmed or not.
**Talks to:** Called by `report/pdf.py::_findings_flowables`,
`report/json_sarif.py::to_sarif` (for rule descriptions). Calls nothing
else.
**Tech:** none.
**Fits in:** ONLINE — shared remediation content across report formats.

### report/accounting.py

#### `report.accounting.compute_cost_summary(result: ScanResult, verifier_model: str | None = None) -> CostSummary`
**Does:** Turns a `ScanResult`'s raw token/call counts into a priced
`CostSummary`. Looks up `verifier_model`'s per-million-token price from a
hardcoded table (falling back to a documented default), adds a fixed
system-prompt token overhead (150) per fresh verifier call actually made
(since the ingest-time chars/4 estimate doesn't include the system
prompt), and computes `calls_avoided` as auto-approved units plus
verifier cache hits. `is_estimate=True` always — kept as an explicit field
rather than a docstring note so a report renderer can't forget to disclose
it.
**Talks to:** Called by `report/pdf.py::generate_pdf`,
`report/json_sarif.py::to_json`, `report/terminal.py::render_terminal` —
every report format computes cost through this one function, never
recomputing it independently.
**Tech:** none beyond arithmetic.
**Fits in:** ONLINE — shared cost/token accounting across all report
formats.

### report/json_sarif.py

#### `report.json_sarif._scanned_at() -> str`
**Does:** Returns the current UTC time as an ISO-8601 string.
**Talks to:** Called only by `to_json`. Calls `datetime.now`.
**Tech:** `datetime` (`timezone.utc`).
**Fits in:** ONLINE (report stage).

#### `report.json_sarif._summary_dict(result, cost) -> dict`
**Does:** Assembles the `summary` block of the JSON report — unit/finding
counts by category, plus LLM call counts from `cost`.
**Talks to:** Called only by `to_json`. Calls nothing else.
**Tech:** none.
**Fits in:** ONLINE (report stage).

#### `report.json_sarif._certificate_dict(result) -> dict | None`
**Does:** Converts `result.calibration` into a plain dict for JSON
serialization, or `None` if there's no certificate.
**Talks to:** Called only by `to_json`. Calls nothing else.
**Tech:** none.
**Fits in:** ONLINE (report stage).

#### `report.json_sarif.to_json(result, target, verifier_model=None) -> str`
**Does:** Renders a `ScanResult` as CodeGate's own JSON report shape (not
a third-party schema — that's what SARIF is for): version, target,
timestamp, summary, certificate, cost, findings, skipped files. Every
number traces back to a `ScanResult` field or `CostSummary` — nothing is
recomputed or guessed at render time.
**Talks to:** Called by `cli.py::scan` (for `--format json`). Calls
`report/accounting.py::compute_cost_summary`, `_summary_dict`,
`_certificate_dict`, `_scanned_at`, `json.dumps`.
**Tech:** `json`.
**Fits in:** ONLINE — the "report" stage, JSON format.

#### `report.json_sarif.to_sarif(result, target) -> str`
**Does:** Renders a `ScanResult` as SARIF 2.1.0, the format GitHub code
scanning and most CI security tooling consume. Builds one rule per tracked
CWE plus an `UNSPECIFIED` rule for escalated-but-unconfirmed findings,
reusing `report/remediation.py::get_remediation`'s title/explanation text
as the rule descriptions so there's exactly one source of truth for that
prose. Maps `Finding.severity` to SARIF's `error`/`warning`/`note`
levels (default `"warning"` for anything unrecognized).
**Talks to:** Called by `cli.py::scan` (for `--format sarif`). Calls
`report/remediation.py::get_remediation`, `json.dumps`.
**Tech:** `json`.
**Fits in:** ONLINE — the "report" stage, SARIF format.

### report/terminal.py

#### `report.terminal.render_terminal(result, target, console, verifier_model=None) -> None`
**Does:** Prints a human-readable scan summary directly to `console` —
CodeGate's default output when no `--format` is given: a summary table
(units scanned/auto-approved/escalated/findings/skipped), a findings
table (using `overflow="fold"` on every column rather than Rich's default
ellipsis truncation, which the code comment notes renders as mojibake on
a default-codepage Windows terminal), a certificate table with a
provisional-warning line if applicable, and a one-line cost summary.
**Talks to:** Called by `cli.py::scan` (for `--format terminal`, the
default). Calls `report/accounting.py::compute_cost_summary`,
`rich.table.Table`.
**Tech:** `rich.console.Console`, `rich.table.Table`.
**Fits in:** ONLINE — the "report" stage, terminal format.

---

## scripts/

Four standalone entry-point scripts, each prepending `src/` to
`sys.path` so they run without an editable install. Three
(`run_real.py`, `run_pipeline_dry_run.py`, `train_from_pregenerated.py`)
drive `research/pipeline.py::run_full_pipeline` with different backend
choices; `run_eval.py` reads the artifacts those produce and computes
every metric `research/eval/` currently supports.

### scripts/run_real.py

#### `run_real.preflight(base_url: str, wanted_models: list[str]) -> None`
**Does:** Fails fast and legibly if the Ollama host at `base_url` is
unreachable or missing a configured model, before any generation work
begins — the docstring is explicit that without this, a run dies hours in
or silently produces garbage. Distinguishes a connect-timeout (likely a
firewall blocking port 11434) from a connection error (likely
`OLLAMA_HOST` still bound to localhost on the host machine) with separate
actionable messages pointing at `docs/OLLAMA_SETUP.md`. Tolerates a bare
model name matching any tag Ollama reports (e.g. config says `qwen2.5-coder`,
Ollama reports `qwen2.5-coder:7b`).
**Talks to:** Called by `main`, unless `--skip-preflight`. Calls
`requests.get` against `{base_url}/api/tags`.
**Tech:** `requests`.
**Fits in:** OFFLINE — a pre-run sanity check specific to the real-Ollama
generation path.

#### `run_real.build_backends(cfg: CodeGateConfig, base_url: str) -> dict[str, Backend]`
**Does:** Builds one `OllamaBackend` per generator named in
`cfg.generators`, all pointed at the same host.
**Talks to:** Called by `main`. Calls
`research/generation/backends.py::OllamaBackend`.
**Tech:** none beyond `OllamaBackend`'s own.
**Fits in:** OFFLINE.

#### `run_real.main() -> int`
**Does:** The script entry point. Parses args, loads config, resolves the
Ollama base URL, runs `preflight` (unless skipped), loads prompts (with an
optional `--limit`), builds backends, and either (`--generate-only`) runs
just `run_generation` and writes `generations.parquet` for a teammate to
ship back and consume via `train_from_pregenerated.py` — deliberately
never executing any generated code, which the docstring notes is exactly
why this mode is safe to run on someone else's machine — or runs the full
`run_full_pipeline` (generation through calibration) and prints a summary.
**Talks to:** Invoked as `python scripts/run_real.py`. Calls
`config.py::load_config`, `env.py::get_env`, `preflight`,
`research/corpus/prompts.py::load_prompt_bank`, `build_backends`,
`research/generation/harness.py::run_generation`,
`schemas.py::validate_dataframe`, `research/pipeline.py::run_full_pipeline`.
**Tech:** `argparse`.
**Fits in:** OFFLINE — the real-corpus generation entry point.

### scripts/run_eval.py

#### `run_eval.main() -> int`
**Does:** Runs every metric CodeGate can currently evaluate, writing PNGs
and a `metrics.json` summary to `data/eval/`: (1) oracle accuracy on the
real hand-labeled fixtures; (2) corpus label distribution, if
`labeled.parquet` exists; (3) ranker score distribution + separation
metrics, if scores also exist; (4) the LTT threshold-search trace plot, if
a trace and calibration exist; (5) scan-vs-ground-truth on
`examples/vulnerable_app/` (real, hand-labeled, not provisional), both
without and — opt-in via `--with-llm`, since an eval script shouldn't spend
API calls just by being run — with the LLM verifier. Each stage prints a
one-line status and is individually skippable if its required input file
is missing, rather than failing the whole run.
**Talks to:** Invoked as `python scripts/run_eval.py`. Calls
`research/artifacts.py::load_calibration`,
`research/eval/metrics.py::oracle_accuracy_on_fixtures`/
`corpus_label_distribution`/`ranker_score_frame`/`ranker_separation_metrics`/
`scan_ground_truth_eval`, `research/eval/plots.py::plot_oracle_accuracy`/
`plot_corpus_label_distribution`/`plot_score_distribution_by_label`/
`plot_ltt_trace`/`plot_scan_ground_truth`, `scan/pipeline.py::run_scan`,
`scan/verifier.py::build_verifier_backend`.
**Tech:** `argparse`, `pandas`, `json`.
**Fits in:** OFFLINE (eval subpackage), but its last stage evaluates the
ONLINE scanner directly — the one script that exercises both halves of
the system in one run.

### scripts/run_pipeline_dry_run.py

#### `run_pipeline_dry_run.main() -> int`
**Does:** End-to-end dry run on `SimulatedBackend` — every pipeline stage
(generation, oracle labeling, consensus, ranking, LTT calibration,
cost-coverage frontier, generator-shift experiment) with zero network
access and zero API keys. The script this project's tests and demos lean
on before real backends are available.
**Talks to:** Invoked as `python scripts/run_pipeline_dry_run.py`. Calls
`config.py::load_config`, `research/corpus/prompts.py::load_prompt_bank`,
`research/generation/backends.py::SimulatedBackend`/`stable_seed`,
`research/pipeline.py::run_full_pipeline`.
**Tech:** `argparse`.
**Fits in:** OFFLINE — the simulated-corpus counterpart to
`run_real.py`, sharing the same `run_full_pipeline` logic so the two never
drift apart.

### scripts/train_from_pregenerated.py

#### `train_from_pregenerated.main() -> int`
**Does:** The receiving half of the two-machine Ollama workflow
documented in `docs/OLLAMA_SETUP.md`: loads a `generations.parquet` someone
else produced (via `run_real.py --generate-only`) and runs labeling
through calibration on it directly, via `run_full_pipeline`'s
`pregenerated_df` parameter — skipping generation entirely so this machine
never needs Ollama access. Builds a dummy `{name: None}` backends dict
purely so the summary's generator count prints correctly; no real
`Backend` instances are needed since generation is bypassed.
**Talks to:** Invoked as `python scripts/train_from_pregenerated.py
<path>`. Calls `config.py::load_config`, `pandas.read_parquet`,
`research/pipeline.py::run_full_pipeline`.
**Tech:** `argparse`, `pandas`.
**Fits in:** OFFLINE — the labeling/calibration half of the split
generation workflow, consuming what `run_real.py --generate-only`
produces.

