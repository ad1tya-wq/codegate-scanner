# CodeGate Scanner — Function Reference

Flat, per-function technical reference. Different purpose from
`ENGINEERING_LOG.md`: that document is a narrative (phases, decisions, why
things changed); this one is a lookup — "what does `X` do, what calls it,
what does it call" — without reading the source.

**Scope of this pass:** every function that exists today — the OFFLINE
research half (corpus generation, oracle labeling, ranking, calibration).
The ONLINE scanner half (`scan/`, `report/`, `cli.py`) doesn't exist yet;
each phase appends its own section here in the same commit as its code, so
this document never claims a function exists before it does.

Architecture context for the "Fits in" field on every entry:

```
  OFFLINE (research, rare)                 ONLINE (scanner, constant — not yet built)
  ────────────────────────                 ──────────────────────────
  prompts → LLMs → code                    directory/file → AST units
       ↓                                        ↓
  oracles label (detonation)               static pre-pass (semgrep+creds)
       ↓                                        ↓
  train ranker ────► model.joblib ────►    ranker scores
       ↓                                        ↓
  calibrate LTT ──► calibration.json ──►   GATE: skip or escalate
                                                ↓
                                           verifier → findings → PDF
```

---

## `gate/` — the statistical core

### `gate/ltt.py`

#### `calibrate_threshold(scores, labels, alpha, delta, thresholds=None) -> LTTResult`
**Does:** Runs Learn-Then-Test fixed-sequence testing over a descending
grid of candidate thresholds to find the least-conservative `t_hat` such
that the miss-rate on vulnerable calibration samples is certified
`≤ alpha` with confidence `≥ 1 - delta`. For each threshold, computes
`k = count(vuln_scores >= t)` and a p-value via
`scipy.stats.binom.cdf(k, n, alpha)`; stops at the first threshold that
fails certification (monotonicity guarantees every less-conservative `t`
also fails), so `t_hat` is the last one that passed.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` (at the
project's configured `alpha`/`delta`) and by `research/eval/frontier.py`
(swept across a range of alphas) and `research/eval/shift.py` (per
generator-holdout). Calls nothing else in the codebase — pure numpy/scipy.
**Tech:** `numpy`, `scipy.stats.binom`.
**Fits in:** OFFLINE — the calibration step that turns ranker scores +
labels into `calibration.json`'s `t_hat`.

#### `LTTResult` (frozen dataclass)
**Does:** Carries the calibration result: `t_hat` (`None` if nothing could
be certified — caller should escalate everything), `alpha`, `delta`,
`n_vuln_calib`, `coverage` (fraction of *all* calibration samples that
would be auto-approved at `t_hat`), and `trace` (the full per-threshold
search history — `(threshold, k, p_value, certified)` tuples, the audit
evidence behind `t_hat`).
**Talks to:** Constructed only by `calibrate_threshold`. Consumed by
`research/pipeline.py` (writes `trace` to `ltt_trace.csv`, and passes the
whole result to `research/artifacts.py::save_calibration`).
**Tech:** stdlib `dataclasses`.
**Fits in:** OFFLINE — calibration artifact, now persisted (Phase 2).

### `gate/risk.py`

#### `empirical_risk(scores, labels, t) -> float`
**Does:** Computes the realized (not certified) risk at threshold `t`:
the fraction of *actually vulnerable* samples that would be auto-approved
(`score >= t`). Returns `nan` if there are no vulnerable samples to
measure against.
**Talks to:** Called by `research/eval/shift.py::run_shift_experiment` to
measure whether a certificate calibrated on some generators still holds
when checked against a held-out one.
**Tech:** `numpy`.
**Fits in:** OFFLINE — the generator-shift experiment (headline research
result: does the certificate survive a model switch).

#### `clopper_pearson_ci(k, n, confidence=0.95) -> (lo, hi)`
**Does:** Exact binomial confidence interval for `k` successes out of `n`
trials, via the beta distribution's inverse CDF. Returns `(0.0, 1.0)` for
`n == 0`.
**Talks to:** Standalone utility — not yet called by any other module in
this codebase (available for reporting a confidence band around a
measured rate, e.g. in Phase 7's PDF methodology appendix).
**Tech:** `scipy.stats.beta`.
**Fits in:** Currently unused; intended for ONLINE reporting once Phase 7
lands.

---

## `oracles/` — ground-truth labeling

### `oracles/ast_utils.py`

#### `function_exists(code, function_name) -> bool`
**Does:** Parses `code` and checks whether it defines a function (any
nesting depth) named `function_name`. Returns `False` on a syntax error
rather than raising.
**Talks to:** Called by every dynamic oracle (`sqli_oracle.check_sqli`,
`cmdi_oracle.check_cmdi`) before attempting to execute the target
function, and by `research/pipeline.py::_first_function_name`'s sibling
logic for picking a candidate entry-point name.
**Tech:** stdlib `ast`.
**Fits in:** OFFLINE — pre-execution gate for the detonation oracles.

### `oracles/sandbox.py`

#### `run_sandboxed(code, harness, timeout_s=5.0) -> SandboxResult`
**Does:** Writes `harness + code` to a temp file and runs it as a fresh
Python subprocess with a wall-clock timeout, capturing stdout/stderr/exit
code. Process-level isolation only — no network disable, no container, no
read-only filesystem (Docker Desktop unavailable at time of writing; the
docstring documents the intended `docker run --network none --read-only`
swap as a drop-in replacement for this function's body, since every
oracle calls it through this same interface).
**Talks to:** Called by `sqli_oracle.check_sqli` and
`cmdi_oracle.check_cmdi` to detonate a payload against generated code.
**Tech:** stdlib `subprocess`, `tempfile`.
**Fits in:** OFFLINE only, and *only* against generated code on the
research machine — this is exactly the execution step `--generate-only`
exists to keep off a teammate's personal laptop.

#### `SandboxResult` (frozen dataclass)
**Does:** Carries `stdout`, `stderr`, `returncode`, `timed_out` from one
sandboxed execution.
**Talks to:** Returned by `run_sandboxed`; inspected by both dynamic
oracles to decide `True`/`False`/`None`.
**Tech:** stdlib `dataclasses`.
**Fits in:** OFFLINE.

### `oracles/sqli_oracle.py`

#### `has_sql_sink(code) -> bool`
**Does:** Cheap keyword scope check — does `code` contain any hint of SQL
execution (`.execute`, `cursor`, `select `, `sqlite3`, `sqlalchemy`, etc.)?
Deliberately over-inclusive: any hint routes to the real dynamic oracle
rather than shortcutting.
**Talks to:** Called first by `check_sqli`, before the expensive
detonation path. Regression-tested directly in
`tests/test_oracle_robustness.py::test_sink_shortcut_does_not_swallow_real_vulnerabilities`.
**Tech:** plain string matching.
**Fits in:** OFFLINE — lets `label_row` return a confident "safe" for code
that provably cannot be SQL-injectable, instead of discarding it as an
abstention.

#### `check_sqli(code, function_name) -> bool | None`
**Does:** Returns `False` immediately if `has_sql_sink(code)` is `False`
(confidently safe). Otherwise, if `function_exists`, injects the payload
`nonexistent' OR '1'='1` against a 16-table sqlite fixture and checks
whether the returned row count is `>= 1` (injection fired, since a
legitimate lookup of a nonexistent user returns 0 rows). Returns `None`
if the function doesn't exist, the harness times out, or it errors without
producing evidence either way.
**Talks to:** Calls `has_sql_sink`, `function_exists`, `run_sandboxed`.
Called by `research/pipeline.py::label_row` for every `CWE-89` sample,
tried against a list of candidate function names.
**Tech:** stdlib `sqlite3` (inside the sandboxed subprocess), the shared
`_HARNESS_TEMPLATE` and `_FIXTURE_TABLES` (16 plausible table names — see
`ENGINEERING_LOG.md` §3 Phase 1 item 5 for why the fixture is this wide).
**Fits in:** OFFLINE — CWE-89 ground-truth labeling.

### `oracles/cmdi_oracle.py`

#### `has_shell_sink(code) -> bool`
**Does:** Same pattern as `has_sql_sink`, for shell/process invocation
(`subprocess`, `os.system`, `os.popen`, `shell=true`, etc.).
**Talks to:** Called first by `check_cmdi`.
**Tech:** plain string matching.
**Fits in:** OFFLINE — same role as `has_sql_sink`, for CWE-78.

#### `check_cmdi(code, function_name) -> bool | None`
**Does:** Returns `False` if there's no shell sink at all. Otherwise, if
the function exists, injects `127.0.0.1 & echo pwned > <sentinel>` as a
host argument and checks whether the sentinel file was created (proof the
payload reached a real shell). The `&` separator (not `;`) is chosen
specifically so the same payload works whether the vulnerable code's
`shell=True` call executes via `cmd.exe` (Windows dev machine) or POSIX
`sh` — documented inline, see `ENGINEERING_LOG.md` §3 Phase 1 item 7.
**Talks to:** Calls `has_shell_sink`, `function_exists`, `run_sandboxed`.
Called by `research/pipeline.py::label_row` for every `CWE-78` sample.
**Tech:** stdlib `tempfile`, `uuid` (sentinel filename), `pathlib`.
**Fits in:** OFFLINE — CWE-78 ground-truth labeling.

### `oracles/creds_oracle.py`

#### `_shannon_entropy(s) -> float`
**Does:** Standard Shannon entropy of a string, used as a "does this look
like a random secret, not a word" signal.
**Talks to:** Internal helper, called only by `check_creds`.
**Tech:** `math.log2`.
**Fits in:** OFFLINE, CWE-798 labeling.

#### `check_creds(code) -> bool`
**Does:** Static-only (no execution): walks the AST looking for string
literals assigned to, passed as, or defaulted for a name matching a
secret-ish pattern (`password`, `api_key`, `token`, `credential`, ...),
that aren't an obvious placeholder (`changeme`, `example`, `xxx`, ...),
and either have entropy above a threshold or match a known key-shape regex
(AWS access key ID pattern, base64-shaped 40-char string). Checks both
plain assignments/keyword args and function-default-argument literals.
**Talks to:** Calls `_shannon_entropy`. Called by
`research/pipeline.py::label_row` for every `CWE-798` sample as the
*authoritative* static verdict (no dynamic oracle is possible for hardcoded
credentials — nothing to detonate).
**Tech:** stdlib `ast`, `re`, `math`.
**Fits in:** OFFLINE — CWE-798 ground-truth labeling; the one oracle that
is purely static because the vulnerability class has no runtime signal to
observe.

### `oracles/consensus.py`

#### `consensus_label(cwe, semgrep_hit, dynamic_verdict, static_verdict, adjudicator_verdict) -> int`
**Does:** Applies the project's consensus rule (v1): for CWE-89/CWE-78
(dynamic oracle exists), the dynamic verdict is authoritative whenever it
isn't `None`; falls back to `semgrep_hit AND adjudicator_verdict` only on
dynamic abstention. For CWE-798 (no dynamic oracle possible), the static
verdict is authoritative when present, same fallback otherwise. Raises
`ValueError` on an unrecognized CWE — deliberately, so a new CWE added to
`config.yaml` without updating this function fails loudly rather than
silently defaulting.
**Talks to:** Called by `research/pipeline.py::label_row`, which supplies
the outputs of `check_sqli`/`check_cmdi`/`check_creds`/`run_semgrep` as
its inputs.
**Tech:** pure logic, no dependencies.
**Fits in:** OFFLINE — the single point where all oracle signals for one
sample are reduced to one label.

### `oracles/semgrep_oracle.py`

#### `_run_semgrep_cli(target, ruleset_path=None, timeout=60) -> dict`
**Does:** The shared CLI invocation both public functions below wrap:
runs `semgrep --config <ruleset> --json --quiet <target>` against a real
path already on disk (a file or a whole directory — semgrep accepts
either), parses the JSON payload into
`{"hit": bool, "findings": [{"rule_id", "severity", "path", "start_line",
"end_line", "message"}, ...]}`. Degrades to
`{"hit": False, "findings": [], "error": "..."}` instead of raising if the
binary is missing, the call times out, or the output isn't parseable
JSON — added when Phase 5 gave callers a real caller-supplied `timeout`
(120s for directory scans vs. the original hardcoded 60s for snippets),
which the single combined function couldn't express cleanly for both
use cases.
**Talks to:** Called by `run_semgrep` (wraps a temp file) and
`run_semgrep_on_path` (calls it directly on the caller's path).
**Tech:** the `semgrep` CLI via `subprocess`, `json` for output parsing.
**Fits in:** shared by both OFFLINE and ONLINE call sites.

#### `run_semgrep(code, ruleset_path=None) -> dict`
**Does:** Writes `code` to a temp file, then delegates to
`_run_semgrep_cli`. Used when the caller has an in-memory code string
rather than a real file — CodeGate's local custom ruleset
(`data/semgrep_rules/codegate_rules.yaml` — written in-house because the
free community registry packs were verified to produce zero findings
against raw-stdlib `sqlite3`/`subprocess` code; they target framework
code like SQLAlchemy/Django/Flask) is the default.
**Talks to:** Called by `research/pipeline.py::label_row` (when
`use_semgrep_and_adjudicator=True`) and by
`ranker/r0_semgrep_score.py::score_r0`.
**Tech:** `tempfile`, then `_run_semgrep_cli`.
**Fits in:** OFFLINE — per-sample, in the labeling/R0-scoring path.

#### `run_semgrep_on_path(target, ruleset_path=None) -> dict`
**Does:** Runs semgrep directly against a real file or directory already
on disk — one CLI invocation covering an entire target, at a 120s
timeout (vs. `run_semgrep`'s 60s), rather than one invocation per unit.
This is the fix for the per-row throughput problem
`ranker/r0_semgrep_score.py`'s own docstring flags: at scan scale (a
whole codebase) one process spawn beats hundreds.
**Talks to:** Called by `scan/pipeline.py::_semgrep_findings` (Phase 5).
Findings carry real file paths and line numbers so they can be mapped
back to specific `scan/ingest.py::Unit`s.
**Tech:** `_run_semgrep_cli` directly (no temp file — the target is
already a real path).
**Fits in:** ONLINE — the scan pipeline's static pre-pass.

---

## `ranker/` — scoring generated code

### `ranker/r0_semgrep_score.py`

#### `score_r0(generations_df) -> pd.DataFrame`
**Does:** The cheapest ranker: runs `run_semgrep` on every row, converts
finding count/severity into a danger score via `_SEVERITY_WEIGHTS`
(`ERROR: 3, WARNING: 2, INFO: 1`), negates it to a safety score (higher =
safer, matching the project-wide ranker convention). Its own docstring
flags that per-row semgrep invocation (~1–10s process startup each) does
not scale past a few hundred samples.
**Talks to:** Calls `oracles/semgrep_oracle.run_semgrep`. Not currently
called by `research/pipeline.py` (R2 is the active ranker); kept as the
cheap baseline for comparison.
**Tech:** `pandas`.
**Fits in:** OFFLINE — baseline ranker, not the production path.

### `ranker/r2_embedding_lr.py`

#### `_embed(code_series) -> np.ndarray`
**Does:** Vectorizes a pandas Series of code strings via a 512-feature
hashing bag-of-tokens vectorizer (`sklearn.feature_extraction.text.HashingVectorizer`).
Explicitly a stand-in: the docstring documents that a real CodeBERT/UniXcoder
embedding is the intended production embedding, and swapping this
function's body changes nothing about `R2Ranker`'s public interface.
**Talks to:** Called by both `R2Ranker.fit` and `R2Ranker.score`.
**Tech:** `sklearn.feature_extraction.text.HashingVectorizer`.
**Fits in:** OFFLINE — feature extraction for the active ranker.

#### `R2Ranker` (`fit(train_df, labels) -> R2Ranker`, `score(df) -> pd.DataFrame`)
**Does:** `fit` embeds the training code and trains a
`sklearn.linear_model.LogisticRegression` against the vulnerable/safe
labels. `score` embeds new code and returns `predict_proba[:, 0]`
(probability of class 0 = safe) as the safety score — higher is safer,
matching the LTT gate's `score >= t_hat` convention. `score` raises
`RuntimeError` if called before `fit`.
**Talks to:** Constructed and used by
`research/pipeline.py::run_full_pipeline` (the single coupling point:
`research/pipeline.py:184`). This is the class whose fitted instance gets
persisted to `model.joblib` via `research/artifacts.py::save_model`
(Phase 2), and whose one-file coupling surface is why swapping the
interim model for the real-corpus model is a file replacement, not a code
change (see `ENGINEERING_LOG.md` §6).
**Tech:** `sklearn.linear_model.LogisticRegression`, `numpy`, `pandas`.
**Fits in:** OFFLINE (training) — the resulting fitted model then serves
ONLINE scoring once Phase 5 exists.

---

## `research/` — the offline pipeline itself

### `research/pipeline.py`

#### `_first_function_name(code) -> str | None`
**Does:** Parses `code` and returns the name of the first top-level
function defined, or `None`. Used as a fallback candidate entry-point name
for real (non-simulated) model output, which won't reliably use the
`SimulatedBackend`'s fixed names (`handler`, `process`, `run_task`,
`do_work`).
**Talks to:** Called only by `label_row`.
**Tech:** stdlib `ast`.
**Fits in:** OFFLINE — labeling real generator output.

#### `label_row(row, use_semgrep_and_adjudicator=False) -> dict`
**Does:** Runs the appropriate oracle(s) for one generated snippet based
on its CWE (`check_sqli` for CWE-89, `check_cmdi` for CWE-78, `check_creds`
for CWE-798), trying a list of candidate function names (the real model's
own first-defined function, then the simulator's fixed names) until one
produces a verdict. Optionally also runs `run_semgrep`. Applies
`consensus_label`. Returns `LABEL_ABSTAIN` (not a coerced "safe") if no
oracle reached a verdict at all.
**Talks to:** Calls `_first_function_name`, `check_sqli`, `check_cmdi`,
`check_creds`, `run_semgrep` (conditionally), `consensus_label`. Called
once per row by `run_full_pipeline`, and directly by
`tests/test_oracle_robustness.py`'s end-to-end regression test.
**Tech:** `pandas.Series` in, `dict` out.
**Fits in:** OFFLINE — the per-sample labeling step, between generation
and ranker training.

#### `run_full_pipeline(cfg, prompts, backends, is_simulated, out_dir, use_semgrep_and_adjudicator=False, checkpoint_path=None) -> dict`
**Does:** The full offline pipeline in one call: generation
(`run_generation`) → labeling (`label_row` per row) → abstention filtering
and warning → R2 ranker fit/score → LTT calibration at the configured
alpha/delta (writing `ltt_trace.csv`) → cost-coverage frontier
(`compute_frontier`, `plot_frontier`) → generator-shift experiment
(`run_shift_experiment`, `plot_shift_results`) per held-out generator.
Writes every intermediate artifact (`generations.parquet`,
`labeled.parquet`, `scores_r2.parquet`, `frontier.csv`/`.png`,
`ltt_trace.csv`, `shift_results.csv`/`.png`) to `out_dir`. Returns a
summary dict (`n_generated`, `vuln_rate`, `n_abstain`, `n_vuln_calib`,
`t_hat`, `coverage`, `n_shift_experiments`).
**Talks to:** Calls `run_generation`, `label_row`, `R2Ranker`,
`calibrate_threshold`, `compute_frontier`, `plot_frontier`,
`run_shift_experiment`, `plot_shift_results`, `validate_dataframe`,
`_write_placeholder_plot`. Called by both
`scripts/run_pipeline_dry_run.py` (simulated) and `scripts/run_real.py`
(real, when not `--generate-only`) — the shared entry point that keeps the
two paths from drifting apart.
**Tech:** `pandas`, `numpy`, orchestration only (no ML/stats logic of its
own beyond what it calls).
**Fits in:** OFFLINE — this function *is* the offline half of the
architecture diagram, top to bottom.

#### `_write_placeholder_plot(path, message) -> None`
**Does:** Writes a PNG with a centered text message, for the case where
there's insufficient data (e.g. zero vulnerable calibration samples) to
produce a real frontier/shift plot — so downstream code that expects a
file at that path never breaks.
**Talks to:** Called only by `run_full_pipeline`'s two degenerate-data
branches.
**Tech:** `matplotlib` (`Agg` backend, headless).
**Fits in:** OFFLINE — defensive plotting fallback.

### `research/corpus/prompts.py`

#### `Prompt` (frozen dataclass)
**Does:** One prompt: `prompt_id`, `cwe`, `flavor`
(`vulnerable`/`neutral`/`near_miss`), `split` (`train`/`calib`), `task`
(the actual text sent to a generator).
**Talks to:** Constructed by `load_prompt_bank`; consumed by
`Backend.generate` implementations and `research/pipeline.py`.
**Tech:** stdlib `dataclasses`.
**Fits in:** OFFLINE — the unit of work for generation.

#### `load_prompt_bank(prompts_dir) -> list[Prompt]`
**Does:** Reads every `*.yaml` file in `prompts_dir`, and for each CWE's
task group, expands it into three `Prompt`s (one per flavor:
`vulnerable`, `neutral`, `near_miss`) sharing the same task group's `id`
and `split`.
**Talks to:** Called by `scripts/run_real.py::main` and
`scripts/run_pipeline_dry_run.py`. Reads YAML files under
`cfg.prompts_dir`.
**Tech:** `PyYAML`, `pathlib`.
**Fits in:** OFFLINE — turns the hand-written prompt YAMLs into the
in-memory prompt bank.

### `research/generation/backends.py`

#### `stable_seed(*parts) -> int`
**Does:** Deterministic, cross-process integer seed from arbitrary parts,
via `sha256(joined_parts)[:8 hex chars]`. Exists specifically because
Python's builtin `hash()` is randomized per-process (`PYTHONHASHSEED`) and
is unsafe for anything that must reproduce across separate runs.
**Talks to:** Called by every `Backend.generate` implementation (as the
model's sampling seed) and by
`research/generation/harness.py::_sample_id` (as the sample ID's basis) —
the same function drives both, so a sample's ID and its generation seed
are derived from the same stable input.
**Tech:** stdlib `hashlib`.
**Fits in:** OFFLINE — reproducibility primitive used throughout
generation.

#### `Backend` (ABC) — `generate(prompt, seed) -> str`
**Does:** The common interface every generator (simulated or real)
implements: given a `Prompt` and an integer seed, return generated Python
source as a string.
**Talks to:** Implemented by `SimulatedBackend`, `OllamaBackend`,
`OpenRouterBackend`, `GeminiBackend`, `GroqBackend`. Consumed by
`research/generation/harness.py::run_generation`, which is backend-agnostic
by design — the harness's checkpoint/resume/retry logic works identically
regardless of which backend produced (or failed to produce) a sample.
**Tech:** stdlib `abc`.
**Fits in:** OFFLINE — the generator abstraction; will also be reused
by Phase 6's `scan/verifier.py` for the escalation LLM call.

#### `SimulatedBackend.generate(prompt, seed) -> str`
**Does:** Deterministic, offline, no-network code generator. Picks a
CWE/flavor-appropriate template from `_SIM_TEMPLATES`, fills in a
randomized (but seeded) function/argument name, returns valid Python.
Used to exercise the full pipeline before real backends were connected,
and still used by most of the test suite for determinism.
**Talks to:** Reads `_SIM_TEMPLATES` (module-level dict). Called by
`research/pipeline.py` in dry-run mode and directly by several tests
(`test_generation.py`, `test_oracle_robustness.py`).
**Tech:** stdlib `random` (seeded via `stable_seed`).
**Fits in:** OFFLINE — the zero-cost stand-in generator, pre-Track-A.

#### `OllamaBackend.generate(prompt, seed) -> str`
**Does:** POSTs to a local (or remote) Ollama server's `/api/generate`
endpoint with the model name, prompt text, and seed; returns the response
text. Requires Ollama running and reachable at `base_url`.
**Talks to:** Constructed per-generator by
`scripts/run_real.py::build_backends`. Network calls only — no
in-repo callees.
**Tech:** `requests`.
**Fits in:** OFFLINE — the active real-generation path (all four
configured generators are Ollama models as of commit `ba642e7`).

#### `OpenRouterBackend.generate`, `GroqBackend.generate` (structurally identical)
**Does:** POST to the respective provider's OpenAI-compatible chat
completions endpoint with an API key; return the completion text.
**Talks to:** Would be constructed wherever `config.yaml` names one of
these providers as a generator or verifier; not currently wired into
`run_real.py`'s all-Ollama path.
**Tech:** `requests`.
**Fits in:** OFFLINE (generation) or, for Phase 6, ONLINE (verifier) — the
same `Backend` interface serves both roles.

#### `GeminiBackend.generate`
**Does:** POSTs to Google's Gemini `generateContent` endpoint with an API
key; returns the response text.
**Talks to:** Intended as the label *adjudicator* specifically —
deliberately never one of the code generators, so it never adjudicates its
own output (role-separation rule enforced structurally in
`config.py::load_config`, which raises if `adjudicator` also appears in
`generators`). Not yet called anywhere at runtime — `label_row`'s
`adjudicator_verdict` stays hardcoded `False` until this is wired in.
**Tech:** `requests`.
**Fits in:** OFFLINE — adjudication path, built but unconnected.

### `research/generation/harness.py`

#### `_sample_id(prompt_id, generator_name, k) -> str`
**Does:** `f"{stable_seed(prompt_id, generator_name, k):08x}-{k}"` —
deterministic ID for one (prompt, generator, replicate) triple.
**Talks to:** Calls `stable_seed`. Called by `run_generation` for every
planned sample, both to check the checkpoint and to tag new records.
**Tech:** `hashlib` (via `stable_seed`).
**Fits in:** OFFLINE — resume correctness depends on this being stable
across process restarts (see `ENGINEERING_LOG.md` §4 decision #3).

#### `_load_checkpoint(checkpoint_path) -> dict[str, dict]`
**Does:** Reads a JSONL checkpoint file, one completed record per line,
keyed by `sample_id`. Skips (rather than raising on) a malformed final
line — the signature of an interrupted write mid-run.
**Talks to:** Called once at the start of `run_generation`.
**Tech:** stdlib `json`, `pathlib`.
**Fits in:** OFFLINE — resume mechanism.

#### `run_generation(prompts, backends, samples_per_prompt, is_simulated, checkpoint_path=None, on_progress=None) -> pd.DataFrame`
**Does:** Iterates every `(prompt, generator, replicate)` combination,
skipping any whose `sample_id` is already in the checkpoint. For new
samples, calls `backend.generate`, catching and logging (not raising on)
any exception so one bad sample doesn't abort a multi-hour run; appends
each success to the JSONL checkpoint immediately. Returns the full
DataFrame of records (schema: `sample_id, prompt_id, cwe, flavor,
generator, code, split, is_simulated`).
**Talks to:** Calls `_load_checkpoint`, `_sample_id`, `stable_seed`,
`Backend.generate`. Called by `research/pipeline.py::run_full_pipeline`
and directly by `scripts/run_real.py --generate-only`.
**Tech:** `pandas`, stdlib `json`/`sys`.
**Fits in:** OFFLINE — the generation stage, checkpointed for the
multi-hour unattended Track A run.

### `research/eval/frontier.py`

#### `compute_frontier(scores, labels, alphas, delta) -> pd.DataFrame`
**Does:** For each candidate `alpha`, calls `calibrate_threshold` and
records the resulting `t_hat`/`coverage`/`n_vuln_calib` — the
cost-coverage curve (coverage = fraction of traffic that never needs an
LLM call, as a function of the certified max miss-rate).
**Talks to:** Calls `gate/ltt.py::calibrate_threshold`. Called by
`research/pipeline.py::run_full_pipeline`.
**Tech:** `pandas`, `numpy`.
**Fits in:** OFFLINE — produces `frontier.csv`, the evidence for choosing
an operating `alpha`.

### `research/eval/shift.py`

#### `ShiftResult` (frozen dataclass)
**Does:** Carries one held-out-generator experiment's result:
`held_out_generator`, `t_hat`, `certified_alpha`,
`realized_risk_on_held_out`, `certificate_held`.
**Talks to:** Constructed by `run_shift_experiment`; consumed by
`research/pipeline.py` (written to `shift_results.csv`) and
`research/eval/plots.py::plot_shift_results`.
**Tech:** stdlib `dataclasses`.
**Fits in:** OFFLINE — generator-shift experiment result.

#### `run_shift_experiment(scores_by_generator, labels_by_generator, held_out, alpha, delta) -> ShiftResult`
**Does:** Pools calibration data from every generator *except*
`held_out`, calibrates a threshold on that pool, then measures the
realized risk (`empirical_risk`) on `held_out`'s own data — the headline
"does the certificate survive a generator switch" experiment. Raises
`ValueError` if there's no non-held-out generator to calibrate on.
**Talks to:** Calls `gate/ltt.py::calibrate_threshold`,
`gate/risk.py::empirical_risk`. Called once per generator by
`research/pipeline.py::run_full_pipeline` when ≥2 generators and ≥1
vulnerable calibration sample are present.
**Tech:** `numpy`.
**Fits in:** OFFLINE — this experiment is the project's stated headline
research result once run against real (non-simulated) generator diversity.

### `research/eval/plots.py`

#### `plot_frontier(frontier_df, out_path) -> None`
**Does:** Renders the alpha-vs-coverage cost-coverage curve to a PNG.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` with
`compute_frontier`'s output.
**Tech:** `matplotlib` (`Agg` backend).
**Fits in:** OFFLINE — reporting artifact for the research write-up.

#### `plot_shift_results(results, out_path) -> None`
**Does:** Bar chart of realized risk per held-out generator, colored
green/red by whether the certificate held, with the certified alpha drawn
as a reference line.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline` with
`run_shift_experiment`'s outputs.
**Tech:** `matplotlib` (`Agg` backend).
**Fits in:** OFFLINE — reporting artifact for the generator-shift result.

---

## Root modules

### `config.py`

#### `CodeGateConfig` (frozen dataclass)
**Does:** Typed view of `config.yaml`: `alpha`, `delta`, `random_seed`,
`cwes`, `flavors`, `generators`, `adjudicator`, `verifier`,
`samples_per_prompt`, `prompts_per_cwe`, `split_ratios`, and three path
fields.
**Talks to:** Constructed only by `load_config`; consumed throughout
`research/pipeline.py` and `scripts/run_real.py`.
**Tech:** stdlib `dataclasses`.
**Fits in:** Both halves — this is the one config object shared by
generation, labeling, calibration, and (eventually) the CLI's default
flags.

#### `load_config(path="config.yaml") -> CodeGateConfig`
**Does:** Loads and validates `config.yaml`: raises if the adjudicator
also appears in the generators list (role-reuse — an adjudicator judging
its own generated code would bias the label toward self-preference), and
raises if `split_ratios` doesn't sum to 1.0.
**Talks to:** Called by `scripts/run_real.py::main` and
`scripts/run_pipeline_dry_run.py`. Reads `config.yaml` via `PyYAML`.
**Tech:** `PyYAML`, `pathlib`.
**Fits in:** OFFLINE entry point today; will also back Phase 3's
`codegate calibrate` CLI command.

### `env.py`

#### `_ensure_env_loaded() -> None`
**Does:** Loads `.env` from the repo root exactly once per process
(module-level `_loaded` flag), no-op if the file is absent.
**Talks to:** Called internally by `get_env` and `require_env`.
**Tech:** `python-dotenv`.
**Fits in:** Both halves — whichever process needs an API key or the
Ollama base URL.

#### `get_env(name, default) -> str`
**Does:** Returns an environment variable, falling back to `default` if
unset/empty — for settings that have a sensible default (e.g.
`OLLAMA_BASE_URL`).
**Talks to:** Called by `scripts/run_real.py::main` for `OLLAMA_BASE_URL`.
**Tech:** stdlib `os`.
**Fits in:** OFFLINE — optional-setting lookup.

#### `require_env(name) -> str`
**Does:** Same as `get_env`, but raises a `RuntimeError` with an
actionable message (pointing at `.env.example` / setup docs) instead of
returning a default, for settings with no safe fallback (API keys).
**Talks to:** Not currently called on the all-Ollama path (no keys
required); will be used by Phase 6's verifier when a key-requiring backend
is selected.
**Tech:** stdlib `os`.
**Fits in:** Both halves — the hard-failure path for missing secrets.

### `schemas.py`

#### `SchemaError(ValueError)`
**Does:** Raised on schema validation failure.
**Talks to:** Raised by `validate_dataframe`.
**Fits in:** Both halves.

#### `validate_dataframe(df, schema_name) -> None`
**Does:** Checks a DataFrame against a named schema in the module-level
`SCHEMAS` dict (`generations`, `labeled`, `scores`): missing columns, extra
columns, and dtype mismatches (with bool/int/float family tolerance).
Raises `SchemaError` listing every problem found, not just the first.
**Talks to:** Called by `research/pipeline.py::run_full_pipeline`
immediately after generation, before anything downstream trusts the
DataFrame's shape.
**Tech:** `pandas`.
**Fits in:** OFFLINE today; the same schemas will gate ONLINE ingest
output once Phase 4 exists.

### `scripts/run_real.py`

#### `preflight(base_url, wanted_models) -> None`
**Does:** Hits Ollama's `/api/tags` before any generation work starts.
Distinguishes `ConnectTimeout` (likely a firewall) from `ConnectionError`
(likely `OLLAMA_HOST` not rebound / Ollama not relaunched) with different
actionable error messages, and separately checks that every model named
in `wanted_models` (tolerating a bare-name match against any tag) is
actually present, naming the exact missing model and the `ollama pull`
command to fix it.
**Talks to:** Calls the Ollama HTTP API directly. Called once by `main`,
before any generation begins — "fail fast and legibly" per its own
docstring, rather than dying hours into an unattended run.
**Tech:** `requests`.
**Fits in:** OFFLINE — the entry check for Track A's unattended run.

#### `build_backends(cfg, base_url) -> dict[str, Backend]`
**Does:** Maps every generator name in `cfg.generators` to an
`OllamaBackend` pointed at the same `base_url` — all four configured
generators are served by one Ollama host.
**Talks to:** Calls `OllamaBackend.__init__`. Called by `main`.
**Tech:** none beyond construction.
**Fits in:** OFFLINE — backend wiring for the all-Ollama generation run.

#### `main() -> int`
**Does:** CLI entry point. Parses args (`--out-dir`, `--config`, `--limit`,
`--base-url`, `--skip-preflight`, `--generate-only`), loads config, runs
`preflight` (unless skipped), loads the prompt bank, builds backends. On
`--generate-only`: calls `run_generation` directly and stops — never
imports or calls anything from the labeling/oracle path, and exits with an
actionable message if every generation failed. Otherwise: calls
`run_full_pipeline` (the full generate → label → rank → calibrate path)
and prints the summary.
**Talks to:** Calls `load_config`, `get_env`, `preflight`,
`load_prompt_bank`, `build_backends`, `run_generation` (generate-only
path) or `run_full_pipeline` (full path), `validate_dataframe`.
**Tech:** stdlib `argparse`.
**Fits in:** OFFLINE — the script a teammate's machine (Track A) or the
research machine actually invokes.

---

## `research/artifacts.py` — persistence (Phase 2)

The layer that gets the trained model and its certificate onto disk
together, so the tool can run without recalibrating from scratch every
time.

#### `Calibration` (frozen dataclass)
**Does:** The certificate, as persisted: `t_hat`, `alpha`, `delta`,
`n_vuln_calib`, `ranker_id` (which model this was calibrated against),
`corpus_version`, `is_provisional` (G1's honesty flag — see
`ENGINEERING_LOG.md` §6), `created_at`.
**Talks to:** Constructed by `save_calibration`; returned by
`load_calibration`/`load_artifacts`. Will be read by `codegate info`
(Phase 3) and the PDF cover banner (Phase 7).
**Tech:** stdlib `dataclasses`.
**Fits in:** the persisted bridge between OFFLINE calibration and ONLINE
scanning.

#### `ArtifactVersionError(ValueError)`
**Does:** Raised when a loaded calibration's `ranker_id` doesn't match the
loaded model's — the version guard.
**Talks to:** Raised only by `load_artifacts`.
**Fits in:** guards the OFFLINE→ONLINE handoff.

#### `save_model(ranker, path) -> None` / `load_model(path) -> R2Ranker`
**Does:** `joblib.dump`/`joblib.load` for an `R2Ranker`, to/from
`model.joblib`. `load_model` raises a clear `FileNotFoundError` (pointing
at `codegate calibrate`) if the file is absent, and `TypeError` if the
file doesn't contain an `R2Ranker`.
**Talks to:** `save_model` is called by
`research/pipeline.py::run_full_pipeline` once a certified threshold
exists. `load_model` is called by `load_artifacts`.
**Tech:** `joblib`.
**Fits in:** OFFLINE writes it (training), ONLINE reads it (scanning,
once Phase 5 exists).

#### `save_calibration(result, path, corpus_version, is_provisional, ranker_id=R2Ranker.RANKER_ID) -> None` / `load_calibration(path) -> Calibration`
**Does:** Serializes an `LTTResult` plus provenance metadata to
`calibration.json` (pretty-printed) / reads it back. `ranker_id` defaults
to the active ranker's own `RANKER_ID` class attribute, so it can't drift
from what actually produced the scores.
**Talks to:** `save_calibration` is called by
`research/pipeline.py::run_full_pipeline` right after
`gate/ltt.py::calibrate_threshold` produces the operating-point
`LTTResult`. `load_calibration` is called by `load_artifacts`.
**Tech:** stdlib `json`, `datetime`.
**Fits in:** OFFLINE writes it, ONLINE reads it.

#### `load_artifacts(model_path, calibration_path) -> (R2Ranker, Calibration)`
**Does:** Loads both files and raises `ArtifactVersionError` if
`calibration.ranker_id != ranker.RANKER_ID` — the version guard named in
the plan ("refuse a calibration whose `ranker_id` ≠ the loaded model's").
This is the function anything that needs a *consistent* model+certificate
pair should call, rather than `load_model`/`load_calibration`
independently.
**Talks to:** Calls `load_model`, `load_calibration`. Will be called by
Phase 3's `codegate scan`/`codegate info`.
**Tech:** none beyond its two callees.
**Fits in:** the guarded ONLINE entry point for loading trained artifacts.

**How `is_provisional`/`corpus_version` get set today:** `run_full_pipeline`
derives both from its existing `is_simulated` flag —
`corpus_version = "simulated-v2" if is_simulated else "real-540"`,
`is_provisional = is_simulated` — rather than taking them as new
parameters, since `is_simulated` was already the caller's signal for
"is this real data." (`research/pipeline.py`, in the `n_vuln_calib > 0`
branch, right after the operating `LTTResult` is computed.)

---

## `cli.py` — command-line interface (Phase 3)

`typer` app, installed as the `codegate` console script
(`[project.scripts]` in `pyproject.toml`). Three subcommands.

#### `info(model_dir=DEFAULT_MODEL_DIR) -> None`
**Does:** Loads the model + calibration pair from `model_dir` (default
`data/model/`, the canonical location the repo commits its shipped
artifacts to) via `load_artifacts`, and prints a table: ranker ID, corpus
version, `t_hat`, certified alpha, confidence, calibration sample count,
creation timestamp. Prints a highlighted `PROVISIONAL` warning (pointing
at `docs/ENGINEERING_LOG.md` section 6) when `calib.is_provisional` is
true. Exits 1 with the raw exception message on a missing file or a
`ranker_id` mismatch — no swallowed errors.
**Talks to:** Calls `research/artifacts.py::load_artifacts`.
**Tech:** `typer`, `rich.table.Table`.
**Fits in:** ONLINE — the "what am I currently certifying" surface.

#### `calibrate(config, out_dir=DEFAULT_MODEL_DIR, real=False, base_url=None, limit=None) -> None`
**Does:** Loads config and the prompt bank, builds either
`SimulatedBackend`s (default — zero dependencies, matches "fresh clone
works with zero setup") or `OllamaBackend`s (`--real`, mirroring
`scripts/run_real.py`'s backend wiring), then calls
`run_full_pipeline`. Prints the resulting vulnerable rate, `t_hat`, and
coverage, and confirms where `model.joblib`/`calibration.json` were
written.
**Talks to:** Calls `load_config`, `load_prompt_bank`, `SimulatedBackend`/
`OllamaBackend`, `run_full_pipeline` (which internally calls
`save_model`/`save_calibration`). This is what produced the
`data/model/model.joblib` + `calibration.json` committed to the repo.
**Tech:** `typer`.
**Fits in:** OFFLINE — the CLI's entry point into the research pipeline;
this is "re-run the research path" from the CLI rather than a standalone
script.

#### `scan(path, format="terminal", output=None, no_llm=False, alpha=None, model_dir=DEFAULT_MODEL_DIR, config=Path("config.yaml")) -> None` (Phase 7)
**Does:** The real scan command. Validates `--format` (exit 1 if
invalid) and rejects `--alpha` outright (exit 2, with an explanation --
see `report/`'s Phase 7 entry below for why an override can't just be
applied post hoc). Unless `--no-llm`, tries to load `config.yaml` for
`cfg.verifier` and build a verifier backend via
`scan/verifier.py::build_verifier_backend` -- a missing `config.yaml`
degrades to no LLM verification rather than erroring, since a scan
target outside this repo won't have one. Calls
`scan/pipeline.py::run_scan`, then dispatches to the requested
formatter: `render_terminal` prints directly; `to_json`/`to_sarif` print
to stdout via plain `print()` (not `console.print()` -- see below) or
write to `--output`; `generate_pdf` always writes a file (`--output` or
`codegate_report.pdf`).
**Talks to:** Calls `load_config`, `scan/verifier.py::build_verifier_backend`,
`scan/pipeline.py::run_scan`, and one of
`report/terminal.py::render_terminal`, `report/json_sarif.py::to_json`/
`to_sarif`, `report/pdf.py::generate_pdf`.
**Tech:** `typer`.
**Fits in:** ONLINE -- the command this whole project is building toward,
now a real, tested, end-to-end scanner rather than a scaffold.

**A real bug caught only by running the actual CLI, not the test suite:**
`console.print(json_text)` looked correct and passed under `CliRunner`,
but against a real terminal `rich` line-wraps at terminal width and
parses `[...]` as markup -- both of which corrupt JSON. Fixed by using
plain `print()` for JSON/SARIF stdout output; `console.print` stays for
`terminal` format and for `Wrote <path>` status lines. See
`docs/ENGINEERING_LOG.md`'s Phase 7 entry for the second bug this same
hand-testing pass caught (a Unicode-ellipsis mojibake in
`report/terminal.py`'s findings table).

**Canonical artifact location established this phase:**
`data/model/model.joblib` + `data/model/calibration.json` -- not
gitignored (unlike `data/runs/*`), and now committed, so
`codegate info` works immediately on a fresh clone per the locked
decision in the original plan ("commit trained artifacts").

---

## `scan/ingest.py` — turning a path into scoreable units (Phase 4)

The first ONLINE-half module. Turns a file or directory into function-level
`Unit`s -- the atom every later scan stage (static pre-pass, ranking,
gating, verification) operates on.

#### `Unit` (frozen dataclass)
**Does:** One function: `file`, `lineno`, `end_lineno` (added in Phase 5
so a line-based finding — e.g. from semgrep — can be mapped back to the
unit whose range contains it), `func_name`, `source` (exact source text
via `ast.get_source_segment`), `content_hash` (sha256 of `source` —
drives Phase 6's verifier cache), `token_estimate` (chars/4 heuristic —
drives Phase 7's savings accounting).
**Talks to:** Constructed by `_ingest_files`. Consumed by
`scan/pipeline.py` (Phase 5) as the input to static/rank/gate, and will
be consumed by `scan/verifier.py` (Phase 6) keyed on `content_hash`.
**Tech:** stdlib `dataclasses`, `hashlib`.
**Fits in:** ONLINE — the unit of work for every later scan stage.

#### `SkippedFile` (frozen dataclass)
**Does:** One file that couldn't become units, with a human-readable
`reason` (unreadable / syntax error). Exists so a scan reports what it
couldn't look at, instead of silently shrinking its own coverage — the
same discipline as `LABEL_ABSTAIN` on the research side (see
`ENGINEERING_LOG.md` §3 Phase 1 item 2), applied to ingest.
**Talks to:** Constructed by `_ingest_files`; collected into
`IngestResult.skipped`. Will surface in Phase 7's report (a "skipped
files" appendix) rather than being silently discarded.
**Tech:** stdlib `dataclasses`.
**Fits in:** ONLINE — ingest failure reporting.

#### `IngestResult` (frozen dataclass)
**Does:** Carries `units: list[Unit]` and `skipped: list[SkippedFile]`
together, so a caller can never see one without the other.
**Talks to:** Returned by `ingest_path`.
**Fits in:** ONLINE.

#### `_load_gitignore_patterns(root) -> list[str]`
**Does:** Reads `root/.gitignore` if present; returns plain-name, glob,
and directory (`trailing '/'` stripped) patterns. Explicitly does not
support negation (`!pattern`) lines — skips them rather than
mishandling them, documented in the docstring as an intentional scope
limit rather than an oversight.
**Talks to:** Called once by `_ingest_directory`.
**Tech:** stdlib `pathlib`.
**Fits in:** ONLINE.

#### `_is_ignored(rel_path, patterns) -> bool`
**Does:** Checks a relative path against the loaded patterns —
per-path-component match and whole-relative-path match, both via
`fnmatch`.
**Talks to:** Called by `_ingest_directory` for every candidate `.py`
file.
**Tech:** stdlib `fnmatch`.
**Fits in:** ONLINE.

#### `_estimate_tokens(source) -> int`
**Does:** `max(1, len(source) // 4)` — the documented chars/4 heuristic
the plan calls for in place of a `tiktoken` dependency. Deliberately the
same estimator used on both sides of Phase 7's savings accounting, so the
comparison stays internally consistent even though it isn't an exact
token count.
**Talks to:** Called by `_ingest_files` for every unit.
**Fits in:** ONLINE — will be reused by `report/accounting.py` (Phase 7).

#### `_ingest_files(paths) -> IngestResult`
**Does:** For each path: reads it (catching `UnicodeDecodeError`/`OSError`
into a `SkippedFile`), `ast.parse`s it (catching `SyntaxError` into a
`SkippedFile`), then walks the tree collecting every
`FunctionDef`/`AsyncFunctionDef` node — including nested functions and
methods, each its own `Unit` — into `units`.
**Talks to:** Calls `ast.parse`, `ast.walk`, `ast.get_source_segment`.
Called by both `_ingest_directory` and `ingest_path` (single-file case).
**Tech:** stdlib `ast`, `hashlib`.
**Fits in:** ONLINE — the actual AST-to-units conversion.

#### `_ingest_directory(root) -> IngestResult`
**Does:** Recursively walks `root` for `*.py` files, skipping the fixed
non-source directory names (`venv`, `.venv`, `site-packages`, `.git`,
`__pycache__` — checked regardless of `.gitignore` content) and anything
`_is_ignored` against the loaded `.gitignore` patterns, then delegates to
`_ingest_files`.
**Talks to:** Calls `_load_gitignore_patterns`, `_is_ignored`,
`_ingest_files`.
**Tech:** `pathlib.Path.rglob`.
**Fits in:** ONLINE — directory-mode ingest.

#### `ingest_path(path) -> IngestResult`
**Does:** The public entry point. Dispatches to `_ingest_files([path])`
for a single file (skip-dir/`.gitignore` rules don't apply — the caller
named this file explicitly) or `_ingest_directory(path)` for a directory.
Raises `FileNotFoundError` for anything else.
**Talks to:** Will be called by `scan/pipeline.py` (Phase 5) and, through
it, by `cli.py::scan` once that command is implemented.
**Tech:** `pathlib`.
**Fits in:** ONLINE — `codegate scan <path>`'s first step.

**Verified against the repo's own `src/` tree**: 62 units, 0 skipped files
(command run this session).

---

## `scan/findings.py`, `scan/pipeline.py` — ingest → static → rank → gate (Phase 5)

The second ONLINE-half module pair. `findings.py` defines the one typed
record every scan-producing stage emits; `pipeline.py` wires the four
stages together into `run_scan`, the function `codegate scan` will
eventually call.

#### `Finding` (frozen dataclass, `scan/findings.py`)
**Does:** One reportable result: `file`, `line`, `func_name`, `cwe`,
`severity`, `source` (validated in `__post_init__` to be one of
`"semgrep"`, `"model"`, `"verifier"` — raises `ValueError` otherwise),
`confidence`, `message`, `fix_hint`. `source` is what makes Phase 7's
detection-attribution table (semgrep vs. model-escalated vs.
LLM-confirmed vs. auto-approved) possible — designed in now rather than
retrofitted later.
**Talks to:** Constructed by `scan/pipeline.py::_semgrep_findings` and
`_needs_review_finding` (`source="model"`), and by
`scan/verifier.py::to_finding` via `_resolve_escalated`
(`source="verifier"`, Phase 7). Consumed by every `report/` module.
**Tech:** stdlib `dataclasses`.
**Fits in:** ONLINE — the common currency of the whole scan pipeline.

#### `ScanResult` (frozen dataclass, `scan/pipeline.py`)
**Does:** The return value of `run_scan`: `findings: list[Finding]`,
`n_units`, `n_auto_approved`, `n_escalated`, `skipped: list[SkippedFile]`,
plus (Phase 7) `n_verified_confirmed/cleared/unresolved`,
`n_verifier_cache_hits`, `n_verifier_calls_made`, `tokens_saved`,
`tokens_spent`, and `calibration: Calibration | None` -- the certificate
this scan actually ran under. All Phase 7 fields default to `0`/`None`,
so `verifier=None` scans (Phase 5's original behavior) construct the
same `ScanResult` shape they always did.
**Talks to:** Returned by `run_scan`. Direct input to every `report/`
formatter: `report/terminal.py`, `report/json_sarif.py`,
`report/pdf.py` all read it, and `report/accounting.py::compute_cost_summary`
reads the token/call fields specifically.
**Fits in:** ONLINE.

#### `_base_rule_id(rule_id) -> str`
**Does:** Strips semgrep's path-derived namespace prefix
(`data.semgrep_rules.codegate-sqli-string-build` →
`codegate-sqli-string-build`) that appears when the ruleset is loaded
from a local file rather than the registry. Safe because this project's
own rule ids use hyphens, never dots, so the segment after the last `.`
always recovers the id exactly as written in `codegate_rules.yaml`,
regardless of the caller's working directory.
**Talks to:** Called by `_semgrep_findings` before the `_RULE_ID_TO_CWE`
lookup.
**Tech:** stdlib string method (`str.rsplit`).
**Fits in:** ONLINE — a semgrep-output-shape adapter.

#### `_map_to_unit(units, file, line) -> Unit | None`
**Does:** Finds which ingested `Unit` a semgrep finding's `(file, line)`
falls inside — resolves both paths for a reliable comparison, then among
all units whose range contains `line`, picks the one with the smallest
`end_lineno - lineno` (the innermost, most specific match, since nested
functions' ranges overlap their enclosing function's). Returns `None` if
no unit contains the line (e.g. module-level code).
**Talks to:** Called by `_semgrep_findings` for every raw semgrep hit.
**Tech:** stdlib `pathlib.Path.resolve`.
**Fits in:** ONLINE — attributes a static finding to a function.

#### `_semgrep_findings(target, units) -> list[Finding]`
**Does:** Runs `run_semgrep_on_path(target)` once, then turns each raw
hit into a `Finding` with `source="semgrep"`, `confidence=1.0`
(deterministic pattern match — no gate applies), and a short hardcoded
`fix_hint` from `_SHORT_FIX_HINT`. Drops any finding whose base rule id
isn't in `_RULE_ID_TO_CWE` — a ruleset/pipeline drift bug (someone added
a semgrep rule without updating the map), not a property of the scanned
code, so it's silently excluded here but would be caught immediately by
any test that adds a rule without updating the map.
**Talks to:** Calls `oracles/semgrep_oracle.py::run_semgrep_on_path`,
`_base_rule_id`, `_map_to_unit`. Called by `run_scan`.
**Fits in:** ONLINE — the static pre-pass stage.

#### `_rank_and_gate(units, model_dir) -> tuple[list[tuple[Unit, float]], int, int, Calibration | None]`
**Does:** Loads `model.joblib` + `calibration.json` via
`research/artifacts.py::load_artifacts`, scores every unit with
`R2Ranker.score`, then applies the certified gate: `score >= t_hat` →
auto-approved (no `Finding` emitted here — the certificate is what
stands behind that unit's safety, not a report line); otherwise
returned as an escalated `(unit, score)` pair for the caller to decide
what happens next. `calib.t_hat is None` (uncertified) escalates every
unit. Also returns the auto-approved units' summed `token_estimate`
(Phase 7's savings baseline) and the loaded `Calibration` itself (`None`
for an empty `units` list, since nothing gets loaded in that case) so
the report can render the certificate the scan actually ran under.
Returns `([], 0, 0, None)` immediately for an empty unit list. **Changed
in Phase 7**: previously built the "needs review" `Finding` directly and
returned `n_escalated` as a bare count; now returns the raw
`(unit, score)` pairs so `_resolve_escalated` (Phase 7) can attempt LLM
verification before any `Finding` is constructed.
**Talks to:** Calls `research/artifacts.py::load_artifacts`,
`ranker/r2_embedding_lr.py::R2Ranker.score`. Called by `run_scan`. Its
`FileNotFoundError` (no trained model) propagates up with
`"codegate calibrate"` in the message — the same actionable-error pattern
as `cli.py::info`.
**Tech:** `pandas.DataFrame` (the ranker's expected input shape).
**Fits in:** ONLINE — the rank + gate stages, and the only place
`model.joblib`/`calibration.json` are read from the scan side.

#### `_needs_review_finding(unit, score) -> Finding` (Phase 7)
**Does:** Builds the `source="model"`, `cwe="UNSPECIFIED"`,
`severity="REVIEW"`, `confidence=1-score` finding for an escalated unit
that the verifier either wasn't asked about (no backend) or couldn't
resolve. This is the exact `Finding` Phase 5 used to build inline inside
`_rank_and_gate`; factored out so both the no-verifier and
verifier-but-unresolved paths in `_resolve_escalated` share one
implementation.
**Talks to:** Called by `_resolve_escalated`.
**Fits in:** ONLINE.

#### `_VerificationTally` (frozen dataclass, Phase 7)
**Does:** `_resolve_escalated`'s return shape: `findings`, `n_confirmed`,
`n_cleared`, `n_unresolved`, `n_cache_hits`, `n_calls_made`,
`tokens_saved`, `tokens_spent`. A named dataclass rather than an 8-tuple
so the call site (`run_scan`) reads by field name, not position.
**Talks to:** Constructed and returned by `_resolve_escalated`; unpacked
by `run_scan` to populate `ScanResult`.
**Fits in:** ONLINE.

#### `_resolve_escalated(escalated, verifier, cache_dir) -> _VerificationTally` (Phase 7)
**Does:** Attempts to resolve every `(unit, score)` pair from
`_rank_and_gate` with the verifier. `verifier=None` -> every unit falls
back to `_needs_review_finding`, all counts stay 0 -- bit-for-bit Phase
5's original behavior. Otherwise, per unit: checks
`scan/verifier.py::is_cached` first (for accounting), then calls
`verify_unit`. `None` result -> `_needs_review_finding` (unresolved).
`result.vulnerable` -> `scan/verifier.py::to_finding` (confirmed, tagged
`source="verifier"`). Otherwise -> no finding at all (cleared, same
convention as an auto-approved unit). Token accounting: a cache miss's
`unit.token_estimate` goes to `tokens_spent` (the API call itself costs
money regardless of whether the response parses); a cache hit's goes to
`tokens_saved`.
**Talks to:** Calls `scan/verifier.py::is_cached`, `verify_unit`,
`to_finding`, and this module's own `_needs_review_finding`. Called by
`run_scan`.
**Fits in:** ONLINE — the join point between Phase 5's gate and Phase
6's verifier, built when Phase 7 gave the result somewhere to go.

#### `run_scan(path, model_dir=DEFAULT_MODEL_DIR, verifier=None, cache_dir=DEFAULT_CACHE_DIR) -> ScanResult`
**Does:** The public entry point: `ingest_path(path)` →
`_semgrep_findings` → `_rank_and_gate` → `_resolve_escalated`, findings
from both stages merged and sorted by `(file, line)`. **Hard invariant,
stated in the docstring and proven by test:** nothing on this path
imports or calls `oracles/sandbox.py`, `sqli_oracle.py`, or
`cmdi_oracle.py` — those detonation oracles execute code specifically to
judge LLM-generated training samples under controlled conditions;
`run_scan` scans arbitrary user code, and executing it would be the
scanner exceeding its mandate. `verifier=None` (the default) reproduces
Phase 5's exact behavior byte-for-byte — every Phase 5 test still passes
unmodified after Phase 7's changes.
**Talks to:** Calls `scan/ingest.py::ingest_path`, `_semgrep_findings`,
`_rank_and_gate`, `_resolve_escalated`. Called by `cli.py::scan` (Phase 7).
**Fits in:** ONLINE — the whole scan pipeline in one call.

**Verified against the repo's own `src/` tree**: 104 units, 87
auto-approved, 17 escalated, 17 findings via the real installed
`codegate` CLI (`codegate scan src --no-llm` and all four `--format`
values), not just `run_scan` called directly — see
`docs/ENGINEERING_LOG.md`'s Phase 7 entry for what that hand-testing
caught that the unit suite didn't. Proven not to execute scanned code
via a sentinel-file test
(`tests/test_scan_pipeline.py::test_scan_never_executes_the_scanned_code`).

---

## `scan/verifier.py` — resolving escalated units with one LLM call each (Phase 6)

The third ONLINE-half module. Takes a unit the gate escalated (Phase 5's
`_rank_and_gate`) and asks an LLM for one structured verdict, cached so a
re-scan of unchanged code never re-asks.

#### `VerifierBackend` (Protocol)
**Does:** The minimal interface a verifier backend must satisfy:
`ask(code: str) -> str`, returning the raw completion text. Deliberately
not the research-side `Backend` ABC (`generate(Prompt, seed) -> str`) —
verification sends a real code snippet and expects a JSON verdict back,
not a generation task keyed on a `Prompt` object, so a separate,
narrower interface is honest about the different contract rather than
forcing an artificial `Prompt` into a scan context that has none.
**Talks to:** Implemented by `GroqVerifierBackend`; consumed by
`verify_unit`.
**Fits in:** ONLINE.

#### `VerifierResult` (frozen dataclass)
**Does:** One parsed verdict: `vulnerable`, `cwe` (one of the three
tracked CWEs or `None`), `line`, `reason`, `fix_hint`.
**Talks to:** Produced by `_parse_verdict`; consumed by `verify_unit`
(cache round-trip) and `to_finding`.
**Fits in:** ONLINE.

#### `GroqVerifierBackend.ask(code) -> str`
**Does:** Sends `code` as the user message (with a fixed system prompt
demanding strict-JSON-only output) to Groq's OpenAI-compatible chat
completions endpoint at `temperature=0`, returns the raw completion
text.
**Talks to:** Constructed by `build_verifier_backend`. Same request
shape as `research/generation/backends.py::GroqBackend` (same endpoint,
same bearer-auth header) — the HTTP pattern is shared even though the
interface isn't.
**Tech:** `requests`.
**Fits in:** ONLINE — the real (non-stub) verifier backend.

#### `build_verifier_backend(model) -> VerifierBackend | None`
**Does:** Reads `GROQ_API_KEY` via `env.py::get_env` (optional — absence
returns `None`, not an error). Maps `model` (a config.yaml role name
like `"llama-3.3-70b-groq"`) to the real Groq API model id via
`_GROQ_MODEL_IDS` before constructing `GroqVerifierBackend`.
**Talks to:** Calls `env.py::get_env`. Will be called by `cli.py::scan`
(Phase 7) to build the backend once per scan invocation, passing
`cfg.verifier` as `model`.
**Fits in:** ONLINE — degrade-without-keys entry point for verification,
same discipline as the rest of the project (`consensus.py`'s optional
adjudicator, `codegate info` on a missing model).

#### `_parse_verdict(raw) -> VerifierResult | None`
**Does:** Regex-extracts the first `{...}` block from `raw` (tolerating
prose wrapped around the JSON, which real LLMs frequently add despite
instructions not to), `json.loads`s it, and validates shape:
`vulnerable` must actually be a bool, `cwe` must be one of the three
tracked CWEs or gets coerced to `None`, `line` must be an int or becomes
`None`. Returns `None` — never raises — on any parse or shape failure.
**Talks to:** Called by `verify_unit`.
**Tech:** stdlib `re`, `json`.
**Fits in:** ONLINE — the untrusted-LLM-output boundary.

#### `_cache_path`, `_load_cached`, `_save_cache`
**Does:** The on-disk cache, one JSON file per `content_hash` under
`.codegate_cache/` (default; caller-overridable). `_load_cached` returns
`None` (not raise) on a missing or corrupt cache file, so a hand-edited
or partially-written cache entry degrades to "ask again," never crashes
a scan. `_save_cache` only ever gets called with an already-validated
`VerifierResult`.
**Talks to:** Called by `verify_unit`.
**Tech:** stdlib `json`, `pathlib`, `dataclasses.asdict`.
**Fits in:** ONLINE — the mechanism behind the project's "re-scanning
unchanged code costs zero calls" claim (`report/accounting.py`, Phase 7,
reads cache hits vs. fresh calls for the savings estimate).

#### `is_cached(content_hash, cache_dir=DEFAULT_CACHE_DIR) -> bool` (Phase 7)
**Does:** Whether `verify_unit` would resolve this `content_hash`
without a fresh LLM call -- a thin wrapper over `_cache_path(...).exists()`.
Exposed as public API (not left as an internal `_` helper) specifically
so `scan/pipeline.py::_resolve_escalated` can count cache hits vs. fresh
calls for accounting without duplicating the cache's file-naming scheme.
**Talks to:** Called by `scan/pipeline.py::_resolve_escalated`, once per
escalated unit, immediately before `verify_unit`.
**Fits in:** ONLINE — the accounting-side complement to `verify_unit`'s
own internal cache check.

#### `verify_unit(unit, backend, cache_dir=DEFAULT_CACHE_DIR) -> VerifierResult | None`
**Does:** The public entry point: cache hit → return it, no call made;
no `backend` → `None`; backend call raises (`requests.RequestException`
or a malformed-response `KeyError`/`IndexError`/`ValueError`) → `None`;
response fails `_parse_verdict` → `None`, and nothing is cached; a valid
verdict is cached and returned. Every `None` path means "still needs
review" to the caller — never "confirmed safe."
**Talks to:** Calls `_load_cached`, `backend.ask`, `_parse_verdict`,
`_save_cache`. Called once per escalated unit by
`scan/pipeline.py::_resolve_escalated` (Phase 7).
**Fits in:** ONLINE — resolves what Phase 5's gate could only escalate.

#### `to_finding(unit, result) -> Finding`
**Does:** Turns a `VerifierResult` the caller has already confirmed is
`vulnerable` into a `Finding(source="verifier", confidence=1.0, ...)`,
falling back to `unit.lineno` when the verdict didn't include a line
number. Callers only call this for confirmed-vulnerable results — a
cleared unit produces no finding, mirroring how an auto-approved unit
(Phase 5) produces none either.
**Talks to:** Called by whichever Phase 7 code assembles the final
`ScanResult.findings` list from verifier output.
**Fits in:** ONLINE — the verifier's exit into the common `Finding`
currency the report (Phase 7) consumes.

**Verified:** `tests/test_verifier.py` (14 tests) against a stub
`VerifierBackend`, including a call-counting stub proving the second
`verify_unit` call on the same `content_hash` never touches the backend.
No live Groq call has been made yet — see `docs/ENGINEERING_LOG.md`,
Phase 6 entry, "needs integration testing."

---

## `report/` — turning a ScanResult into something a human reads (Phase 7)

Five modules, none containing any LLM-written prose. Every sentence in
every formatter is hand-written; every number traces back to a
`ScanResult` field or a documented constant.

### `report/remediation.py`

#### `Remediation` (frozen dataclass)
**Does:** `cwe`, `title`, `explanation`, `before` (vulnerable code
sample), `after` (fixed code sample).
**Talks to:** Constructed by `_REMEDIATIONS`/`_DEFAULT`; returned by
`get_remediation`.
**Fits in:** ONLINE.

#### `get_remediation(cwe) -> Remediation`
**Does:** Looks up the hardcoded remediation for `cwe` in `_REMEDIATIONS`
(one hand-written entry each for CWE-89, CWE-78, CWE-798 -- explanation
plus a before/after code pair). Falls back to `_DEFAULT` (a generic
"needs manual review" entry, no code samples) for `"UNSPECIFIED"` or any
other unrecognized value -- never raises, since every finding a report
lists needs a remediation section, confirmed or not.
**Talks to:** Called by `report/pdf.py::_findings_flowables` and
`report/json_sarif.py::to_sarif` (for its SARIF rule descriptions --
one source of truth for the CWE explanation text, not duplicated).
**Fits in:** ONLINE — the "no LLM writes remediation prose" guarantee,
concretely.

### `report/accounting.py`

#### `CostSummary` (frozen dataclass)
**Does:** `tokens_saved`, `tokens_spent`, `calls_avoided`, `calls_made`,
`estimated_cost_usd`, `price_per_million_tokens_usd`, `is_estimate`
(always `True` today -- a real field a renderer must read, not a
docstring note it could silently drop).
**Talks to:** Returned by `compute_cost_summary`; read by every `report/`
formatter's cost section.
**Fits in:** ONLINE.

#### `compute_cost_summary(result, verifier_model=None) -> CostSummary`
**Does:** Turns `ScanResult`'s raw counts into a priced summary.
`tokens_spent` = `result.tokens_spent` (the chars/4 estimate for
freshly-verified units, from `scan/pipeline.py::_resolve_escalated`)
plus a fixed 150-token system-prompt overhead per call actually made
(`result.n_verifier_calls_made`). `calls_avoided` = auto-approved +
cache hits. Price comes from `_PRICE_PER_MILLION_TOKENS_USD` (hand
-maintained, checked 2026-08-31), falling back to a default rather than
raising for an unrecognized model name.
**Talks to:** Reads `ScanResult` fields directly. Called by every
`report/` formatter that shows a cost figure.
**Tech:** plain dict lookup, no external pricing API.
**Fits in:** ONLINE — deliberately not live-priced, so a report stays
reproducible from the numbers it was generated with.

### `report/json_sarif.py`

#### `to_json(result, target, verifier_model=None) -> str`
**Does:** CodeGate's own JSON report shape (not a third-party schema):
`codegate_version`, `target`, `scanned_at`, a `summary` dict, a
`certificate` dict (or `null` when `result.calibration is None`), a
`cost` dict from `CostSummary`, the full `findings` list, and
`skipped_files`. `json.dumps(..., indent=2)`.
**Talks to:** Calls `report/accounting.py::compute_cost_summary`. Called
by `cli.py::scan` for `--format json`.
**Fits in:** ONLINE.

#### `to_sarif(result, target) -> str`
**Does:** SARIF 2.1.0 -- the format GitHub code scanning and most CI
security tooling consume. One `rules` entry per tracked CWE plus
`UNSPECIFIED`, descriptions pulled from `report/remediation.py::get_remediation`
so the explanation text has one source of truth. Each finding becomes a
`results` entry with `ruleId`, a `level` (`error`/`warning`/`note`,
mapped from `Finding.severity` via `_SARIF_LEVEL`, defaulting to
`"warning"` for anything unrecognized), a message, and a
`physicalLocation` using a POSIX-style relative path
(`Path(f.file).as_posix()`) and `max(f.line, 1)` as the start line.
**Talks to:** Calls `report/remediation.py::get_remediation`. Called by
`cli.py::scan` for `--format sarif`.
**Fits in:** ONLINE.

### `report/terminal.py`

#### `render_terminal(result, target, console, verifier_model=None) -> None`
**Does:** The default `codegate scan` output. Prints a summary table
(units/auto-approved/escalated/findings/skipped), a findings table (one
row per finding, every column `overflow="fold"` rather than rich's
default ellipsis truncation -- see the mojibake note in `cli.py::scan`'s
entry above), the certificate (if `result.calibration is not None`,
including the `PROVISIONAL` banner), and a one-line LLM
calls-made/avoided/estimated-cost summary.
**Talks to:** Calls `report/accounting.py::compute_cost_summary`. Called
by `cli.py::scan` for `--format terminal` (the default).
**Tech:** `rich.console.Console`, `rich.table.Table`.
**Fits in:** ONLINE.

### `report/pdf.py`

The major deliverable: a 7-section PDF (cover, executive summary,
detection attribution, cost & token accounting, findings detail,
coverage & certificate, methodology) with syntax-highlighted code
excerpts. Deterministic layout via reportlab Platypus flowables.

#### `_highlight(code) -> str`
**Does:** Lexes `code` with `pygments.lex(code, PythonLexer())` and
turns each token into reportlab Paragraph markup -- a restricted XML
subset (`<font color="...">`, `<br/>`), not full HTML, since that's what
`Paragraph` actually accepts. Maps a small hand-picked set of token-type
prefixes (Keyword, Name.Builtin, String, Number, Comment, Operator) to
hex colors via `_TOKEN_COLORS`; leading indentation is preserved as
`&nbsp;` runs since `Paragraph` collapses plain whitespace; text is
XML-escaped before wrapping.
**Talks to:** Called by `_findings_flowables` for both the finding
excerpt and each remediation's before/after samples.
**Tech:** `pygments.lex`, `pygments.token`, `xml.sax.saxutils.escape`.
**Fits in:** ONLINE.

#### `_read_excerpt(file, line, context=3) -> tuple[str, int]`
**Does:** Reads `file` from disk and returns the lines around `line`
(±`context`) plus the excerpt's first line number. Returns `("", 0)` --
never raises -- if the file can't be read, since the scanned source may
have moved or changed between the scan and the report render.
**Talks to:** Called by `_findings_flowables`.
**Fits in:** ONLINE -- the PDF-only reason `Finding`/`ScanResult` don't
need to carry source text themselves: the report reads it back from disk
at render time, in the same process, same invocation.

#### `_cover_flowables`, `_executive_summary_flowables`, `_attribution_flowables`, `_cost_flowables`, `_findings_flowables`, `_certificate_flowables`, `_methodology_flowables`
**Does:** One function per report section, each returning a list of
reportlab flowables (`Paragraph`, `Table`, `Spacer`, ...). Attribution
counts findings by `source`; cost renders `CostSummary` plus the
"these are estimates" disclaimer paragraph; findings detail combines
`_read_excerpt` + `_highlight` + `report/remediation.py::get_remediation`
per finding; certificate renders `result.calibration` (or a "nothing to
certify" message when `None`) plus the `PROVISIONAL` banner when
applicable; methodology is fully static hand-written text (scope,
threat model, CWE list).
**Talks to:** Called by `generate_pdf`, in document order.
**Fits in:** ONLINE.

#### `generate_pdf(result, target, output_path, verifier_model=None) -> Path`
**Does:** Builds the full flowable list from every section function
above and renders it via `reportlab.platypus.SimpleDocTemplate.build`.
Creates `output_path`'s parent directories if needed. Returns
`output_path`.
**Talks to:** Calls every `_*_flowables` function and
`report/accounting.py::compute_cost_summary`. Called by `cli.py::scan`
for `--format pdf`.
**Tech:** `reportlab.platypus`, `reportlab.lib`.
**Fits in:** ONLINE.

**Verified:** 42 new tests across `test_report_remediation.py` (3),
`test_report_accounting.py` (5), `test_report_json_sarif.py` (6),
`test_report_pdf.py` (10, including a real generated PDF's `%PDF-`
byte signature), `test_report_terminal.py` (4), plus 14 changed/added
tests in `test_scan_pipeline.py` and 6 in `test_cli.py`. Also hand
-verified against the repo's own `src/` tree via the real installed
`codegate` CLI across all four `--format` values, including opening and
visually inspecting the generated PDF -- see `docs/ENGINEERING_LOG.md`'s
Phase 7 entry for the two bugs that hand-testing caught and the unit
suite didn't.

---

## `examples/vulnerable_app/` — demo target (Phase 9)

Not library code, so no per-function entries here (per this doc's own
scope note above) -- see `examples/vulnerable_app/README.md` for the
full CWE/function table and `docs/ENGINEERING_LOG.md`'s Phase 9 entry
for what building it caught (a real `Paragraph`-escaping bug in
`report/pdf.py`, fixed the same session). Six files: `database.py`,
`system_tasks.py`, `config.py` (one vulnerable function + its direct
fix each, for CWE-89/78/798 respectively), `report_utils.py` (entirely
safe), `app.py` (ties them together), `README.md`. A generated
`sample_report.pdf` is committed alongside.

## Status

Every module through Phase 9 now has a section above. Only Phase 8
(retrain on the real corpus, once Track A lands) remains, and it
changes floats inside `data/model/model.joblib` and
`data/model/calibration.json`, not any function's signature or
behavior described in this document.
