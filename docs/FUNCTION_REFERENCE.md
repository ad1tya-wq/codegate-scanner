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

#### `run_semgrep(code, ruleset_path=None) -> dict`
**Does:** Writes `code` to a temp file and invokes the `semgrep` CLI
against CodeGate's local custom ruleset (`data/semgrep_rules/codegate_rules.yaml`
— written in-house because the free community registry packs were
verified to produce zero findings against raw-stdlib `sqlite3`/`subprocess`
code; they target framework code like SQLAlchemy/Django/Flask). Returns
`{"hit": bool, "findings": [...]}` with each finding's rule ID and
severity. Degrades to `{"hit": False, "findings": [], "error": "..."}`
instead of raising if the semgrep binary is missing or the call times out,
so the pipeline can still run on a machine without semgrep installed.
**Talks to:** Called by `research/pipeline.py::label_row` (when
`use_semgrep_and_adjudicator=True`) and by
`ranker/r0_semgrep_score.py::score_r0`.
**Tech:** the `semgrep` CLI via `subprocess`, `json` for output parsing.
**Fits in:** OFFLINE today (per-sample, in the labeling/R0-scoring path).
Phase 5 will add a *second*, ONLINE use — one semgrep invocation over an
entire target directory, the fix for the per-row throughput problem this
module's own docstring on `r0_semgrep_score.py` flags.

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

## Not yet written

Phases 3–7 and 9 will each add a section here, in the same commit as the
code:

- **Phase 3** — `cli.py`: `codegate scan/info/calibrate`
- **Phase 4** — `scan/ingest.py`: directory walk → AST function-level units
- **Phase 5** — `scan/pipeline.py`, `scan/findings.py`: ingest → static →
  rank → gate wiring
- **Phase 6** — `scan/verifier.py`: escalation LLM call, content-hash cache
- **Phase 7** — `report/pdf.py`, `report/remediation.py`,
  `report/accounting.py`, `report/json_sarif.py`
- **Phase 9** — `examples/vulnerable_app/` (demo assets, not library code)
