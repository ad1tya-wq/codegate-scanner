# ProvEval-Py — Dataset Datasheet

Following the spirit of Gebru et al., "Datasheets for Datasets" (2018),
adapted to this project's scope. Status as of 2026-08-28: **the corpus
described here is the prompt bank and the pipeline that turns it into
labeled generations — the generations themselves are currently
SimulatedBackend output, not real LLM output.** This datasheet documents
what exists and is honest about what doesn't yet.

## Motivation

**For what purpose was the dataset created?** To provide a
provenance-labeled benchmark of AI-generated Python code, annotated with
per-CWE vulnerability labels and per-sample generating-model identity, so
that a certified auto-approval gate (Learn-Then-Test conformal risk
control) can be calibrated and its guarantee tested — including whether
that guarantee survives a switch in which model generated the code
(leave-one-generator-out shift). See
`docs/superpowers/specs/2026-08-28-codegate-design.md`.

**Who created it?** Built as part of BCSE 497J Project 1 (VIT), team:
Linga Nikhil Arya, Aditya Sahu, Peter Isaac; faculty guide Dr. Dega
Nagaraju. This datasheet and the pipeline that produces the dataset were
authored in an overnight autonomous session on 2026-08-28.

## Composition

**What do the instances represent?** Each instance is one Python code
snippet, generated in response to one prompt, from one generator, labeled
vulnerable/safe for one specific CWE.

**CWEs covered (3):** CWE-89 (SQL injection), CWE-78 (OS command
injection), CWE-798 (hardcoded credentials). Chosen because all three are
detectable from diff-local context and, critically, two of the three
(CWE-89, CWE-78) are **dynamically detonatable** — the labeling oracle can
execute a proof-of-concept payload and observe whether the injection
actually fires, rather than relying on static pattern-matching alone.

**Prompt structure:** Each of 45 task groups (15 per CWE) is authored as
three flavors sharing one underlying task:
- **vulnerable** — a task phrased to elicit the CWE's vulnerable pattern.
- **neutral** — an unrelated, always-safe task (a size/composition
  balance control, not a vulnerability-detection test case).
- **near_miss** — a task phrased to produce code that is *safe* but
  *shaped* like the vulnerable pattern (a parameterized query that still
  splices a whitelisted table name; `subprocess.run(shell=False)` with a
  list arg; a credential read from an environment variable with no
  fallback default). This is the corpus's central design decision: without
  near-miss items, a classifier can hit high accuracy by keying on
  superficial prompt phrasing rather than the actual vulnerability, and
  the benchmark would silently measure the prompt template instead of
  vulnerability detection.

**How many instances (currently)?** 45 task groups × 3 flavors = 135
prompts. Each prompt, multiplied by `samples_per_prompt` (3, per
`config.yaml`) and by however many generator backends are configured (4 in
`config.yaml`; all 4 are `SimulatedBackend` instances as of tonight — see
"Collection process") = up to 1,620 generation instances. This is ~25% of
the design target of 60 task groups/CWE (540 prompts) — see
`NEEDS_FROM_YOU.md` for the plan to close that gap; nothing about the
pipeline changes when it does, since the prompt bank is the only thing
that grows.

**Splits.** `train` / `calib` / `test`, assigned **per task group** (all
three flavors of one task group share one split) at prompt-authoring time
in `data/prompts/*.yaml`, never re-derived downstream. This is the
leakage control: a classifier or the calibration procedure never sees two
flavors of the same underlying task on both sides of a split boundary.
Current distribution: 18/15/12 task groups (40%/33%/27%), matching
`config.yaml`'s target 40/30/30 ratio.

## Collection process

**How was the data associated with each instance acquired?** Prompts:
hand-authored (not mined or scraped), per the pattern above, informed by
Pearce et al.'s "Asleep at the Keyboard?" CWE taxonomy and by
`SecurityEval`'s existing prompt-corpus methodology as a starting
reference point (not reused verbatim — this corpus is original content).
Generated code: produced by calling a `Backend.generate(prompt, seed)`
interface (`src/codegate/generation/backends.py`).

**Which backend produced tonight's instances?** `SimulatedBackend` — a
deterministic, offline, zero-network code generator that emits
syntactically valid Python following the CWE/flavor-appropriate pattern
from a small hand-written template table, with randomized but
seed-reproducible variable/function naming. **This is not real LLM
output** and must not be reported as such. It exists to let the entire
pipeline (generation → labeling → ranking → calibration → evaluation) be
built, tested, and run end-to-end before real API access is available.
Real backends (`OllamaBackend`, `OpenRouterBackend`, `GroqBackend`,
`GeminiBackend`) implement the identical interface and are wired into
`scripts/run_real.py` — see `NEEDS_FROM_YOU.md` for what's needed to
switch over (API keys, mainly).

**Timeframe.** Prompt authoring and pipeline construction: 2026-08-28.

## Preprocessing / labeling

**Labeling is multi-oracle, with dynamic evidence given priority over
static pattern-matching** (documented as "Consensus rule v1" in
`src/codegate/oracles/consensus.py`):

| CWE | Primary oracle | Method |
|---|---|---|
| CWE-89 | `oracles/sqli_oracle.py` | Injects a payload (`' OR '1'='1`) into an in-memory sqlite3 fixture via the generated function itself, and checks whether the returned row count widened beyond a legitimate single-row lookup — i.e., the injection *executed*, not merely "the code looks suspicious." |
| CWE-78 | `oracles/cmdi_oracle.py` | Injects a shell-metacharacter payload (`& echo pwned > <sentinel>`) and checks whether the sentinel file was actually created — again, executed evidence, not a pattern match. |
| CWE-798 | `oracles/creds_oracle.py` | Static only — no dynamic oracle is possible for "is this credential real." AST-based: a string literal assigned to, passed as, or defaulted for a variable/parameter whose name matches a secret-like pattern, above an entropy threshold, excluding known placeholder markers. |

A custom, offline semgrep ruleset (`data/semgrep_rules/codegate_rules.yaml`)
supplements these as a secondary signal and a fallback when the primary
oracle abstains (function not found, timeout). It was written after
verifying empirically that semgrep's free-tier community registry packs
(`p/python`, `p/security-audit`, `p/sql-injection`) produce **zero
findings** on this corpus's raw-stdlib `sqlite3`/`subprocess` code — those
packs mostly target framework code (SQLAlchemy/Django/Flask), which this
corpus deliberately does not use.

**The LLM adjudicator role (`gemini-flash` in `config.yaml`) is defined
but not yet exercised** — no Gemini API key was available tonight. When
active, it participates only as a fallback vote when the primary
dynamic/static oracle abstains, never as the sole labeler, and — per the
design's role-reuse guard — is never one of the code generators, so it
cannot rate its own output.

**Known label-quality caveats, stated plainly:**
- No manual/human-validated subsample has been labeled yet — Cohen's κ
  and a hand-audited noise-rate estimate (both called for in the design
  spec) are **not yet computed**. This is the single most important
  labeling-quality gap to close before any certified result is reported
  as final.
- The dynamic oracles' fixture-based validation (`tests/test_oracles.py`,
  `data/fixtures/*.py`) proves the oracle *mechanism* is correct against
  hand-written known-vulnerable/known-safe examples — it does not by
  itself prove label quality on *generated* code, which may exercise
  patterns the oracle wasn't designed around.

## Uses

**What other tasks could this dataset be used for?** The prompt bank
(independent of any specific generator's output) is reusable for any
study comparing code-generation safety across models on these 3 CWEs.

**Are there tasks for which the dataset should not be used?** Per the
project's threat-model scoping (spec §"threat model"), this dataset
supports **benign-setting** vulnerability-detection research only — it is
not designed for and should not be used to evaluate adversarial evasion
of a scanner, since prompts are not adversarially crafted against any
specific detector.

## Distribution

Not yet distributed outside the project repository
([github.com/ad1tya-wq/codegate](https://github.com/ad1tya-wq/codegate),
currently private). SecurityEval (MSR4P&S 2022) is credited as a
methodological reference for prompt-corpus structure; no content from it
is redistributed verbatim in this repo. License for this project's own
prompt content and code: not yet chosen — to be set before any public
release.

## Maintenance

Maintained as part of this repository; changes tracked via git history
and `PROGRESS.md`. No external contribution process yet.

## Known biases (stated, not hidden)

- **Simulated generator homogeneity.** Tonight's 4 "generators" are all
  the same `SimulatedBackend` class with different names/seeds, drawing
  from the same small template table — real cross-model variation
  (documented at length in the source literature this project cites, e.g.
  Pearce et al.) does not exist in tonight's data. The generator-shift
  experiment's mechanism was validated against this data (it correctly
  detected a certificate break in one trial — see `PROGRESS.md`), but the
  *result itself* is not a claim about real models and must not be
  reported as one.
- **Prompt-authoring bias.** All 135 prompts were hand-written by one
  contributor in one session; they reflect that person's mental model of
  "realistic" vulnerable/near-miss code shapes, not a sampled distribution
  of real-world tasks. The near-miss items in particular required judgment
  calls about what counts as "genuinely safe but suspicious-shaped," which
  is inherently somewhat subjective — this is exactly what the (not yet
  performed) manual validation pass is for.
- **CWE selection bias.** All 3 CWEs were chosen partly *because* they are
  easy to detect (2 of 3 dynamically). This is disclosed in the design
  spec as a deliberate scoping choice, not an accident — but it does mean
  this corpus is not representative of CWE difficulty in general; harder,
  interprocedural, or purely-static-only vulnerability classes are
  explicitly out of scope (see spec, "Cut permanently").
