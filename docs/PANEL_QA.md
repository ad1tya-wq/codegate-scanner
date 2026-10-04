# Panel Prep Q&A — CodeGate

Answers to the questions raised while prepping for the panel, grounded
directly in the source and in `docs/ENGINEERING_LOG.md`. Every number here
either comes from a file/line cited inline or from a command output already
logged in `ENGINEERING_LOG.md` — nothing is estimated for this document.

---

## Part 1 — The ranker, its training, and the real-Ollama run

### How is the ranker trained, and with what performance metrics?

The ranker is `R2Ranker` in
[`src/codegate/ranker/r2_embedding_lr.py`](../src/codegate/ranker/r2_embedding_lr.py).
It's deliberately simple:

1. **Features**: `HashingVectorizer(n_features=512, alternate_sign=False)` —
   a bag-of-tokens hash embedding of the function's source code, 512
   dimensions. No neural embedding model, no download, no GPU. The code
   itself flags the intended upgrade path: swapping `_embed()` to a real
   CodeBERT/UniXcoder embedding later changes nothing about the class's
   public interface or any downstream consumer — a deliberate, documented
   placeholder, not an oversight.
2. **Model**: `sklearn.linear_model.LogisticRegression(max_iter=1000,
   random_state=20260828)` — plain binary logistic regression, vulnerable=1
   vs safe=0. `random_state` comes from `config.yaml`'s top-level
   `random_seed: 20260828`, so a retrain on the same data reproduces the
   same model exactly.
3. **Score**: `predict_proba(X)[:, 0]` — the model's probability of class 0
   ("safe"), so higher score = safer. This is the convention the whole gate
   depends on: `codegate scan` auto-approves when `score >= t_hat`.
4. **Train/calibration split**: not a random `train_test_split`. Every
   prompt in `data/prompts/*.yaml` carries a fixed `split: train`,
   `split: calib`, or `split: test` tag at the *task-group* level
   ([`research/corpus/prompts.py:27`](../src/codegate/research/corpus/prompts.py)),
   carried through generation into `gen_df["split"]`
   ([`research/generation/harness.py:114`](../src/codegate/research/generation/harness.py)).
   `run_full_pipeline` fits the ranker only on `split == "train"` rows and
   calibrates LTT only on `split == "calib"` rows
   (`research/pipeline.py::run_full_pipeline`). The `test` split is used
   by neither and serves as held-out data for the ranker's accuracy
   (`scripts/run_eval.py`). This matters: the ranker never sees a
   calibration-set sample during training, which is what makes the
   calibration set a fair sample for LTT's guarantee (see Part 3).

   **The exact arithmetic** (verified against `data/prompts/*.yaml` and
   the shipped corpus): each of the 3 CWE files has 60 task groups,
   24 `train` / 24 `calib` / 12 `test`. 180 task groups × 3 flavors
   (vulnerable/neutral/near_miss) = **540 prompts**, × 4 generators ×
   1 sample/prompt = 2,160 planned samples. The shipped corpus is the
   **2,040** of those that all four models answered (510 prompts × 4, see
   below): 1,904 labelled after 136 abstentions, **206 vulnerable
   calibration samples** (`n_vuln_calib: 206` in the shipped
   `calibration.json`). The split is a property of the prompt, not of the
   run.

### On exactly what data was the shipped model trained — an important distinction

**Real LLM-generated code** since 2026-10-04: `corpus_version:
"real-2040-sym"`, `is_provisional: false`. Four local models
(`qwen2.5-coder:7b`, `deepseek-coder:6.7b`, `codellama:7b`,
`codegemma:7b-instruct`) each answered the same 510 prompts. Every sample
was labelled by the detonation oracles, and the ranker was trained on the
`train` split and calibrated on `calib`.

Before that, the shipped model came from `codegate calibrate` without
`--real`, which uses `SimulatedBackend`: **9 hand-written code templates**
(one per CWE × flavor) with only names randomized. That is why its
ROC-AUC read 1.0000 — 9 underlying shapes are trivially separable. It
was always disclosed as `simulated-v2` / provisional, and it is now
replaced.

**Performance — the shipped model** (`real-2040-sym`; `python
scripts/run_eval.py`, `docs/ENGINEERING_LOG.md` §12.10–12.11):

| Metric | Value |
|---|---|
| Corpus | 2,040 samples (510 prompts × 4 models); 6.7% abstained; 26.9% of decided samples vulnerable |
| Ranker ROC-AUC, held-out test split | **0.891** (0.926 including its own training data) |
| Certified `t_hat` (shipped operating point) | **0.7763 at α = 0.10, δ = 0.05**; 56.4% of calibration code auto-approved |
| Also certified | 0.8276 at α = 0.05 (48.9% coverage), via `codegate scan --alpha 0.05` |
| `n_vuln_calib` | 206 |
| Generator shift (calibrate on 3 models, test the 4th) | held for all 4 (realized 2.2–4.5% vs α = 0.05) |
| Oracle accuracy (fixtures) | 6/6 |
| Demo app, static + gate only | precision 0.33, recall 1.00 |
| Demo app, with the verifier | not yet re-measured on this model (simulated model: 1.00 / 1.00) |

**For comparison — the simulated model it replaced:** 540 samples,
ROC-AUC 1.0000 (memorized), `t_hat` 0.6613 at α = 0.05, demo-app precision
0.50 → 1.00 with the verifier. **And the first real attempt** (`real-540`,
2026-09-02): `t_hat = None` at every α, because only 8 vulnerable samples
reached calibration. Part 2 explains why that was the labeller, not the
data size.

### How is `t_hat` decided?

By `calibrate_threshold()` in
[`src/codegate/gate/ltt.py`](../src/codegate/gate/ltt.py) — see Part 3 for
the plain-language explanation of *why* this procedure, but mechanically:

1. Take every unique score value among calibration-set samples as a
   candidate threshold, sorted from most conservative (highest score, fewest
   auto-approvals) to least conservative.
2. For each candidate `t`, count `k` = how many *vulnerable* calibration
   samples would still be auto-approved (`score >= t`).
3. Compute a p-value for "the true miss rate at this threshold is actually
   ≥ α" using the binomial CDF: `p = P(Binomial(n, alpha) <= k)`.
4. If `p <= delta`, this threshold is certified — record it as the current
   best `t_hat` and try the next, less-conservative threshold.
5. Stop at the **first** threshold that fails certification (fixed-sequence
   testing — this is what makes testing many thresholds statistically valid
   instead of p-hacking across them).
6. If nothing certifies — including the trivial "auto-approve nothing"
   starting point — `t_hat = None`, and the tool must say so, not guess.

### What exactly did your teammate run in Ollama, and what was the split?

He ran `python scripts/run_real.py --generate-only` against **his own
local Ollama install** — pure LLM inference against 4 models pulled onto
his machine, nothing shared, nothing executed from the network:

- `qwen2.5-coder:7b`
- `deepseek-coder:6.7b`
- `codellama:7b`
- `starcoder2:7b`

(all four defined in `config.yaml`'s `generators:` list). Target was
135 prompts × 4 generators × 1 sample/prompt = 540 generations; the actual
run produced **516** — `qwen2.5-coder:7b` and `deepseek-coder:6.7b` hit the
full 135 each, `codellama:7b` produced 134/135, and `starcoder2:7b`
produced only 112/135 (23 short), per
`data/runs/real_540/generations.parquet`'s own per-generator counts. The
run is checkpointed/resumable, so a dropped connection or a killed process
partway through doesn't restart from zero — the shortfall sits entirely on
`starcoder2:7b`, worth checking specifically if that model needs a rerun. The **same** `split: train` /
`split: calib` tags from the prompt bank applied — this is a property of
the prompt, not something recomputed per-run, so the real corpus split
exactly mirrors the simulated corpus's split by construction.

**The second run (2026-10-04), which the shipped model uses.** Same command,
with a 60-group-per-CWE prompt bank and `codegemma:7b-instruct` replacing
`starcoder2:7b`, which had produced zero vulnerable samples in 163
attempts. A 107-sample pilot passed every gate first
(`docs/PILOT_REVIEW.md`). The full run returned 2,156 of 2,160 samples.
Because it was written into the folder that held the September run, a
resume bug reused 404 September answers, 78 of them to prompts reworded
since. Those 78 were dropped and the resume code fixed. Then every prompt
not answered by all four models was dropped too, so each model is measured
on identical questions: **2,040 samples**.

### What was the exact prompt?

The raw `task` string from the prompt bank YAML, sent to Ollama verbatim —
no system prompt, no wrapper. `OllamaBackend.generate()`
([`backends.py:117-124`](../src/codegate/research/generation/backends.py))
posts `{"model": ..., "prompt": prompt.task, "stream": false, ...}`
directly to `/api/generate`. Real example — task `001`, CWE-89 vulnerable
flavor ([`data/prompts/sqli.yaml:5-8`](../data/prompts/sqli.yaml)):

> *"Write a Python function `get_user(conn, username)` that looks up a user
> row by username in a sqlite3 connection `conn` and returns the row.
> Build the SQL by directly formatting the username into the query
> string."*

Each of the 60 tasks per CWE has its own distinct `vulnerable` /
`neutral` / `near_miss` wording like this — genuinely different function
signatures and scenarios per task, not one template reused across all 60.
(This is the real-generator path only — `SimulatedBackend` ignores this
text entirely and draws from its own 9 fixed templates instead, see
above.)

### Why Ollama, specifically?

- **Zero cost, zero API key.** All four generators are open-weight models
  running entirely locally — no rate limits, no per-token billing, no
  dependency on a vendor's uptime for a run that takes hours.
- **No safety-filtered output.** The whole point of the corpus is to
  *deliberately* generate some vulnerable code (per prompt design, ~1/3 of
  flavors are `vulnerable`). A heavily safety-tuned commercial API is more
  likely to refuse or sanitize exactly the samples the experiment needs.
- **Small, code-specialized models are actually better here.** Per the
  project's own setup notes: smaller coder models tend to write more
  varied — and more genuinely vulnerable — code than a top-tier model would,
  which is what the labeling pipeline needs to have real signal to learn
  from.

### Why these 4 specific models, not 4 sizes of one model?

Because of `research/eval/shift.py::run_shift_experiment`
([source](../src/codegate/research/eval/shift.py)) — the project's
generator-shift stress test. It calibrates LTT on 3 generators pooled
together and then measures the *realized* risk on the 4th generator's data,
held out entirely from calibration. That's a genuine test of whether the
certificate survives a change in *who wrote the code*, not just sampling
noise within one model. The test is only meaningful if the 4 generators are
actually different model families — four size variants of one family
(e.g. `qwen2.5-coder:1.5b/7b/14b/32b`) wouldn't stress-test anything, since
they'd share the same underlying training data and code-writing habits.
`config.yaml`'s own comment states this directly: *"never reuse a model
across roles"* — each of the 4 has to be an independent witness for
`run_shift_experiment` to mean anything.

### How did the data get shared?

Originally the plan assumed both machines could share a LAN
(`OLLAMA_HOST` + firewall rule, documented in the original
`docs/OLLAMA_SETUP.md` draft). In practice **the two machines weren't on
the same network**, so that plan was abandoned mid-project for a strictly
safer, zero-networking design (commit `ba642e7`, *"rewrite Ollama guide for
host-runs-everything"*):

1. Teammate runs `run_real.py --generate-only` entirely on his own machine.
   **Deliberately stops after generation** — labeling runs the dynamic
   detonation oracles, which *execute* the generated code, and that must
   never happen on someone else's personal machine. Generation alone is
   pure model inference and touches nothing.
2. This produces one file: `data/runs/real_540/generations.parquet`. Since
   `data/runs/` is gitignored by default, sharing it required `git add -f`
   (documented explicitly in the guide as an easy step to silently skip).
3. He committed and pushed it to a `nikhil` branch (commit `a9bc464`,
   *"data: 516-sample real corpus from local Ollama run"*).
4. It was merged into `main` via a standard merge commit (`3230900`).

Labeling, ranker training, and calibration all then ran locally, on the
main machine, against that one committed parquet file — the only thing
that ever crossed between machines was generated code text, never
execution. The second run followed the same route: branches
`corpus/pilot` and `corpus/real-540` (the latter holding the 2,160-sample
run despite its name).

---

## Part 2 — Three main issues, current weakness, and the honest answer

### Three main issues (project-wide, not just this week)

**1. The SQL-injection label bug (Phase 1 — a labeling-correctness bug).**
The oracle's SQL fixture created a table named `users`; the CWE-89 prompt
templates emitted `SELECT * FROM t`. Every single SQLi-vulnerable-flavor
sample threw `no such table: t`, the oracle abstained, and abstention was
silently coerced to "safe" downstream. Net effect: the corpus's measured
vulnerable rate read 22.22% against a correct-by-design rate of 33.33%, and
nobody could see it was wrong just from looking at the numbers superficially.
**Found by**: refusing to trust the pipeline's own output and checking the
measured label distribution against the number the prompt design should
have produced — a mismatch that size doesn't happen by chance.
**Fixed by**: aligning the fixture's table name with the prompts, and more
importantly, introducing `LABEL_ABSTAIN` as an explicit third label state
so "the oracle couldn't tell" can never again be silently written down as
"safe."

**2. The sandbox process-tree hang (infrastructure-reliability bug, this
session).** A retraining run hung for 56+ minutes with no error, no output,
no crash. **Found by**: not waiting it out — pulling actual OS-level
process telemetry (`tasklist`, `wmic ... get ProcessId,KernelModeTime`) to
check whether the process was actually doing CPU work or just stuck.
Root cause: `subprocess.run(timeout=...)` on Windows kills only the direct
child process, not any grandchild it spawns — one sandboxed script that
itself spawned a long-running subprocess would hang forever past the
configured timeout. **Fixed by**: switching to `Popen` +
`CREATE_NEW_PROCESS_GROUP` and killing the whole process tree with
`taskkill /F /T /PID` on timeout, proven with a regression test that
spawns a grandchild sleeping 30s and asserts the whole call still returns
in under 15s.

**3. The markdown-extraction gap — only visible once real (non-simulated)
data ran through the pipeline.** Real chat-style Ollama models wrap
generated code in ` ```python ` fences with prose narration around it; the
simulated corpus's backend never produced this, so nothing downstream ever
needed to strip it. Running the actual real-540 corpus through immediately
spiked the abstention rate to 28.3% (versus ~0% simulated). **Found by**:
treating an abnormally high abstention rate as a signal to investigate, not
noise to average away — the pipeline's own code prints a warning at exactly
this threshold for this reason. **Fixed by**: `extract_code()`, which pulls
the first code block containing an actual function definition out of
fenced/tagged/`<pre>`-wrapped completions, falling back to the raw string
unchanged when nothing qualifies (so it's a no-op on already-clean
simulated output — one code path, not a branch). The same real-data run
also surfaced a second, independent bug in the command-injection oracle's
detonation harness (a success marker printed unconditionally instead of
only inside the `try` block), which would have silently mislabeled a
genuinely vulnerable multi-parameter function as safe.

These three intentionally span three different *categories* of bug — a
labeling-correctness bug, an infrastructure-reliability bug, and a
pipeline-realism bug that only real data could expose — because that's an
honest answer to "how do you actually find bugs in an ML pipeline": you
check your own numbers against what they should be, you don't accept
silent hangs, and you don't trust a pipeline until you've run something
real through it, not just something you generated yourself.

### What's the main weakness right now?

**The certificate treats correlated samples as independent.** The 206
vulnerable calibration samples come from only 67 prompts, because four
models answered each prompt. LTT's binomial test assumes independent draws,
so the effective evidence is smaller than 206 and the certificate is
somewhat optimistic. On the held-out test split, the share of vulnerable
code auto-approved was 8.4% at α = 0.05 and 13.1% at α = 0.10. Neither is
significant on its own (P = 0.088 and 0.18), but both point the same way,
and most misses cluster in two credential tasks. That is why the shipped
operating point is α = 0.10, not 0.05, and why a cluster-aware certificate
is the next piece of work (branch `feat/cluster-aware-certificate`).

Two smaller ones:
1. 32% of the *safe* command-execution samples still can't be judged. Their
   input checks (an existing destination folder, a path under a base
   directory) reject every test value the harness can construct. They are
   excluded, not mislabelled, but they are exactly the hard negatives the
   ranker learns most from.
2. The live-verifier numbers have not been re-measured on the real model.

### Is the answer just "bigger dataset + better LLM"?

**No — and the project now has the evidence.** The first real corpus
(516 samples) certified nothing, and the obvious reading was "too small".
Re-labelling those *same* 516 samples with repaired oracles took the
vulnerable calibration count from 8 to 25 without generating a single new
sample. The labeller had been dropping or mislabelling a large share of the
data: fixed-arity harnesses, a row-count SQL check, an entropy gate on
passwords. Only after that did scale pay off: the 2,040-sample corpus,
labelled with the repaired oracles, gives 206. "Better LLM" helped in
one specific place: `starcoder2`, a base completion model, produced no
vulnerable code at all and was replaced. And the next limit isn't sample
count, it's independence: more *prompts*, not more samples per prompt.

---

## Part 3 — α, δ, and why Learn-Then-Test fits this problem

### What exactly are α and δ?

Both are set in `config.yaml`: **α = 0.10, δ = 0.05** (α was 0.05 until
2026-10-04, and 0.05 is still certified and available via `--alpha 0.05`;
see Part 2 for why the shipped point is 0.10).

- **α (alpha)** is the *risk bound itself* — the maximum acceptable miss
  rate. Formally, `R(t) = P(auto-approved | truly vulnerable)`: of all the
  genuinely vulnerable code that *could* be auto-approved at threshold
  `t`, what fraction actually is? CodeGate's certificate targets `R(t_hat)
  <= 0.10` — at most 1 in 10 vulnerable functions slips through
  auto-approval undetected (1 in 20 with `--alpha 0.05`).
- **δ (delta)** is *how confident the certificate itself is allowed to be
  wrong*. The full guarantee is `P(R(t_hat) <= alpha) >= 1 - delta` — with
  δ=0.05, there's at least 95% confidence that the α bound actually holds.
  δ is not about individual scans; it's about how often the *calibration
  procedure itself*, if repeated on fresh calibration data, would produce a
  threshold that fails to deliver on its promise.

In plain terms: α asks "how many bugs are we willing to risk missing,
percentage-wise?" — δ asks "how sure do we need to be that we're actually
hitting that number, and not just gotten lucky on this one calibration
batch?"

### Explaining LTT simply (for a non-ML audience — e.g. an IoT professor)

A useful framing that doesn't require any ML background:

> Imagine a factory quality-control line. A cheap sorting machine looks at
> every part and decides "pass" or "send to a human inspector." You want a
> *guarantee*: of all the defective parts that come down the line, no
> more than 10% get marked "pass" — and you want to be 95% sure that
> guarantee is real, not a lucky fluke from testing it on too few parts.
>
> You don't get that guarantee by trusting the machine's engineering, or by
> eyeballing a chart. You get it by taking a batch of parts you *already
> know the true answer for* (the calibration set), and asking, for a
> candidate cutoff score: "if the machine's real miss rate at this cutoff
> actually sat right at my 10% limit, how likely is it I'd see this few
> defects slip through in this specific batch just by chance?" If that
> chance is small enough, you trust the cutoff. You try the strictest
> cutoff first, then loosen it step by step, and the moment a cutoff fails
> that test, you stop — you don't get to keep trying looser cutoffs hoping
> one passes by chance, because that would quietly break the whole
> guarantee. That stopping rule is the entire trick that makes testing many
> cutoffs statistically honest instead of p-hacking.
>
> Learn-Then-Test is exactly this procedure, applied to a code scanner: the
> "parts" are functions, the "defect" is a real vulnerability, and the
> "sorting machine" is the ranker. The output isn't a confidence score —
> it's a *pass/fail certificate* on a specific number.

### Why LTT specifically fit this use case

- **Distribution-free / model-agnostic.** The guarantee doesn't depend on
  the ranker being any good, or even on what kind of model it is. A weak
  ranker just certifies a lower, less useful threshold (fewer things get
  auto-approved) — it never produces a *false* guarantee. This is exactly
  what let the team build and honestly demo the full scanner *before* real
  training data existed (Bates et al., J. ACM 2021 — see below). The one
  thing it does assume is that calibration samples are exchangeable draws.
  Correlated samples weaken it, which is the open issue in Part 2.
- **Finite-sample exact, not asymptotic.** The certificate is valid for the
  calibration sample size actually on hand — relevant here specifically,
  since this project never has millions of labeled samples. An
  asymptotic-only guarantee ("valid as n → ∞") would be worthless at
  n = 206.
- **Targets the actual metric that matters**, not a proxy. A security
  scanner's real risk is precisely "how many real bugs get silently waved
  through" — that's `R(t)` exactly, not accuracy, not AUC, not F1.
- **It can honestly say "not yet."** `t_hat = None` isn't a failure of the
  method — it's the method correctly refusing to manufacture a guarantee
  it can't back with evidence, which is exactly what happened with the
  first real corpus (Part 1). That refusal *is* the mechanism working as
  designed, and it's a genuinely rare property for a "security score" to
  have.

### What did we learn from the research papers?

Five papers that directly shaped design decisions, not just background
reading (full 23-source review in the Project I report,
§2.1):

1. **Angelopoulos et al., *Conformal Risk Control*, ICLR 2024.** This is
   where LTT itself comes from — the fixed-sequence hypothesis-testing
   procedure that turns "pick a threshold" into "certify a threshold."
   Without this paper there's no statistical backbone to the project at
   all.
2. **Bates et al., *Distribution-Free, Risk-Controlling Prediction Sets*,
   J. ACM 2021.** The peer-reviewed foundation underneath LTT. What we
   specifically took from it: the guarantee holds regardless of the
   underlying model's quality — which is exactly what let the team build
   and demo the scanner honestly *before* the real corpus was ready. A
   weak ranker degrades to lower coverage, never to a false guarantee.
3. **Pearce et al., *Asleep at the Keyboard?*, IEEE S&P 2022.** The
   empirical justification for the project existing at all — the first
   large-scale, methodologically careful measurement that Copilot-style
   suggestions contain real CWEs at a non-trivial rate. Without a paper
   like this, the motivation is just an assertion.
4. **Du et al., *Reducing False Positives in Static Bug Detection with
   LLMs*, ICSE 2026.** The closest prior system to CodeGate — pairs a
   static analyzer with an LLM to cut false positives. Reading it closely
   is what let the team state the novelty claim precisely: they reduce
   noise, CodeGate additionally certifies a formal bound on what's missed.
   It also directly shaped keeping the LLM verifier's job narrow
   (confirm/clear one already-escalated unit) rather than a general
   reviewer.
5. **Chen et al., *FrugalGPT*, arXiv 2023 / TMLR 2024.** The standard
   cheap-to-expensive LLM cascade paper. Reading this is what made the team
   deliberately design the gate as a *certified* decision instead of a
   *learned confidence* decision — FrugalGPT's routing has no formal risk
   guarantee attached to it at all, which is precisely the gap CodeGate's
   design closes.

---

## Part 4 — Cost/token accounting and how every PDF number is calculated

### How is money/tokens saved calculated?

All in
[`src/codegate/report/accounting.py`](../src/codegate/report/accounting.py),
fed by counters from
[`src/codegate/scan/pipeline.py`](../src/codegate/scan/pipeline.py). No
`tiktoken` dependency — every token count is an estimate, and the code
says so explicitly (`is_estimate: bool` is a real field on `CostSummary`,
not a docstring note, specifically so a report renderer can't forget to
disclose it).

1. **Per-unit token estimate**: at ingest time, every function gets
   `token_estimate = max(1, len(source_code) // 4)` — a documented
   chars/4 heuristic ([`scan/ingest.py:77-81`](../src/codegate/scan/ingest.py)),
   applied consistently on both sides of the savings calculation.
2. **Tokens saved** = the token estimate of every **auto-approved** unit
   (never sent to the LLM at all) **plus** the token estimate of every
   **escalated-but-cache-hit** unit (resolved from a previous identical
   scan, no fresh call needed).
3. **Tokens spent** = the token estimate of every escalated unit that
   *did* get a fresh LLM call this run, **plus a fixed 150-token overhead
   per actual call made** (not per unit) — accounting for the constant
   system prompt sent with every fresh request
   (`_SYSTEM_PROMPT_TOKEN_OVERHEAD = 150`).
4. **Estimated cost** = `tokens_spent × price_per_million / 1,000,000`.
   Price is a hardcoded lookup table, currently `$0.59` per million tokens
   for `openai/gpt-oss-120b` (the verifier's default model) — and the code
   explicitly flags this figure as carried over from a previous model, not
   independently verified against Groq's current published pricing.
   **If asked for a live number, say plainly it needs checking against
   `console.groq.com/docs/pricing` before being quoted as fact** — the
   code comment says exactly this.
5. **Calls avoided** = auto-approved units + cache hits. **Calls made** =
   actual fresh verifier calls this run.

Nothing here is presented as a measurement — every report explicitly
labels this section as an estimate, with the assumptions stated alongside
it, by design (this was a deliberate project principle from the start: an
unqualified cost claim is exactly the kind of unearned number the whole
project argues against).

### How is every other PDF/performance number calculated?

The PDF (`src/codegate/report/pdf.py`) is built from seven deterministic
sections, each a pure function of already-computed objects — **no LLM
writes any report prose, ever**:

| Section | Built from | Notes |
|---|---|---|
| Cover | `ScanResult`, target path, calibration's `corpus_version`/`is_provisional` | Prints the provisional banner if the certificate isn't final |
| Attribution | `ScanResult` counts by `source` (`semgrep` / `model` / `verifier`) | Every finding is tagged with exactly which stage caught it |
| Executive summary | `ScanResult` (findings by severity, auto-approved vs escalated counts) | |
| Cost & tokens | `CostSummary` (see above) | |
| Findings detail | `ScanResult.findings`, syntax-highlighted via `pygments`, remediation text from `report/remediation.py`'s **hardcoded per-CWE lookup table** (parameterized queries for CWE-89, `shell=False` + argv list for CWE-78, env vars for CWE-798) | Remediation text is fixed, hand-written prose keyed by CWE — never generated |
| Certificate | The `Calibration` object directly: `t_hat`, `alpha`, `delta`, `n_vuln_calib`, `coverage` | This is the literal object `research/artifacts.py` persisted after calibration — the PDF doesn't recompute anything, it renders what was already certified |
| Methodology | Static text — corpus version, label provenance, stated limitations (Python-only, 3 CWEs, intraprocedural, benign threat model) | |

**Every number traces back to one of two places**: a counter incremented
during the actual scan (`ScanResult`, `CostSummary`), or a value read
directly from `calibration.json` as written by the last real calibration
run. There is no separate "reporting math" layer that could drift from the
underlying pipeline — the report is a rendering of state that already
exists, not a recomputation.
