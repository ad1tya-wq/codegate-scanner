# CodeGate — Team Briefing

Written to bring a teammate up to speed cold, for the Review 2 panel.
Split into three parts so three people can each own one section of the
explanation. Read your part fully before the panel; skim the other two
so you can field a question that strays outside your section.

---

# PART 1 — The Problem, the Novelty, the Solution

**Owner: whoever explains the "why."**

## The problem

AI code assistants (Copilot, Claude, ChatGPT, local coding models) write
a meaningful share of the code developers ship today, and multiple
published studies (Pearce et al., *Asleep at the Keyboard?*, IEEE S&P
2022; Fu et al., ACM TOSEM 2025) have measured that a real fraction of
that generated code contains classic security bugs: SQL injection,
command injection, hardcoded credentials, and more. The tools that exist
to catch this force a bad tradeoff:

- **Static analyzers** (semgrep, Bandit, CodeQL) are fast and free, but
  only catch the exact patterns their rules were written for. They never
  tell you what they *missed*.
- **LLM code review** is far more flexible, but calling a language model
  on every function in a codebase is slow and expensive, and that cost
  multiplies if you run it in CI on every commit.

Neither approach can answer the question that actually matters: *of the
code you did NOT flag, what fraction is still vulnerable?*

## What we are doing about it

CodeGate is a three-tier scanner: a deterministic static pass, then a
certified statistical gate, then an LLM verifier reserved only for the
code the gate cannot already vouch for. The static pass and the gate run
with zero API calls; the LLM is called only for the minority of code the
gate escalates, and even those calls are cached so re-scanning unchanged
code costs nothing.

## Where the novelty is

The gate is the actual contribution. It is built on **Learn-Then-Test
(LTT)**, a form of **conformal risk control** (Angelopoulos, Bates, et
al., ICLR 2024). Concretely: a lightweight ranker scores every function
from 0 to 1 (higher = safer), and a calibration procedure certifies the
most permissive auto-approval threshold `t_hat` such that the share of
*vulnerable* functions scoring above `t_hat` (the miss rate) is provably
below a chosen `alpha` (10% in the shipped model), with a chosen
confidence `1 - delta` (95%). This guarantee is **distribution-free and
finite-sample** — it does not assume the ranker is good. A bad ranker just
certifies a lower coverage (more gets escalated), never a false guarantee.
What it does assume is that the calibration data is representative.
We count each task once as evidence, because answers to the same task are
correlated; see Part 3 for why that mattered. That is
the property a normal "pick a threshold that looked good on a validation
set" approach does not have, and it is why we can say something no
competing tool says: not just "here are the bugs we found," but a
provable bound on what we didn't find among the code we auto-approved.

Nobody currently combines this specific triple: a certified statistical
gate, an LLM cascade for the escalated remainder, and an honest
disclosed flag (`is_provisional`) for when the underlying model itself
is not yet trustworthy. The closest related work (Du et al., ICSE 2026;
IRIS, arXiv 2024) pairs static analysis with an LLM to cut false
positives, but neither gives a formal bound on what's missed. Cascade
systems like FrugalGPT route cheap-to-expensive by a learned confidence
score, with no formal guarantee attached at all.

## The one-sentence pitch

*"CodeGate is a Python security scanner that mathematically proves how
much it might be missing, and only spends an LLM call on the code that
proof can't cover."*

---

# PART 2 — Implementation Walkthrough

**Owner: whoever explains the "how it's built."**

## Two halves, one contract

The codebase splits into an **offline research pipeline** (runs rarely,
trains the model) and an **online scanner** (runs constantly, never
executes anything it scans). They communicate through exactly two files:
`data/model/model.joblib` and `data/model/calibration.json`. Retraining
never changes a line of scanner code — only the floats inside those two
files.

## Phase-by-phase

**Phase 0 — Migration.** Carried the research half (`gate/`, `oracles/`,
`ranker/`, `research/`) from the old v1 repo into a fresh repo with
proper packaging. *Issue:* v1's `pyproject.toml` had no build system at
all — `pip install -e .` didn't work. Fixed by writing a real one.

**Phase 1 — Foundation fixes.** Four verified defects, most important:
the SQLi detonation harness only created a database table named
`users`, but the vulnerable-flavor prompt template generated queries
against a table named `t`. Every dynamic check errored, the oracle
abstained, and abstention was — at the time — silently coerced into
"safe." **Every vulnerable-flavor CWE-89 sample was mislabeled safe and
nobody could tell**, because there was no separate "abstained" state,
just "safe" or "vulnerable" — this alone dragged the corpus's measured
vulnerable rate down to 22.22% when the correct, by-design rate is
33.33%. Fixed by widening the fixture to create every plausible table
name, and by introducing `LABEL_ABSTAIN` as a real third value excluded
from training. This exact defect class (an oracle failure silently read
as "safe") recurred twice more later — see Phase 8.

**Phase 2 — Persistence.** `research/artifacts.py`: save/load the
trained model and its certificate together, with a version guard so a
model and a calibration file that don't match can't silently pair up.

**Phase 3 — Packaging + CLI.** `typer`-based CLI (`codegate info`,
`calibrate`, `scan`). Chosen because it gives real help text, validation
and tables from type hints with almost no boilerplate, versus hand
rolling the same with `argparse`.

**Phase 4 — Ingest.** `scan/ingest.py`: walks a directory, honors
`.gitignore`, and uses Python's `ast` module to pull out every function
(including nested functions and methods) as an independently-scoreable
unit. Function-level, not file-level, because the ranker is trained on
function-sized snippets — whole-file scoring would be out of
distribution.

**Phase 5 — Scan pipeline.** `scan/pipeline.py`: wires ingest, one
directory-scale `semgrep` pass (not one call per function, which
doesn't scale), the ranker, and the certified gate together. *Issue:*
semgrep prefixes rule IDs with a path-derived namespace when loaded
from a local ruleset file, which broke an exact-match lookup — fixed by
stripping to the last `.` segment.

**Phase 6 — LLM verifier.** `scan/verifier.py`: one JSON-structured call
to a Groq-hosted model per escalated unit, cached on disk by content
hash. *Issue, found live on 2026-09-02:* the originally-configured model
(`llama-3.3-70b-versatile`) had been silently removed from Groq's
catalog since the plan was written — every call 404'd. Diagnosed with a
direct `GET /models` call against the API, not guessed. Remapped to
`openai/gpt-oss-120b`.

**Phase 7 — Reporting + CLI wiring.** `report/`: terminal, JSON, SARIF
and PDF formatters (`reportlab` + `pygments`, chosen because they need
no external binary like `wkhtmltopdf`), all deterministic — no LLM
writes any report text. *Issue:* `rich`'s `console.print()` line-wraps
and markup-parses text, which corrupted JSON piped to stdout — fixed by
using plain `print()` for machine-readable formats.

**Phase 9 — Demo assets.** `examples/vulnerable_app/`: one vulnerable
function per tracked CWE, each paired with its own direct fix, plus
unrelated safe code. *Issue:* a `reportlab` XML-escaping bug meant a
module-level finding's function name (the literal string `"<module>"`)
was silently parsed as an invalid tag and dropped from the PDF. Fixed by
escaping every dynamic string before it reaches report text.

**Phase 8 — Retrain on real data.** Done on 2026-10-04, after a first
attempt certified nothing. See Part 3.

## Tech stack, briefly, and why

| Tool | Role | Why this one |
|---|---|---|
| `scikit-learn` (HashingVectorizer + LogisticRegression) | The ranker | Cheap and deterministic enough that LTT can evaluate the risk function at every candidate threshold during calibration without it being slow |
| `scipy.stats` | The actual statistics behind the certificate | Peer-reviewed, not hand-rolled — the guarantee is only as trustworthy as this math |
| Ollama (4 local code models) | Generates the training corpus | Free, local, no API key, and not safety-filtered against writing the deliberately vulnerable code the corpus needs; four different model families make the generator-shift test meaningful |
| `semgrep` (custom local ruleset) | Deterministic static pass | Community rule packs produced zero hits on our raw-stdlib patterns (verified empirically); a small hand-written ruleset targets exactly SQLi/cmdi/creds |
| Groq (`openai/gpt-oss-120b`) | LLM verifier host | Free tier, fast enough not to bottleneck a scan, OpenAI-compatible so swapping providers later is one new class |
| `reportlab` + `pygments` | PDF generation | Pure Python, no external binary dependency |
| `typer` + `rich` | CLI | Type-hint-driven, minimal boilerplate |
| GitHub Actions | CI | Free, runs the full suite plus a clean-install smoke test on every push |

---

# PART 3 — Current Status, Open Issues, Future Work, and What the Literature Taught Us

**Owner: whoever explains "where we actually are."**

## Current status

Every phase is built and tested: 435 automated tests, all passing
locally. CI runs on `main`, so it runs once this branch is merged. The
shipped model is now **trained and certified on real LLM-generated code**:

| | |
|---|---|
| Corpus | 2,040 samples: 510 prompts answered by each of 4 local models (qwen2.5-coder, deepseek-coder, codellama, codegemma) |
| Certificate | `t_hat = 0.8276` at α = 0.10, δ = 0.05, cluster-aware over 66 task groups; 49% of calibration code auto-approved. α = 0.05 is also certified (`--alpha 0.05`, 29% coverage) |
| Held-out check | 6.8% per task (8.4% per sample) of unseen vulnerable code auto-approved, against 10% |
| Ranker accuracy | ROC-AUC 0.891 on held-out data |
| Generator shift | Calibrated on 3 models, tested on the 4th (unseen data): 3 of 4 within 10%; codegemma 11.0%, not significant |
| Demo app | Catches every vulnerability (recall 1.00); precision 0.25 before the verifier |

## How we got here — the honest version

The first real corpus (516 samples, September) certified nothing: only 8
vulnerable samples reached the calibration split. The tempting reading
was "not enough data". **It was the labeller.** The detonation harnesses
called every function with a fixed number of arguments, so ~44% of
prompts could never be judged. The SQL oracle judged by row count, so it
labelled injectable DELETEs safe and safe `COUNT(*)` queries vulnerable.
The credentials oracle required high entropy, which rejects real
passwords like `hunter2`. Fixing those took the same 516 samples from 8
vulnerable calibration samples to 25, without generating anything new.

Then scale paid off. A 60-task-per-CWE prompt bank, a pilot run that
passed every quality gate, and a full run from the teammate's machine
produced the corpus. Reading the full corpus surfaced another round of
labeller problems, most importantly a credentials oracle still labelling
51 of 60 hardcoded secrets "safe". There was also a resume bug that had
reused 404 stale samples. Both are fixed. The corpus was then trimmed so
every model answered the same prompts: 206 vulnerable calibration samples,
and the threshold certifies. Full record: `docs/ENGINEERING_LOG.md` §12.

## The last problem we found, and how it was solved

**The standard certificate was optimistic for our data.** LTT's usual test
treats every calibration sample as independent. Ours cluster: the 206
vulnerable calibration samples come from 66 tasks, because four models
answered each one, and their scores correlate (0.57). That shrinks the
real evidence to roughly 94 independent samples. In simulation the
standard test then broke its own promise far more often than allowed,
and on our held-out data its threshold missed 13.1% against a 10% target.

The fix: **count each task once.** The cluster-aware certificate averages
each task's miss fraction and tests that with the Hoeffding–Bentkus bound
for bounded losses, the same bound the original LTT paper uses. In
simulation it kept its promise in every setting. On held-out data it
misses 6.8% per task (8.4% per sample), within 10%. It costs coverage:
49% of code is auto-approved instead of 56%.

## What's left

1. **More tasks, not more samples per task** — the task is the unit of
   evidence, so that is what buys coverage, and what would make α = 0.05
   practical (29% coverage today).
2. **Smaller items:** 32% of safe command-execution samples still can't be
   judged by the harness; the live verifier hasn't been re-measured on
   the real model; the Groq price table is still a placeholder; and
   semgrep misses one `%`-formatted SQL pattern split across a `with`
   block.

## Five things the literature actually shaped

1. **Angelopoulos et al., *Conformal Risk Control*, ICLR 2024.** This is
   where LTT itself comes from — the fixed-sequence hypothesis testing
   procedure that turns "pick a threshold" into "certify a threshold."
   Without this paper there is no statistical backbone to the project.

2. **Bates et al., *Distribution-Free, Risk-Controlling Prediction
   Sets*, J. ACM 2021.** The peer-reviewed foundation underneath LTT.
   What we took from it specifically: the guarantee holds regardless of
   the underlying model's quality, which is what let us build the
   scanner and demo it honestly *before* the real corpus was ready — a
   bad ranker degrades to lower coverage, never a false guarantee.

3. **Pearce et al., *Asleep at the Keyboard?*, IEEE S&P 2022.** This is
   the empirical justification for the whole project existing — the
   first large-scale, methodologically careful measurement that Copilot
   suggestions contain real CWEs at a non-trivial rate. Without a paper
   like this the motivation section is just an assertion.

4. **Du et al., *Reducing False Positives in Static Bug Detection with
   LLMs*, ICSE 2026.** The closest prior system to ours: pairs a static
   analyzer with an LLM to reduce false positives. Reading it closely is
   what let us state our novelty claim precisely — they reduce noise,
   we additionally certify a bound on what's missed. It also directly
   informed keeping the verifier's job narrow (confirm/clear one
   escalated unit) rather than trying to make it a general reviewer.

5. **Chen et al., *FrugalGPT*, arXiv 2023 / TMLR 2024.** The standard
   cheap-to-expensive LLM cascade paper. Reading this is what made us
   deliberately design the gate as a *certified* decision instead of a
   *learned confidence* decision — FrugalGPT's routing has no formal
   risk guarantee attached to it at all, which is exactly the gap our
   design closes.
