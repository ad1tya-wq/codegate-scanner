# CodeGate

**A certified-miss-rate security scanner for Python.** CodeGate escalates
code to an LLM only when it cannot mathematically prove the code is
safe — and it can tell you, with a real statistical guarantee, how often
it's wrong.

[![CI](https://github.com/ad1tya-wq/codegate-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ad1tya-wq/codegate-scanner/actions/workflows/ci.yml)

---

## Table of contents

- [What CodeGate is](#what-codegate-is)
- [How it works, technically](#how-it-works-technically)
- [Quickstart](#quickstart)
- [Try it: the demo app](#try-it-the-demo-app)
- [High-level design](#high-level-design)
- [The scan pipeline](#the-scan-pipeline)
- [Current metrics](#current-metrics)
- [Future improvements](#future-improvements)
- [Project context](#project-context)

---

## What CodeGate is

Most AI-assisted code scanners force a bad trade-off. Either they're pure
static analysis — fast and free, but they miss anything that isn't a
known pattern — or they send *every* function to an LLM, which is slow,
expensive, and still just a probabilistic guess dressed up as an answer.

CodeGate does neither. It runs a cheap, deterministic pre-pass over your
code first, and only calls an LLM for the functions it genuinely cannot
vouch for. The part it *doesn't* escalate isn't a guess either — it comes
with a real, provable guarantee: **"of the vulnerable functions it sees,
at most 10% get auto-approved, and we're 95% confident of that bound."** That
guarantee is computed statistically, not asserted, and it holds no
matter what the underlying model looks like inside.

The result: static-analysis speed and cost for the code that's obviously
fine, LLM-level judgment reserved for the code that actually needs it,
and a number at the end you can defend instead of a vibe.

## How it works, technically

The certificate comes from **Learn-Then-Test (LTT) conformal risk
control** — a distribution-free, finite-sample method for choosing a
decision threshold with a provable risk bound. Concretely:

1. A lightweight ranker (`HashingVectorizer` + `LogisticRegression`,
   trained on labeled code samples) scores every function `0–1`, where
   higher means *safer*.
2. LTT runs fixed-sequence hypothesis testing over candidate thresholds
   `t`, where the risk `R(t) = P(score ≥ t | vulnerable)` is monotone in
   `t`. It certifies the most permissive threshold `t̂` such that
   `P(R(t̂) ≤ α) ≥ 1 − δ` — i.e. the true miss-rate at that threshold is
   below `α` with confidence `1 − δ`.
3. Any function scoring `≥ t̂` is auto-approved under that certificate.
   Anything below it is **escalated** — either to an LLM verifier (one
   call, JSON-structured, cached by content hash) or, without a key, left
   as "needs review."

This means the certificate's validity doesn't depend on the ranker being
good — a bad ranker just certifies a lower coverage (more gets
escalated), never a false guarantee. What it does depend on is the
calibration samples being exchangeable draws (see the caveat under
[Current metrics](#current-metrics)). That's the actual point of using a
conformal method instead of just picking a threshold that "looks right"
on a validation set.

Three CWEs are tracked today: **CWE-89** (SQL injection), **CWE-78** (OS
command injection), **CWE-798** (hardcoded credentials) — chosen because
each has a reliable, automatable ground-truth signal (see
[Current metrics](#current-metrics)).

## Quickstart

```bash
git clone https://github.com/ad1tya-wq/codegate-scanner.git
cd codegate-scanner
pip install -e .
```

That's it — no Docker, no API key, no calibration run. The repo ships
with a pre-trained model and certificate at `data/model/`, so the tool
works immediately:

```bash
codegate info                              # what model/certificate is loaded
codegate scan path/to/your/project         # scan it (terminal output)
codegate scan path/to/your/project --format pdf --output report.pdf
codegate scan path/to/your/project --alpha 0.05   # any alpha the certificate covers
```

Want the LLM verifier for escalated findings? Get a free key at
[console.groq.com](https://console.groq.com), then:

```bash
echo "GROQ_API_KEY=your-key-here" >> .env
codegate scan path/to/your/project         # LLM verification now runs automatically
```

No key (or `--no-llm`)? The scanner still runs everything else and marks
escalated findings "needs review" instead of crashing or silently
skipping them.

## Try it: the demo app

[`examples/vulnerable_app/`](examples/vulnerable_app/) is a small,
intentionally mixed target: each tracked CWE appears once as a
vulnerable function, sitting right next to its own direct fix, plus a
handful of unrelated safe functions with no security pattern at all.
It exists specifically to show CodeGate *discriminating* — not just
flagging everything.

```bash
codegate scan examples/vulnerable_app --no-llm
```

A pre-generated `examples/vulnerable_app/sample_report.pdf` is committed
in that directory, so you can see the actual PDF output without running
anything.

## High-level design

The project has two halves that share one artifact pair and otherwise
never touch each other.

```mermaid
flowchart LR
    subgraph OFFLINE["OFFLINE — research (rare, ~hours)"]
        direction TB
        A[Prompts] --> B[LLM generators]
        B --> C[Detonation oracles<br/>label the output]
        C --> D[Train ranker]
        D --> E[Calibrate LTT threshold]
    end

    E -->|model.joblib +<br/>calibration.json| F

    subgraph ONLINE["ONLINE — scanner (constant, seconds)"]
        direction TB
        F[Your codebase] --> G[codegate scan]
    end

    style OFFLINE fill:#fff3cd,stroke:#c9a227
    style ONLINE fill:#d4edda,stroke:#2e7d32
```

**OFFLINE (research half, run rarely):** generates code from several
LLMs against a fixed prompt bank, labels each sample with *dynamic
detonation oracles* — the SQLi and cmdi oracles actually **execute** the
generated code in a sandbox and observe whether the exploit fires, which
is a stronger signal than any pattern match — trains the ranker, and
calibrates the LTT threshold. This is the only place in the whole
project that runs untrusted, LLM-generated code, and it's a deliberate,
contained choice (see
[docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md) for why that's safe).

**ONLINE (scanner half, run constantly):** takes the trained artifacts
as a fixed input and never executes anything it scans. This is the
`codegate` CLI everyone actually uses.

The two halves talk through exactly two files: `data/model/model.joblib`
and `data/model/calibration.json`. Retraining the offline half only ever
changes what's inside those two files — never a line of scanner code.

## The scan pipeline

```mermaid
flowchart TD
    A[File or directory] --> B["INGEST<br/>AST-walk into function-level units"]
    B --> C["STATIC<br/>one semgrep pass over the whole target"]
    C --> D["RANK<br/>score every unit 0-1"]
    D --> E{"score ≥ t̂ ?"}
    E -->|yes| F["AUTO-APPROVE<br/>0 LLM calls, under the certificate"]
    E -->|no| G["ESCALATE"]
    G --> H{"GROQ_API_KEY set<br/>and not --no-llm?"}
    H -->|yes| I["VERIFY<br/>1 LLM call, cached by content hash"]
    H -->|no| J["needs review"]
    I -->|confirmed| K["finding: source=verifier"]
    I -->|cleared| L["no finding"]
    I -->|unresolved| J
    C --> M["finding: source=semgrep"]

    F --> N["REPORT<br/>terminal / json / sarif / pdf"]
    J --> N
    K --> N
    M --> N
```

Every finding is tagged with where it came from
(`semgrep` / `model` / `verifier`), which is what makes the report's
detection-attribution breakdown possible — you can see exactly how many
findings were deterministic pattern matches versus how many needed the
certified model or an LLM call.

## Current metrics

Generated by [`scripts/run_eval.py`](scripts/run_eval.py) from what is in
`data/model/`: a model trained and calibrated on **real** LLM-generated
code (`corpus_version: real-2040-sym`, not provisional). Full numbers and
PNGs land in `data/eval/` (gitignored — regenerate locally with
`python scripts/run_eval.py --with-llm`).

| Metric | Result | What it means |
|---|---|---|
| Oracle accuracy on ground-truth fixtures | **6/6** | The three oracles (SQLi, cmdi, creds) agree with their textbook examples |
| Corpus size / vulnerable rate / abstentions | **2,040 / 26.9% / 6.7%** | Real code from 4 local models (qwen2.5-coder, deepseek-coder, codellama, codegemma), 510 prompts each; abstentions are samples no oracle could judge, excluded rather than counted as safe |
| Ranker separation (ROC-AUC), held-out test split | **0.891** | How well the score separates vulnerable from safe code the ranker never saw (0.926 including its training data) |
| Certified threshold | **t̂ = 0.7763 @ α = 0.10, δ = 0.05** | Of vulnerable functions, at most 10% score above this, with 95% confidence; 56% of calibration code clears it. α = 0.05 is also certified (t̂ = 0.8276) and available via `--alpha 0.05` |
| Generator shift (calibrate on 3 models, test on the 4th) | **held for all 4** | Realized miss rates 2.2–4.5% against α = 0.05 on the model left out |
| End-to-end scan vs. real ground truth, static + gate only | **precision 0.33, recall 1.00, F1 0.50** | Catches every real vulnerability in the demo app; escalates more safe functions than strictly needed, which costs LLM calls, not misses |
| End-to-end scan vs. real ground truth, **with LLM verifier** | *not yet re-run on the real model* | Was precision 1.00 / recall 1.00 on the earlier simulated model; needs a Groq key and live API calls to re-measure |

**Open caveat.** LTT's guarantee assumes the calibration samples are
independent draws. Here the 206 vulnerable calibration samples come from 67
prompts answered by four models, so they are correlated, and the
certificate is somewhat optimistic. On the held-out test split the realized
miss rate was 13.1% at α = 0.10 (not significant on its own, but in the
same direction). A cluster-aware certificate is planned on
[`feat/cluster-aware-certificate`](https://github.com/ad1tya-wq/codegate-scanner/blob/feat/cluster-aware-certificate/docs/cluster-aware-certificate/README.md);
details in `docs/ENGINEERING_LOG.md` §12.10–12.11.

## Future improvements

- **A cluster-aware certificate** whose guarantee survives correlated
  calibration samples (see the caveat above), so the headline α can
  return to 0.05 without qualification.
- **More task groups** — the independent unit is the prompt, not the
  sample, so certifying at α = 0.05 at prompt level needs at least 59
  vulnerable calibration prompts with zero misses (67 today, 3 missed).
- **Published cost/token accounting**, backed by real Groq pricing
  (currently a placeholder — see `report/accounting.py`) and real
  per-call token usage from the API's own `usage` field, not just the
  chars/4 estimate.
- **Better CWE-78 near-miss coverage** — 32% of safe command-execution
  samples still can't be judged, because they validate input in ways the
  harness can't satisfy (existing directories, base-directory checks).
- **Broaden CWE coverage** beyond the current three, each requiring its
  own reliable ground-truth signal (dynamic detonation where possible,
  same standard as CWE-89/78 today).

See [`docs/DESIGN_RATIONALE.md`](docs/DESIGN_RATIONALE.md) for the
tech-stack rationale, the hurdles that shaped these decisions, and a
harder look at the project's novelty claims.

## Project context

Built for BCSE 497J (Project 1) at VIT by Linga Nikhil Arya, Aditya
Sahu, and Peter Isaac, guided by Dr. Dega Nagaraju. See
[`docs/ENGINEERING_LOG.md`](docs/ENGINEERING_LOG.md) for the full,
evidence-cited build history, and
[`docs/FUNCTION_REFERENCE.md`](docs/FUNCTION_REFERENCE.md) for a
per-function technical reference of the entire codebase.
