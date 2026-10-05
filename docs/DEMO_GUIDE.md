# CodeGate — Live Demo Guide

Written for the Review 2 panel demo. Keep this open on a second screen or
printed. Total demo time target: **8-10 minutes**.

## 1 · Before you walk in (do this now, once)

```bash
cd D:\CodeGateScanner
codegate info                                    # confirms install works, prints the certificate
```

If that prints a table with `Ranker: R2`, you're good. If it errors, run
`pip install -e .` again first.

**Warm the LLM verifier cache** so the live-verifier part of the demo is
fast, not waiting on a real API call in front of the panel:

```bash
codegate scan examples/vulnerable_app
```

Run this once now. It calls Groq for the 10 escalated units and caches
every result by content hash — the same command during the actual demo
will be instant (all cache hits, `llm calls made: 0`).

**Have a backup ready** in case live network/API access is flaky in the
room: `examples/vulnerable_app/sample_report.pdf` is already committed
and open-able with zero commands (generated from the shipped model with
`--no-llm`, so it shows the static + gate result, not verifier output). If anything about the live LLM call
fails during the demo, say so plainly and fall back to `--no-llm` or the
committed PDF — do not stall trying to debug it live.

Increase your terminal font size before you start. Nobody in the back
row can read 10pt.

## 2 · What to scan, and why

Use **`examples/vulnerable_app/`** — 6 small files, 14 functions, real
committed ground truth (each CWE appears once as a vulnerable function
sitting next to its own fix, plus unrelated safe functions). It runs in
seconds and the story it tells is clean: not "here's a wall of output,"
but "watch the tool tell vulnerable and safe code apart."

Do **not** scan the full `src/` tree live (104 units, more findings than
you can narrate in the time you have) or an external repo you haven't
tested beforehand (unpredictable timing, unpredictable questions).

## 3 · The demo script

Read the narration aloud roughly as written — it's timed to fit.

### Step 1 — the certificate (about 1 minute)

```bash
codegate info
```

*"CodeGate ships with a trained model and a certificate already
calibrated in the repo, so this runs with zero setup. The model was
trained on about two thousand code samples written by four real LLMs,
and every sample was labelled by actually running it against an attack.
This table is the statistical guarantee: averaged over coding tasks, at
most 10% of vulnerable functions score above this threshold and get
auto-approved, with 95% confidence. Each task counts once as evidence, however many models
answered it, so correlated answers can't inflate the guarantee. A stricter
5% threshold is also certified, if you want it."*

### Step 2 — static and certified gate only (about 2 minutes)

```bash
codegate scan examples/vulnerable_app --no-llm
```

*"This is semgrep plus our certified model gate, no LLM involved yet.
Semgrep deterministically catches all three real vulnerabilities: SQL
injection, command injection, hardcoded credentials. The gate
auto-approves the functions it can certify and escalates the rest. It
errs on the side of escalating: a safe function sent for review costs
one LLM call, while a vulnerable one waved through would break the
guarantee."*

Point at the summary table: `Auto-approved 4 / Escalated 10 / Findings 13`
(semgrep's 3 real findings plus the 10 functions escalated for review).
On a target this small the strict threshold escalates most functions;
that costs LLM calls, never misses.

### Step 3 — with the LLM verifier (about 2 minutes)

```bash
codegate scan examples/vulnerable_app
```

*"Same scan, verifier on. Every escalated unit gets one LLM call, cached
so a repeat scan costs nothing — that's why this just ran instantly,
we warmed the cache earlier. Watch what happens to those false
positives."*

Point out how many of the escalated functions the verifier clears.
**Rehearse this step once beforehand** (it also warms the cache) and
note the findings count and precision from your own run. This step has
not been re-measured since the real model shipped: on the earlier
simulated model the verifier took precision from 0.50 to 1.00, but don't
quote that figure for this model. To get the number, run
`python scripts/run_eval.py --with-llm` and read `data/eval/metrics.json`.

### Step 4 — the report (about 2 minutes)

```bash
codegate scan examples/vulnerable_app --format pdf --output demo_report.pdf
```

Open `demo_report.pdf`. Flip to the findings-detail page — point out the
syntax-highlighted excerpt and the hardcoded remediation text (no LLM
writes any of the report prose; it's deterministic). Mention the cost
accounting page: every dollar figure is explicitly labeled an estimate,
with the assumptions printed alongside it.

### Step 5 — if asked "did you test this on real code?" (have this ready)

*"Yes, and the shipped model is trained on it. Four local models each
answered the same 510 prompts, about two thousand samples in all. Every
sample was labelled by detonating it, not by pattern matching. Our first
real run failed to certify anything, and that turned out to be bugs in
our own labeller, not too little data. We fixed them, measured each fix
against data we already had, and the next run certified. We also held
out one model at a time: calibrated on three models, three of four held
on the fourth, and the fourth came in at 11% against 10%, within noise.
One more thing we found and fixed: four models answering the same task
give correlated answers, and the standard certificate counted them as
independent evidence, which made it optimistic. Ours counts each task
once, and on held-out data it stays within its 10% promise. Numbers are
in `docs/ENGINEERING_LOG.md` sections 12 and 13."*

This is a strong answer if asked directly — it shows the team tested
against reality, found and fixed real problems, and says plainly what
isn't finished yet.

## 4 · Numbers to have ready if asked

| Question | Answer |
|---|---|
| How many tests? | 442, all passing (CI runs on Python 3.11 and 3.13) |
| How many CWEs? | 3 — SQL injection, OS command injection, hardcoded credentials |
| Certified guarantee? | Averaged over tasks, at most 10% of vulnerable functions auto-approved, 95% confidence (α = 0.10, δ = 0.05), counting each task once; 5% also certified via `--alpha 0.05` |
| Does it hold on unseen data? | Yes: 9.3% per task of held-out vulnerable code auto-approved, against the 10% bound (10.7% pooled per sample, which is not the certified quantity) |
| Precision / recall without the verifier? | 0.27 / 1.00 on the demo app: catches every vulnerability, escalates most safe code |
| Precision with the verifier? | Not yet re-measured on the real model (was 1.00 on the simulated one) |
| Ranker accuracy? | ROC-AUC 0.903 on held-out data it never trained on |
| Real corpus size? | 2,040 samples: 510 prompts × 4 models (qwen2.5-coder, deepseek-coder, codellama, codegemma) |
| Real corpus abstention rate? | 5.6% (was 28.3% before the labeller fixes of section 12, 6.6% before the label audit of sections 14–15) |
| Does it generalize to a new model? | Calibrated on 3 models, tested on the 4th: 3 of 4 within 10%; codegemma 10.5% (10 of 95, not significant) |
| Cost per scan? | Estimated, disclosed as an estimate; demo app costs under $0.001 with the verifier on |

## 5 · If something breaks live

- **No internet / Groq unreachable:** add `--no-llm` to every command
  above. The static + certified gate story still works; just skip step 3's
  "precision improves" narrative or describe it verbally using the
  numbers table above instead of live-demonstrating it.
- **Terminal output looks garbled:** the `--format pdf` output is safer
  to project than the terminal table on an unfamiliar display/projector.
  Lean on step 4 more if step 2/3's terminal tables render oddly.
- **Any crash:** open the committed `examples/vulnerable_app/sample_report.pdf`
  directly and narrate from that instead of the live command. It's real
  output from this exact codebase, not a mockup.
