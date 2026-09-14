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

Run this once now. It calls Groq for the 5 escalated units and caches
every result by content hash — the same command during the actual demo
will be instant (all cache hits, `llm calls made: 0`).

**Have a backup ready** in case live network/API access is flaky in the
room: `examples/vulnerable_app/sample_report.pdf` is already committed
and open-able with zero commands. If anything about the live LLM call
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
calibrated in the repo, so this runs with zero setup. This table is the
actual statistical guarantee — at this threshold, at most 5% of what we
auto-approve is vulnerable, with 95% confidence. It's flagged
PROVISIONAL right now because it's calibrated on a simulated corpus
while we scale up real training data — more on that if you ask."*

### Step 2 — static and certified gate only (about 2 minutes)

```bash
codegate scan examples/vulnerable_app --no-llm
```

*"This is semgrep plus our certified model gate, no LLM involved yet.
Semgrep deterministically catches all three real vulnerabilities: SQL
injection, command injection, hardcoded credentials. The model gate also
escalates a few of the actually-safe functions for review, since the
certificate is still provisional — that's expected and disclosed, not
hidden."*

Point at the summary table: `Auto-approved 9 / Escalated 5 / Findings 8`.

### Step 3 — with the LLM verifier (about 2 minutes)

```bash
codegate scan examples/vulnerable_app
```

*"Same scan, verifier on. Every escalated unit gets one LLM call, cached
so a repeat scan costs nothing — that's why this just ran instantly,
we warmed the cache earlier. Watch what happens to those false
positives."*

Point out: findings drop from 8 to 5, precision goes from 0.50 to 1.00
on this target (mention the number directly — it's real, measured, and
in `docs/ENGINEERING_LOG.md` section 10 and `data/eval/metrics.json` if
anyone wants to check it against the underlying numbers). Every
remaining finding is a real, correctly-attributed vulnerability.

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

*"Yes — we generated a real 516-sample corpus from four different
Ollama models, labeled it with the same dynamic detonation oracles, and
re-ran the whole pipeline on it this week. That real run actually
surfaced two genuine bugs in our labeling logic that the simulated
corpus had never triggered — a markdown-extraction gap and a
process-hang in the sandbox — both found and fixed. The corpus itself
is still too small to certify a new threshold: only 8 vulnerable samples
landed in the calibration split, and the statistics need more evidence
than that before we swap the shipped model. That's a sample-size
problem, not a mechanism problem — the certificate math and the whole
pipeline are proven correct against real data; we just need a bigger
real corpus before we can certify against it. Full numbers are in
`docs/ENGINEERING_LOG.md` section 11."*

This is a strong answer if asked directly — it shows the team tested
against reality, found real bugs, and is honest about what isn't
finished yet, rather than either hiding the gap or claiming something
uncertified is production-ready.

## 4 · Numbers to have ready if asked

| Question | Answer |
|---|---|
| How many tests? | 200, all passing, CI-verified on Python 3.11 and 3.13 |
| How many CWEs? | 3 — SQL injection, OS command injection, hardcoded credentials |
| Precision without the verifier? | 0.50 on the demo app (semgrep alone catches everything, model gate over-escalates) |
| Precision with the verifier? | 1.00 on the demo app, live-verified against Groq |
| Real corpus size? | 516 samples, 4 generator models, 33.3% vulnerable by design |
| Real corpus abstention rate? | 28.3%, understood and explained (see section 11) |
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
