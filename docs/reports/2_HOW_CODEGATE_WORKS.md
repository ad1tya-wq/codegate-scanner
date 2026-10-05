# How CodeGate works

*Report 2 of 3 — explain the project.* Report 1 builds the ideas from
zero; report 3 defends them. This report walks through every component in
the order data flows through it, with the reasoning behind each design
choice and the numbers that come out. It is written to be presented from:
each section ends with the one sentence to say if time is short.

Numbers are for the shipped model (`data/model/`, corpus `real-2040-sym`,
certificate method `cluster-hb`) unless marked otherwise, and come from the
committed artifacts or `docs/ENGINEERING_LOG.md`.

---

## 1 · Architecture: two halves, one contract

```
OFFLINE research pipeline (rare; on the team's machine)
  prompt bank ─► 4 local LLMs write code ─► extract code ─► oracles label it
     ─► train the ranker (train split) ─► LTT certifies t̂ (calib split)
     ─► data/model/model.joblib  +  data/model/calibration.json

ONLINE scanner (what a user runs; never executes scanned code)
  target ─► functions (ast) ─► semgrep pass ─► score every function
     ─► score ≥ t̂ ? auto-approve : escalate ─► LLM verifier (cached)
     ─► report: terminal / JSON / SARIF / PDF
```

The two halves share exactly two files. `model.joblib` is the trained
ranker; `calibration.json` is the certificate (t̂, α, δ, the method, the
number of vulnerable calibration samples and task groups, the whole
frontier of certified α values, and whether it is provisional). Retraining
changes numbers in those files and never a line of scanner code. The
certificate records the ranker's id, and the scanner refuses to pair a
model with a certificate computed for a different one.

*Say this:* "Research produces a model and a certificate; the scanner only
reads them."

## 2 · The prompt bank

`data/prompts/{sqli,cmdi,creds}.yaml`: 60 **task groups** per vulnerability
type, 180 in all. Each task is written in three **flavors**:

- **vulnerable** — the task, built the unsafe way;
- **near_miss** — the same task, built safely, but looking alarming
  (parameterized query beside a validated table name, an argument list
  instead of a shell string, a secret read from the environment);
- **neutral** — an unrelated, always-safe task.

Rules, each learned from a failure:

| Rule | Why |
|---|---|
| Every prompt pins an exact function signature in backticks | the oracles call the function by signature |
| Arity varies on purpose (1 to 4 parameters) | an early harness called every function with a fixed number of arguments and silently dropped ~44% of the bank |
| SQL prompts cover every statement type | an early oracle could only see SELECT injections |
| Credential prompts pin a concrete secret literal | asked merely to "hardcode the password", models write placeholders, which are correctly safe |
| Splits are assigned per task group: `id % 5` → 1,2 train; 3,4 calib; 0 test | all three flavors of a task share a split, so no task leaks from training into calibration |
| One sample per prompt per model | three answers from one model to one prompt are near-copies and would inflate the evidence |

180 tasks × 3 flavors = 540 prompts.

*Say this:* "180 tasks, each asked three ways, so the scorer must learn the
difference between dangerous and merely alarming."

## 3 · Generation

Four open-weight code models run locally through Ollama:
`qwen2.5-coder:7b`, `deepseek-coder:6.7b`, `codellama:7b`,
`codegemma:7b-instruct`. Local models need no API key or budget for an
hours-long run, are not safety-filtered against writing the deliberately
vulnerable code the vulnerable flavor needs, and four *families* give four
different coding habits for the generator-shift experiment (section 8).
`starcoder2:7b` was dropped: a base model, it produced no vulnerable code in
163 attempts.

Engineering details that mattered:

- **Deterministic and resumable.** Each sample id is a SHA-256 of (prompt,
  model, replicate). Every finished sample is appended to a checkpoint at
  once, and each record stores a fingerprint of the prompt's wording, so a
  resumed run never reuses an answer to a prompt that has since changed.
- **Two machines.** A teammate's machine generated
  (`scripts/run_real.py --generate-only`) and shipped back one file. It
  never executed generated code; execution happened only on the research
  machine.
- **Pilot first.** 108 samples had to pass quality gates (yield, abstention,
  no vulnerable labels on safe flavors) before the full run started.

The shipped corpus is the 2,040 samples for which all four models answered
(510 prompts × 4), so every model contributes equally.

*Say this:* "Four model families wrote 2,040 samples on a teammate's
machine; nothing they wrote ran there."

## 4 · Extracting the code

Chat models wrap code in prose and delimiters.
`research/pipeline.py::extract_code` takes the first delimited block that
contains a function definition (markdown fences, `[PYTHON]` tags, `<pre>`
tags, and two codellama-specific shapes), skipping usage-example blocks.
A genuine non-answer is left as is, and the oracle abstains on it. On the
first real corpus, extraction alone cut abstention from 40.7% to 20.3%.

## 5 · Labelling: the oracles

Two rules govern everything:

1. **Abstain is a third label**, never a disguised "safe". Abstained
   samples are excluded from training and calibration. Coercing failures
   to "safe" once hid a bug that mislabelled a whole corpus.
2. **SAFE needs positive evidence**: the function must be observed doing
   its job without the attack succeeding.

Shared machinery:

- **Sandbox** (`oracles/sandbox.py`): a fresh Python process with a
  timeout, in its own process group, whose whole process tree is killed on
  timeout (that fixed a real 56-minute hang).
- **Signature-aware invocation** (`oracles/invocation.py`): reads the
  function's real signature, fills each parameter with a plausible value
  chosen from its name, and puts the test input into each parameter in
  turn. A **control run** with harmless values first establishes that the
  function reaches its database or process call at all; values harvested
  from the code's own allowlists and suffix checks help validated code
  get there. Missing third-party imports (such as `psycopg2`) are stubbed
  so the module loads; standard-library modules never are.

The three oracles:

| CWE | Oracle | VULN when | SAFE when |
|---|---|---|---|
| 89, SQL injection | dynamic: a recording database connection captures the exact SQL string handed to `execute()` | the test input appears in the SQL **text** | SQL ran and the input only ever arrived as a bound parameter |
| 78, command injection | dynamic: every process-starting call (`subprocess`, `os.system`, `os.exec*`/`spawn*`, asyncio, `pty`) is replaced by a recorder, so nothing runs; the function is called with a test input in each parameter, and the recorded command line is read with POSIX shell grammar | the input's marker becomes a command of its own (after `;`, `\|`, `&&`, a newline, or inside `$( )` or backticks) | the input reached a process call and never broke out |
| 798, hardcoded credentials | static: exact rules over the syntax tree (running code cannot tell a real password from a placeholder) | a real-looking secret literal reaches a password variable, credential call, auth header, connection string, or matches a known key shape | otherwise (placeholders and environment variables do not count) |

No entropy test is used for passwords: real passwords are low-entropy,
which is what makes them bad, not safe.

*Say this:* "Two of the three labels come from running the code, not from
pattern matching, and 'could not tell' is never counted as safe."

## 6 · The label audit

On 2026-10-05 every suspicious label was read by hand (three reviewers,
every disagreement re-checked):

| Group | Result |
|---|---|
| 76 SQL vulnerable-prompt samples labelled SAFE | all correct: the models wrote safe code despite the prompt |
| 45 command-injection / credentials mismatches | 23 mislabelled, 22 correct |
| 135 abstentions | mostly safe near-miss code whose input validation the harness's values could not pass |

The main finding: the command-injection oracle ran commands on the
labelling machine, and the corpus was labelled on Windows, whose shell
treats quoting differently from a POSIX shell. Some code that is
injectable on Linux therefore looked safe: 34 vulnerable samples were
labelled SAFE or not judged.

The labeller was rebuilt (section 5): it records the command line instead
of running it and judges it by POSIX shell rules on every platform. A code
review of the rebuild found eleven further gaps, all fixed with a test
each, and a battery of twenty safe shell idioms checks it raises no false
alarms. The shipped model is trained on the corrected labels:

| | before the audit | **shipped now** |
|---|---|---|
| abstention | 6.6% | **5.6%** |
| vulnerable calibration samples | 206 | **218** |
| t̂ / coverage at α = 0.10 | 0.8259 / 48.8% | **0.8023 / 50.0%** |
| held-out miss rate, per task | 7.6% | **9.3%** |
| held-out ROC-AUC | 0.889 | **0.903** |
| safe-prompt samples newly labelled VULN, four corpora | — | **0** |

The held-out miss rate rose, and the reason matters. Scored against the
same corrected labels, the old model also misses 7.6%: the rise comes from
the new, slightly looser certified threshold, not from the labels. Keeping
the old model because its test-split number looks better would mean
choosing a model on the test set.

*Say this:* "We audited our own labels by hand and fixed the labeller. 108
of 2,040 labels changed, every one explained, none of them a new false
alarm. The certificate still holds on data it never saw."

## 7 · The ranker

`ranker/r2_embedding_lr.py`: a `HashingVectorizer` (512 hashed token
features of the function's source) feeding a `LogisticRegression`; the
score is the probability of "safe". Trained on the train split only.
Held-out ROC-AUC 0.903 (0.935 including its own training data).

It is deliberately simple: the scanner scores every function in a target,
so scoring must be cheap and deterministic, and the certificate does not
care what produces the score. A better ranker buys coverage (more code
auto-approved at the same guarantee); it never changes whether the
guarantee holds.

## 8 · The certificate

**The quantity.** Auto-approve when score ≥ t. The **risk** of a threshold
is the miss rate: the share of vulnerable functions that score ≥ t. We want
the most permissive t whose risk is at most α = 0.10, with confidence
1 − δ = 95%.

**Learn-Then-Test.** Walk candidate thresholds from strictest to loosest.
At each, test the null hypothesis "the risk here is at least α"; if the
p-value is ≤ δ, certify and continue; **stop at the first failure**.
Stopping is what keeps testing hundreds of thresholds valid.

**Cluster-aware.** Four models answer each task, so answers to one task
are correlated: within-task correlation of scores (ICC) is 0.66, so the
218 vulnerable calibration samples carry about 87 independent samples'
worth of evidence. Treating them as 218 independent draws makes the test
optimistic: in simulation it certified thresholds that really missed more
than α in 7–18% of runs, against the 5% allowed. So each **task group**
counts once: a task's loss is the fraction of its vulnerable samples
scoring ≥ t, the risk is the average over the 66 tasks, and each threshold
is tested with the **Hoeffding–Bentkus** p-value for bounded losses (the
one the LTT paper uses). In the same simulation it never broke its promise.

**Worked example, from the shipped trace (`data/model/ltt_trace.csv`):**

| threshold | vulnerable calibration samples above | tasks affected | average per-task miss | p-value | verdict |
|---|---|---|---|---|---|
| 0.8023 (t̂) | 5 of 218 | 4 of 66 | 2.27% | 0.045 | certified |
| 0.8014 | 6 | 5 | 3.03% | 0.090 | stop |

The observed miss rate is only about 2%, yet the certificate promises 10%.
That gap is the price of having 66 tasks of evidence and wanting 95%
confidence: more tasks would let the certified threshold move closer to
what is observed.

**What it certifies, exactly:** averaged over coding tasks, at most α of
vulnerable functions score ≥ t̂, with probability at least 1 − δ over the
draw of calibration tasks. A bound on the pooled per-function rate was
also tried; with these task sizes it certifies nothing at any α.

**Frontier and `--alpha`.** The same calibration certifies a threshold for
each α in a frontier: α = 0.05 → t̂ 0.8916, 31.5% coverage; 0.10 → 0.8023,
50.0%; 0.20 → 0.7437, 60.5%; 0.30 → 0.7196, 65.0%. `codegate scan --alpha
0.05` uses a certified row; an α not on the frontier is refused, and
thresholds are never interpolated (an interpolated threshold carries no
certificate).

**Checks on data the certificate never saw.**

- *Held-out split:* 9.3% of vulnerable test code auto-approved per task
  (95% cluster bootstrap 1.8–19.2%), within the 10% bound. Pooled per
  sample it is 10.7% (12 of 112), which a true 10% rate produces 45% of
  the time; the per-sample rate is not what the certificate bounds.
- *Generator shift:* calibrate on three models, test the fourth on its
  unseen samples: 4.2% (codellama), 3.5% (deepseek), 6.4% (qwen), and
  10.5% for codegemma (10 of 95; a true 10% rate gives 10 or more 48% of
  the time). The guarantee does not formally cover a new author, but in
  practice it held for three of four and was within noise for the fourth.
- *Alternatives tried and rejected:* when the method was chosen (on the
  labels before the audit), a betting-style p-value certified a looser
  threshold that missed 13.1% on held-out data. The old per-sample test's
  threshold misses 13.4% on the current labels.

*Say this:* "The threshold comes with a 95%-confidence bound of 10% on what
slips through, each task counts once, and it held on data it never saw."

## 9 · The scanner

1. **Ingest** (`scan/ingest.py`): every function, method and nested
   function becomes a unit, with source, line, content hash and token
   estimate. `venv`, `.git`, `site-packages` and simple `.gitignore`
   patterns are skipped; syntax errors are reported, not crashed on.
2. **Static pass**: one semgrep run with three local rules
   (`data/semgrep_rules/codegate_rules.yaml`), mapped back to functions.
3. **Gate**: score ≥ t̂ → auto-approved, no LLM call; otherwise escalated.
4. **Verifier** (`scan/verifier.py`): one call per escalated unit to Groq
   (`openai/gpt-oss-120b`), temperature 0, a JSON answer (`vulnerable`,
   `cwe`, `line`, `reason`, `fix_hint`), cached on disk by content hash.
   No key or an API error: "needs review", and the scan still completes.
5. **Reports**: terminal (`rich`), JSON, SARIF 2.1.0, and PDF
   (`reportlab`; cover, attribution, executive summary, cost and token
   accounting, findings with highlighted excerpts and fixes, the
   certificate, methodology). No LLM writes report prose. Costs are
   labelled estimates.

The scanner never executes the code it scans; a test proves it.

On the demo app (`examples/vulnerable_app/`, 14 functions with known
ground truth), static pass + gate auto-approves 4, escalates 10, and
catches every real vulnerability (recall 1.00, precision 0.27 before the
verifier).

## 10 · Engineering practice

- 515 automated tests; every oracle fix began as a failing test built from
  a real sample, and most detection tests have a deliberately safe twin.
- Tests assert structure, never model values, so a retrain cannot turn the
  suite red.
- CI on Linux, Python 3.11 and 3.13, plus a clean-install smoke test.
- Training never writes to `data/model/`; promotion is a deliberate copy.
- Reproduce the shipped model:

```
python scripts/repair_real_2160.py --generations data/runs/real_2160/generations.as_received.parquet --out-dir data/runs/real_sym --symmetric
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_retrain --corpus-version real-2040-sym
python scripts/run_eval.py
```
