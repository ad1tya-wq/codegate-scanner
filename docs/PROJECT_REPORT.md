# CodeGate — Complete Project Report

This document explains CodeGate from the first idea to the shipped tool:
what problem it addresses, every technical component, how each was built,
why each decision was made, what went wrong along the way, and where the
project stands. It is written to be read start to finish by someone who
has never seen the code, and to answer a reviewer's "why?" at every step.

Every number in it comes from a command run on the project repository, a
committed artifact, or `docs/ENGINEERING_LOG.md`, which cites the commit,
test or command behind each claim. Where something is not yet measured or
not yet solved, this document says so.

---

## 1 · The idea

### 1.1 The problem

AI coding assistants now write a large share of the code developers ship.
Careful studies of their output (Pearce et al., *Asleep at the Keyboard?*,
IEEE S&P 2022, the first large-scale measurement of Copilot) found that a
real fraction of generated code contains classic, well-understood security
bugs: SQL injection, OS command injection, hardcoded credentials. The code
looks fine, runs fine, and passes review by a busy human.

The tools available to catch this force a bad trade-off:

- **Static analyzers** (semgrep, Bandit, CodeQL) are fast, free and
  deterministic, but they only catch the exact patterns someone wrote a
  rule for. Above all, they never tell you what they *missed*.
- **LLM code review** is flexible and catches patterns no rule anticipated,
  but sending every function in a codebase to a language model is slow and
  expensive, especially in CI on every commit. Its answer is also a
  probabilistic judgement with no stated error rate.

Neither answers the question that actually matters to the person deciding
whether to merge: *of the code you did not flag, how much is still
vulnerable?*

### 1.2 The core idea

CodeGate's answer is a **certified triage gate**. A cheap model scores every
function for how safe it looks. A statistical procedure from conformal
prediction, **Learn-Then-Test (LTT)**, then picks a score threshold above
which functions are auto-approved, together with a *proof-style guarantee*:

> Averaged over coding tasks, at most a fraction α of the vulnerable
> functions that reach the gate score above the threshold and get
> auto-approved — and this holds with probability at least 1 − δ.

(Averaged over tasks because each task counts once as evidence; section
2.2 explains why.)

Everything below the threshold is escalated to an LLM verifier, so LLM
spend is confined to the code the certificate cannot vouch for. A
deterministic static pass runs first and catches the textbook cases outright.

Three properties make this more than "pick a threshold that looked good on
a validation set":

1. **The guarantee is computed, not asserted.** It comes from a hypothesis
   test over labelled calibration data.
2. **It does not depend on the model being good.** A weak ranker certifies
   a *lower* threshold of usefulness (fewer functions auto-approved, more
   escalated). It cannot produce a false guarantee, provided the
   calibration data is representative.
3. **It can say "not yet".** If the evidence does not support any
   threshold, the method certifies nothing and everything is escalated.
   That happened to this project once, and it was the method working
   correctly (section 8).

### 1.3 Scope decisions taken at the start

- **Python only.** One language done properly beats several done badly.
  Python's `ast` module gives exact function boundaries for free.
- **Three CWEs:** CWE-89 (SQL injection), CWE-78 (OS command injection),
  CWE-798 (hardcoded credentials). They were chosen because each is common
  in generated code *and* each admits an **automatable ground truth**: the
  first two can be proven by actually running the code against an exploit,
  and the third can be decided by exact static rules. The certificate is
  only as good as its labels, so a CWE without reliable automatic labelling
  would have weakened the whole claim. Adding CWEs was deliberately deferred.
- **Function-level units.** The model scores individual functions, because
  that is the size of what it is trained on, and a function is the natural
  unit a reviewer acts on.
- **The scanner never executes user code.** Executing code is how the
  *training labels* are produced, on a machine the team controls, against
  code the team's own prompts generated. The scanner a user runs only reads
  code. This split shaped the entire architecture.

---

## 2 · Background

### 2.1 The three vulnerability classes

**CWE-89, SQL injection.** User input is spliced into SQL text instead of
being passed as a bound parameter:

```
conn.execute("SELECT * FROM users WHERE name = '" + name + "'")   # vulnerable
conn.execute("SELECT * FROM users WHERE name = ?", (name,))         # safe
```

With `name = "x' OR '1'='1"` the first query returns every user. The second
is safe because the driver sends the value separately from the SQL.

**CWE-78, OS command injection.** User input reaches a shell:

```
os.system("ping -c 1 " + host)                              # vulnerable
subprocess.run(["ping", "-c", "1", host], shell=False)      # safe
```

With a host value containing a shell separator followed by another command,
the first version runs that second command. The second version passes
`host` as a single argument and no shell is involved.

**CWE-798, hardcoded credentials.** A secret is written into source code
(`password = "hunter2"`), so anyone with the code, a backup or the git
history has it. The safe form reads it from the environment or a secret
store.

### 2.2 Conformal risk control and Learn-Then-Test

Let a ranker give each function a score `s` in [0, 1], higher meaning
safer, and auto-approve when `s ≥ t`. Define the **risk** of threshold `t`:

```
R(t) = P(score ≥ t | the function is vulnerable)
```

That is the miss rate: the share of vulnerable code that would be waved
through. `R(t)` falls as `t` rises. We want the most permissive `t` (most
code auto-approved) that keeps `R(t) ≤ α`.

LTT (Angelopoulos, Bates et al.) turns this into **fixed-sequence
hypothesis testing** over a labelled calibration set:

1. Take `n` vulnerable calibration samples.
2. Walk candidate thresholds from strictest (highest) to loosest.
3. At each `t`, count `k` = vulnerable samples with score ≥ `t`.
4. Test the null hypothesis "the true risk at `t` is at least α". Under that
   null, `k` is at least Binomial(`n`, α), so the p-value is
   `p = P(Binomial(n, α) ≤ k)`.
5. If `p ≤ δ`, reject the null and certify `t`, then move to the next,
   looser threshold. **Stop at the first threshold that fails.** Stopping
   is what makes testing many thresholds valid. Continuing to look for a
   looser one that happens to pass would be p-hacking.

The result is `t̂` with `P(R(t̂) ≤ α) ≥ 1 − δ`. The guarantee is
**distribution-free** (no assumption about how scores are distributed) and
**finite-sample** (valid at the actual `n`, not only as `n → ∞`). It
assumes the calibration data is **exchangeable** with the code the tool
will later see.

CodeGate's certificate is **cluster-aware**. Several models answer each
task, so samples from one task group are correlated (measured intra-group
correlation 0.57 on the shipped corpus). The standard test treats every
sample as independent and becomes optimistic. In simulation it certified
thresholds that really missed more than α in 8.5–12% of runs, against the
5% allowed. So CodeGate counts each task group once. A group's loss is the
fraction of its vulnerable samples above `t`, the risk is the mean over
groups, and each threshold is tested with the Hoeffding–Bentkus p-value
for bounded losses (the one the LTT paper uses). That needs only *task
groups* to be exchangeable, which kept its promise in every simulated
setting. Section 8.9 tells how this was found.

How much data is needed: with zero misses (`k = 0`), certifying requires
`(1 − α)^n ≤ δ`, so at α = δ = 0.05 the minimum is **59 vulnerable
calibration samples**. The tolerance for misses grows slowly: n = 100
tolerates k ≤ 1, n = 150 tolerates k ≤ 2, n = 206 tolerates k ≤ 4.

### 2.3 Related work, and what is new here

- **Pearce et al., IEEE S&P 2022** — the empirical motivation: generated
  code contains real CWEs at a non-trivial rate.
- **Bates et al., J. ACM 2021; Angelopoulos et al., ICLR 2024** — risk-
  controlling prediction and conformal risk control, the source of LTT and
  of the "a bad model degrades coverage, never the guarantee" property.
- **Du et al., ICSE 2026; IRIS (2024)** — static analysis plus an LLM to
  reduce false positives. Closest prior systems; neither bounds what is
  *missed*.
- **FrugalGPT (Chen et al.)** — cheap-to-expensive LLM cascades routed by a
  learned confidence, with no formal risk guarantee.

CodeGate's contribution is the combination: a **certified** gate on the miss
rate, an LLM cascade spent only on what the certificate cannot cover, and
labels produced by **executing** generated code, not by pattern matching.

---

## 3 · Architecture

CodeGate has two halves that never import each other's internals:

```
OFFLINE research pipeline (runs rarely, on the team's machine)
  prompt bank -> 4 local LLMs generate code -> extract code
    -> oracles label each sample (execute it against an exploit, or static rules)
    -> train the ranker on the train split
    -> LTT certifies t_hat on the calib split
    -> writes data/model/model.joblib + data/model/calibration.json

ONLINE scanner (what a user runs; never executes the code it scans)
  target directory -> ingest functions (ast)
    -> static pass (semgrep, one run over the whole target)
    -> rank every function -> gate: score >= t_hat ? auto-approve : escalate
    -> escalated: one LLM verifier call each, cached by content hash
    -> report: terminal / JSON / SARIF / PDF
```

**The contract between the halves is exactly two files**:
`data/model/model.joblib` (the trained ranker) and
`data/model/calibration.json` (the certificate). Retraining changes the
numbers inside those files, never a line of scanner code. `calibration.json`
also carries the model's `ranker_id`, and the scanner refuses to pair a
model with a certificate computed for a different one.

Repository layout:

| Path | Contents |
|---|---|
| `src/codegate/gate/` | LTT (`ltt.py`) and risk helpers (`risk.py`) |
| `src/codegate/oracles/` | Labellers: sandbox, invocation helper, DB-API recorder, SQLi, cmdi and creds oracles, consensus, semgrep wrapper |
| `src/codegate/ranker/` | The R2 ranker and the R0 semgrep baseline |
| `src/codegate/research/` | Prompt bank, generation backends and harness, the pipeline, artifacts, evaluation |
| `src/codegate/scan/` | Ingest, scan pipeline, findings, LLM verifier |
| `src/codegate/report/` | Terminal, JSON/SARIF and PDF reports, cost accounting, remediation text |
| `src/codegate/cli.py` | `codegate info`, `calibrate`, `scan` |
| `scripts/` | Corpus generation, relabelling, training from a shipped corpus, evaluation, corpus repair |
| `data/prompts/` | The prompt bank (YAML) |
| `data/model/` | The shipped model and certificate |
| `tests/` | 442 automated tests |
| `examples/vulnerable_app/` | Demo target with known ground truth |

---

## 4 · The offline research pipeline

### 4.1 The prompt bank

The corpus is generated from prompts in `data/prompts/{sqli,cmdi,creds}.yaml`.
Each file holds **60 task groups**, and each task group has three
**flavors** sharing one underlying task:

- **vulnerable** — asks for the task in a way that elicits the bug
  ("build the SQL by directly formatting the username into the query").
- **near_miss** — asks for code that is *safe* but looks like the
  vulnerable pattern: a parameterized query beside an allowlisted table
  name, `subprocess.run([...], shell=False)`, a secret read from
  `os.environ`. **This is the corpus's central design decision.** Without
  near-misses, a model can score well by keying on surface features ("uses
  `subprocess`") instead of the actual vulnerability, and the benchmark
  would measure the prompt template rather than vulnerability detection.
- **neutral** — an unrelated, always-safe task (a balance control).

Design rules, each learned from a failure:

- **Every prompt pins an exact function signature** in backticks
  (``get_user(conn, username)``). The oracles call the function by
  signature, so guessing it is avoided.
- **Arity varies deliberately**: CWE-89 vulnerable prompts span 2, 3 and 4
  parameters, CWE-78 spans 1 to 3. A test asserts the spread, so a
  regression in signature handling appears as failed labels rather than
  silence.
- **CWE-89 covers every statement type**: SELECT, INSERT, UPDATE, DELETE,
  ORDER BY, LIKE, BETWEEN, IN, JOIN, aggregates, LIMIT/OFFSET. The original
  bank was SELECT-heavy because the original oracle could only see SELECT
  injections.
- **Every vulnerable CWE-798 prompt pins its secret literal** ("…assigned
  the string literal `Kx7pQm2wZr`"). Asked merely to "hardcode the
  password", models write `your_password` or `<API_KEY>`. Those are
  placeholders, not credentials, so they correctly label as safe, and the
  vulnerable flavor yielded only 17%. Pinning a concrete literal fixed it.
- **Splits are assigned per task group, never per prompt**, by the rule
  `id % 5 → {1, 2: train; 3, 4: calib; 0: test}`, giving 24 / 24 / 12 groups
  per CWE. All three flavors of a task share a split, so the model is never
  trained on one flavor of a task and calibrated on another (leakage
  control). The interleaved rule keeps similar adjacent tasks apart.

Size: 180 task groups × 3 flavors = **540 prompts**. With 4 generators and
one sample per prompt, that is 2,160 planned samples.

**Why one sample per prompt, not three.** Three completions of the same
prompt from the same model are highly correlated. LTT counts every
calibration sample as an independent piece of evidence, so 300 correlated
samples would make the certificate look stronger than the evidence is.
Growth comes from new task groups instead.

### 4.2 Generation

**Backends** (`research/generation/backends.py`) implement one interface,
`generate(prompt, seed) -> str`:

- `SimulatedBackend` — a deterministic, offline template filler (9
  templates, one per CWE × flavor). It let the whole pipeline be built and
  tested before any real model ran. It was the shipped model's source until
  October 2026.
- `OllamaBackend` — posts the prompt text verbatim to a local Ollama server
  (`/api/generate`), with a fixed seed.

**Why local Ollama models.** No API key and no cost for a run that takes
hours. Open-weight code models are not safety-filtered against writing the
deliberately vulnerable code the vulnerable flavor needs. And four different
model families (`qwen2.5-coder:7b`, `deepseek-coder:6.7b`, `codellama:7b`,
`codegemma:7b-instruct`) make the generator-shift experiment (section 4.7)
meaningful. Four sizes of one family would share training data and habits.
`starcoder2:7b` was in the original line-up and was replaced: it is a base
completion model, not instruction-tuned, and produced **zero** vulnerable
samples in 163 attempts.

**Determinism and resume.** Each sample's id is a stable hash of
(prompt id, generator, replicate) via SHA-256 (`stable_seed`), never a
random UUID, so a restarted run can recognise finished work. Every finished
sample is appended to a JSONL checkpoint immediately, so a multi-hour run
survives a dropped connection or a closed laptop. Since October 2026 each
checkpoint record also stores a **fingerprint of the prompt's wording**.
A record is reused only if the wording still matches, and the split always
comes from the current prompt (section 8.6 explains the bug that made this
necessary).

**The two-machine workflow.** The machines generating and labelling were
not on a shared network. So the generation host runs
`scripts/run_real.py --generate-only` entirely locally and ships back one
file, `generations.parquet`, through a git branch. Generation is pure model
inference: **no generated code is ever executed on the host's machine.**
Execution (labelling) happens only on the research machine. The teammate's
step-by-step instructions are `docs/CORPUS_GENERATION_GUIDE.md`, including
a mandatory **pilot** (`--pilot-per-cwe 3`, 108 samples) that must pass
quality gates before the full run is started.

### 4.3 Extracting code from model output

Real chat models wrap code in prose and delimiters.
`research/pipeline.py::extract_code` returns the first delimited block that
actually contains a `def`: markdown fences, `[PYTHON]` tags, `<pre>` tags,
and two codellama shapes found in the pilot (an HTML `<details>` block, and
code followed by a closing fence that was never opened). The first block
isn't always the right one, because codellama often follows the
implementation with a usage example. If nothing qualifies, the raw text is
returned unchanged, and a genuine non-answer then abstains downstream
rather than being forced into a false extraction. On the first real corpus,
extraction alone cut the abstention rate from 40.7% to 20.3%.

### 4.4 Labelling: the oracles

Labels decide everything. A wrong label goes straight into training and into
the certificate. So the labelling design rests on two rules:

1. **Abstention is a third state, never coerced to "safe".** If an oracle
   cannot reach a verdict, the sample is labelled `LABEL_ABSTAIN` (−1) and
   excluded from training and calibration. This rule exists because the
   opposite once hid a bug that mislabelled a third of the corpus
   (section 8.1).
2. **A SAFE verdict needs positive evidence.** "The function ran without
   the exploit firing" is evidence. "The function crashed before reaching
   anything" is not, and that is an abstention.

**The sandbox** (`oracles/sandbox.py`). Generated code runs in a fresh
Python subprocess with a wall-clock timeout, in its own process group, and
the whole process tree is killed on timeout. That last part fixed a real
56-minute hang, where a grandchild process kept pipes open after its parent
was killed. This is process-level isolation for *benign accidents* in code
the team's own prompts produced. It is not a container, and is documented
as such.

**Signature-aware invocation** (`oracles/invocation.py`). The original
harnesses called every function with a fixed number of arguments, so any
other signature raised `TypeError` and abstained. That silently discarded
about 44% of the dynamic prompt bank. Now the harness reads the function's
real signature, fills every parameter with a type-plausible benign value
chosen from its name (`user_id` → 1, `start_date` → a date,
`sort_column` → a column name, otherwise `"alice"`), and puts the payload
into **each parameter in turn**.

Before any payload, a **control run** with benign values establishes that
the function does reach its database call or process spawn at all. Safe code
that validates input often rejects the guessed values too, so the control
run tries progressively better candidates (`benign_vectors`):

- values harvested from the code's own allowlists (`{"png", "jpg"}`, dict keys);
- values satisfying its suffix or prefix checks (`"alice.zip"` for
  `.endswith(".zip")`);
- then a type flip (`1` where it guessed a string), for code that casts
  with `int()`.

Whichever vector works becomes the base for the payload runs. Vulnerable
code reaches its sink on the first try, so the extra candidates cost
nothing there.

Two more harness properties came from real samples. First, models often
leave a demo call at the bottom of the file (`scan_host("example.org", 80)`),
and when it crashed it killed the whole script before the harness ran. The
generated code is now executed inside a guard, so the function survives a
crashing demo call. Second, generated code imports drivers the labelling
machine lacks, such as `psycopg2`. A missing-module finder supplies
permissive stubs for those *third-party* names, so the import doesn't
abort the script. It never stubs a standard-library name, because standard
modules probe for platform-specific ones: Python's `subprocess` decides it
is on Windows with `try: import msvcrt`. A fake `msvcrt` on Linux broke
every command check, until CI caught it (section 8.8).

**SQL injection oracle** (`oracles/sqli_oracle.py`). The generated function
receives a **recording DB-API connection** (`oracles/dbapi_recorder.py`)
wrapping a real in-memory SQLite database. The database holds 20-column
tables under every table name a model plausibly picks. The recorder captures
the exact SQL string each `execute()` is given, then runs it. The verdict:

- **VULNERABLE** when the payload `nonexistent' OR '1'='1` appears in an
  executed statement's **SQL text** — the definition of injection. A bound
  parameter is passed separately and never appears in the text, whatever
  the paramstyle.
- **SAFE** when SQL was observed running and the payload never reached the
  text.
- **Abstain** otherwise.

This replaced two earlier designs. A row-count check labelled injectable
DELETE/UPDATE code safe and parameterized `COUNT(*)` code vulnerable. A
SQLite trace callback could not see Postgres-style code (`%s`
placeholders, `with conn.cursor() as cur`), because SQLite rejected the
statement before anything could be traced. The recorder also translates
`%s` placeholders so that parameterized Postgres-idiom code can run.

**Command injection oracle** (`oracles/cmdi_oracle.py`). The payload is a
harmless shell sequence that writes a sentinel file in a fresh temporary
directory, using `&`, which separates commands in both POSIX `sh` and
Windows `cmd.exe`. If the code also checks a suffix or prefix, variants
carry it. The verdict:

- **VULNERABLE** if the sentinel file exists. That is direct proof the
  payload reached a shell. It counts even if the function raises
  afterwards, for example code that parses the command's output with
  `int(...)`.
- **SAFE** if the function was observed reaching a process spawn and no
  sentinel appeared. A `FileNotFoundError` from a missing binary counts as
  reaching the spawn: it can only occur on the `shell=False` path, since a
  shell always exists.
- **Abstain** otherwise.

**Hardcoded-credentials oracle** (`oracles/creds_oracle.py`). Static by
necessity, because no execution can tell whether a string is a real
password. It walks the syntax tree and flags a **secret literal** that
reaches a credential position:

- a secret-named variable, attribute, subscript, keyword argument, dict key
  or default value (`password`, `api_key`, `token`, `routing_key`,
  `X-Routing-Key`, …);
- the password slot of credential calls (`.login(user, pw)`, `ftplib.FTP`,
  `HTTPBasicAuth`, `set_password`), or the last argument of calls named like
  `connect`/`auth`/`login`;
- a `(user, password)` tuple, a secret-named function's return value
  (`get_jwt_secret()`), or a hardcoded fallback such as
  `os.environ.get("JWT_SECRET", "...")`.

A literal also counts if it reaches one of those positions through a local
variable. Separately, it flags unambiguous **shapes** under any name: vendor
key prefixes (AWS `AKIA…`, Stripe `sk_live_…`, GitHub `ghp_…`, SendGrid
`SG.…`, `whsec_…`, `npm_…`), Slack and Discord webhook URLs, passwords
inside URLs and connection strings, and secrets in query strings.

A *secret literal* is at least 6 characters, contains no whitespace (which
rules out prose), and is not a placeholder (`changeme`, `your_…`, `<…>`,
`example`). Entropy is deliberately **not** used: the old rule required
high entropy and rejected `hunter2`, `letmein` and `P@ssw0rd`. Real
passwords are low-entropy, which is what makes them bad, not safe. The
near-miss flavor reads from the environment, which is never a literal, so
widening these rules was checked against every near-miss sample for false
positives.

**Consensus** (`oracles/consensus.py`). The label is the dynamic oracle's
verdict for CWE-89/78 and the static oracle's for CWE-798. An earlier design
carried an LLM "adjudicator" fallback. It was never wired in, and could never
have fired, because labelling abstains first. It was removed once it was
confirmed nothing read it.

### 4.5 The ranker

`ranker/r2_embedding_lr.py`: a `HashingVectorizer` (512 features,
token-hash bag of the function's source) feeding a `LogisticRegression`.
Its score is the probability of "safe", so higher means safer. It is
trained only on the `train` split.

**Why so simple.** LTT evaluates the risk at every candidate threshold
during calibration, and the scanner must score *every* function in a
target, so scoring has to be cheap and deterministic. LTT does not care
what produces the score. The guarantee holds for any ranker, and a better
ranker only buys more coverage. The project spent its effort where the
real risk was, on correct labels. A better ranker trained on wrong labels
is still wrong. A code-embedding model is a drop-in future upgrade behind
the same interface.

### 4.6 Calibration and the certificate

`gate/ltt.py::calibrate_threshold` implements section 2.2 exactly. Given
each sample's task group (its prompt id minus the flavor), it runs the
cluster-aware test; without groups, it runs the per-sample binomial test.
`config.yaml`'s `certificate: cluster` selects the first. The candidate
thresholds are the unique calibration scores, plus +∞ (approve nothing,
always certifiable) as the starting point. The function records a
full trace of (threshold, k, p-value, certified). The pipeline runs it
at the configured operating point and also across a **frontier** of α
values (0.05, 0.10, 0.20, 0.30), recording the threshold and coverage at
each.

`research/artifacts.py` writes `calibration.json`: `t_hat`, `alpha`,
`delta`, `n_vuln_calib`, `ranker_id`, `corpus_version`, `is_provisional`,
`created_at`, the whole frontier, the certificate `method`, and
`n_vuln_groups`. The frontier is what powers scan-time
`--alpha`. A user can ask for any α that LTT actually certified. An α that
was not certified is refused with a list of the valid ones, and thresholds
are **never interpolated**, because an interpolated threshold carries no
guarantee. `is_provisional` is true whenever the corpus was simulated, and the
PDF and JSON reports surface it.

### 4.7 Evaluation

`scripts/run_eval.py` reports:

- oracle accuracy on hand-labelled fixtures;
- the corpus label distribution, with abstentions shown as their own bar;
- ranker separation (ROC-AUC) on the **held-out test split** — the figure
  to quote — beside the full-corpus figure, which includes training data;
- the LTT trace;
- an end-to-end scan of `examples/vulnerable_app/` against its known ground
  truth, without and (optionally) with the LLM verifier.

**The generator-shift experiment** (`research/eval/shift.py`) calibrates
LTT on three generators and measures the realized miss rate on the fourth,
which was never seen during calibration. It asks whether the certificate
survives a change in *who wrote the code*, the distribution shift a real
deployment faces.

---

## 5 · The online scanner

**Ingest** (`scan/ingest.py`). Walks the target, skips `venv`, `.venv`,
`site-packages`, `.git` and `__pycache__`, honours simple `.gitignore`
patterns, and uses `ast` to extract every function, method and nested
function as a unit. Each unit gets its source, line number, a content hash
and a token estimate. Unreadable files and syntax errors are reported, not
crashed on.

**Static pass.** One semgrep run over the whole target, with a local,
hand-written ruleset (`data/semgrep_rules/codegate_rules.yaml`). Its rules
are `codegate-sqli-string-build`, `codegate-cmdi-shell-true` and
`codegate-hardcoded-credential-assignment`. The free community packs were
measured to produce zero findings on this project's standard-library
patterns, because they target framework code. The local ruleset is also
fully offline. Findings are mapped back to the function that contains them.

**Rank and gate.** Every unit is scored by the shipped ranker.
`score ≥ t̂` auto-approves it under the certificate, with no LLM call.
Anything below is escalated. If the calibration certified nothing, everything
escalates.

**LLM verifier** (`scan/verifier.py`). Each escalated unit gets one call to
a Groq-hosted model (`openai/gpt-oss-120b`), with temperature 0 and a system
prompt that demands a single JSON object: `vulnerable`, `cwe`, `line`,
`reason`, `fix_hint`. Results are cached on disk under `.codegate_cache/` by
content hash, so re-scanning unchanged code costs nothing. The verifier is
optional by design: without a key, or on any API failure, escalated units
are reported as "needs review" and the scan still completes. Groq was
chosen for a free tier, speed (a verifier call sits in the scan's critical
path), and an OpenAI-compatible API that makes changing provider a new
class, not a redesign.

**Reports** (`report/`). All four formats are deterministic, and no LLM
writes any report prose:

- **Terminal:** a summary table and findings via `rich`.
- **JSON:** machine-readable output, including the certificate.
- **SARIF 2.1.0:** for code-scanning integrations.
- **PDF:** built with `reportlab` and `pygments` (pure Python, no external
  binary). Sections: cover, detection attribution, executive summary,
  cost & token accounting, findings detail with syntax-highlighted excerpts
  and remediation, coverage & certificate, and methodology & limitations.

Cost figures are explicitly labelled estimates. The price table is a
placeholder, and tokens are estimated at characters ÷ 4.

**CLI** (`cli.py`, built with `typer`):

```
codegate info                                   # the loaded model and certificate
codegate scan <path> [--format terminal|json|sarif|pdf] [--output FILE]
                     [--no-llm] [--alpha A]
codegate calibrate [--real] [--out-dir DIR]     # rebuild model + certificate (default DIR: data/model)
```

---

## 6 · Engineering practice

- **Test-driven fixes.** Every defect fix in the oracle work started as a
  failing test reproducing the real sample. The test was then made to pass,
  and the full suite rerun. The suite has **442 tests**. The largest file,
  `tests/test_oracle_ground_truth.py` (158 tests), pins hand-verified labels
  for every defect found on real data. Most detection tests have a
  deliberately safe twin, so a loosened detector shows up as a failure.
- **Guardrail: tests assert structure, never model values.** Retraining
  must not turn the suite red. A test that pinned a model number would be
  testing the data, not the code.
- **Measure before and after, on data already in hand.**
  `scripts/relabel.py` re-labels an existing corpus with the current
  oracles in minutes. Every oracle change was judged by its effect on real
  corpora: abstention rate, yield, and, most importantly, that safe flavors
  gained no false positives.
- **Never write exploratory output to `data/model/`.** Training always goes
  to a scratch directory. Promotion is a deliberate copy.
  `train_from_pregenerated.py` used to default to `data/model/`, and now
  requires `--out-dir`.
- **Continuous integration** (GitHub Actions, Linux): the full suite on
  Python 3.11 and 3.13, plus a *clean-install smoke test* that installs with
  no extras and no keys and runs every report format. The smoke test exists
  because a clean install was once completely broken. Every developer machine
  had an optional dependency installed, so nothing local ever noticed.
- **Honesty discipline.** Provisional certificates, estimated costs, and
  measurements that haven't been taken are labelled as such in the
  artifacts and reports themselves, not only in prose.

---

## 7 · Timeline

| Phase | What | Outcome |
|---|---|---|
| 0 | New repository; research code migrated; real packaging | `pip install -e .` works (it did not in v1) |
| 1 | Foundation fixes | The SQLi table-name bug and the abstain-as-safe bug found and fixed (8.1) |
| 1.5 | Ollama-only generation, `--generate-only`, two-machine workflow | Generation needs no API keys and executes nothing on the host |
| 2 | Persistence: model + certificate saved together, version guard | Mismatched pairs refused |
| 3 | Packaging and CLI | `info`, `calibrate` |
| 4 | Ingest | Function-level units |
| 5 | Scan pipeline | Static pass + certified gate |
| 6 | LLM verifier | Live-verified; deprecated model found and replaced (8.3) |
| 7 | Reports and CLI wiring | Four deterministic formats |
| 9 | Demo assets | `examples/vulnerable_app/` with known ground truth |
| 8 | Retrain on real data | First attempt certified nothing (Sept); after oracle repairs and a 2,160-sample run, certified and shipped (Oct 2026) |

---

## 8 · What went wrong, and how each was found

The defects below matter more than the features. Each was a way for the tool
to produce a *confident wrong answer*, the exact failure a certified scanner
exists to prevent.

### 8.1 The table-name bug hidden by abstain-as-safe

The SQLi harness created a table named `users`, while the prompts produced
queries against `t`. Every CWE-89 sample raised `no such table`, the oracle
abstained, and abstention was silently recorded as safe. The corpus *looked*
plausible. It was found by comparing the measured label distribution with
the rate the prompt design guarantees (22.2% measured vs 33.3% by design).
Fixed by widening the fixture and, more importantly, by making abstention a
third label state.

### 8.2 A clean install that never worked

`cli.py` eagerly imported the research pipeline, which imported
`matplotlib`, an optional dependency. Every command crashed on a plain
install, and no developer noticed, because every machine had the extra
installed. Found by setting up the clean-install CI job. Fixed with a lazy
import, and by moving semgrep into the core dependencies.

### 8.3 The verifier model vanished

The configured Groq model had been removed from Groq's catalog without
warning, and every call returned 404. The scanner's degrade-safely design
absorbed it (findings fell back to "needs review"), which also made it
invisible. Diagnosed with a direct `GET /models` call, and remapped to
`openai/gpt-oss-120b`.

### 8.4 The first real corpus certified nothing — and it wasn't the data size

The first real corpus (516 samples, September 2026) produced `t̂ = None` at
every α up to 0.30. Only **8** vulnerable samples reached calibration, one
short of the 9 needed even at α = 0.30. The obvious reading was "too little
data". Direct testing of the oracles showed **four defects** instead:

1. **Fixed-arity harnesses**: about 44% of prompts could never be judged.
   Every CWE-78 vulnerable label came from one-argument prompts.
2. **The SQLi oracle judged by row count**: it labelled injectable DELETEs
   safe and safe `COUNT(*)` queries vulnerable. That is label noise *in*
   the training data, which is worse than abstention.
3. **An entropy gate on passwords**: it missed most realistic secrets.
4. **A base model that produced no vulnerable code** (`starcoder2`).

Re-labelling the *same* 516 samples after the fixes took vulnerable
calibration samples from 8 to 25, without generating anything. Only then
was scaling the corpus worth doing.

### 8.5 Postgres idiom and the recording connection

After the first fixes, most remaining SQLi abstentions had one cause: models
write Postgres-style code (`%s` placeholders, `psycopg2`), which SQLite
rejects before anything can be observed. The recording DB-API connection
moved the observation point to the `execute()` call, which made detection
independent of whether the SQL is valid SQLite.

### 8.6 The resume bug

The full 2,160-sample run was written into a folder that still held the
September run's checkpoint. Resume matched samples by id alone, and the id
does not include the prompt's wording. So it silently reused **404**
September answers: 78 to credential prompts reworded since, and 189 with a
split reassigned since. Found by checking each sample's split against the
prompt bank and diffing code against the September corpus. Fixed with
prompt fingerprints. The corpus was repaired reproducibly
(`scripts/repair_real_2160.py`).

### 8.7 The second labelling round

Reading the full corpus showed the credentials oracle labelling **51 of 60**
vulnerable samples "safe" even though the pinned secret was present
verbatim. The secrets were in shapes the rules never reached: bytes
literals, tuples, webhook URLs, connection strings and more. A command
oracle was also abstaining on proven injections whose output parsing raised
afterwards, and on safe code whose input checks rejected every guessed
value. Each was fixed test-first.

Every changed verdict was checked against the oracle as it stood before.
Across three corpora, all credential flips moved from SAFE to VULNERABLE.
The only safe-flavor VULN labels left were read by hand: each is code the
model really wrote vulnerable despite a safe prompt.

### 8.8 A Windows-only success

All labelling ran on Windows. The first CI run of the new code on Linux
showed every command-injection check abstaining. The missing-module stub
finder had faked `msvcrt`, the module Python's `subprocess` uses to detect
Windows. Fixed by never stubbing a standard-library name. No shipped label
was affected, because no corpus sample imports a platform-absent standard
module.

### 8.9 A certificate that was right on paper and optimistic in practice

The first real certificate passed its own test, but on held-out data its
α = 0.10 threshold auto-approved 13.1% of vulnerable code. The cause was
structural, not bad luck. Four models answer each task, so the 206
vulnerable calibration samples are 66 correlated clusters (intra-group
correlation 0.57). The per-sample binomial test counted them as 206
independent draws. A seeded simulation confirmed it: under that
correlation the test certified thresholds that really missed more than α
in 8.5–12% of runs, against the 5% it promises. The cluster-aware
certificate (section 2.2) held in every setting, and on the real data it
stays within target. While building it, the generator-shift experiment
turned out to calibrate and measure on the ranker's own training samples;
it now uses the calibration split and unseen data only.

---

## 9 · Results

### 9.1 The corpus

| | |
|---|---|
| Generated (full run) | 2,156 of 2,160 |
| Repaired (stale answers removed, splits corrected) | 2,078 |
| **Shipped corpus** (prompts answered by all 4 models) | **2,040 = 510 prompts × 4** |
| Abstentions | 135 (6.6%) |
| Vulnerable among decided | 26.8% |
| Splits (samples) | train 820 / calib 812 / test 408 |

Abstention on the same pipeline was 28.3% in September and 19.2% after the
first repairs, and is 6.5–6.6% now.

### 9.2 The certificate (shipped)

| α | t̂ | coverage | vulnerable calibration samples |
|---|---|---|---|
Cluster-aware: 206 vulnerable calibration samples in 66 task groups.

| α | t̂ | coverage | vulnerable calibration samples |
|---|---|---|---|
| 0.05 | 0.9091 | 29.2% | 206 (66 groups) |
| **0.10 (shipped)** | **0.8259** | **48.8%** | 206 (66 groups) |
| 0.20 | 0.7634 | 60.3% | 206 (66 groups) |
| 0.30 | 0.7440 | 63.7% | 206 (66 groups) |

For comparison, the per-sample binomial certificate it replaced gave
t̂ = 0.7763 (56.4% coverage) at α = 0.10.

### 9.3 Generalization

| Measure | Result |
|---|---|
| Ranker ROC-AUC, held-out test split | **0.889** (0.925 including training data) |
| Held-out test split, share of vulnerable code auto-approved | **7.6% per task group, 9.3% per sample** vs α = 0.10 (95% cluster bootstrap 0.8–16.7%) |
| Generator shift (calibrate on 3, test the 4th on unseen data) | 3 of 4 within α = 0.10: 2.9% (codellama), 3.7% (deepseek), 7.0% (qwen); codegemma 11.0% (10 of 91, P = 0.43) |
| Demo app, static + gate only | precision 0.27, recall 1.00 (4 of 14 auto-approved) |
| Demo app, with verifier | not yet re-measured on the real model |

---

## 10 · Limitations and open issues

**Coverage.** The cluster-aware certificate is stricter: at α = 0.05 it
certifies only 29% coverage, so the shipped operating point is α = 0.10.
It assumes task groups are exchangeable with future tasks; the tasks are
hand-written, so that is a judgement about how representative the prompt
bank is, not something the statistics can check.

**Other open items:**

- 32% of safe command-execution samples still can't be judged: their
  validation demands real directories or paths under a base directory that
  no generated value satisfies. These samples are excluded, not mislabelled,
  but they are valuable hard negatives.
- The live verifier has not been re-measured on the real model.
- Cost figures are estimates (placeholder price table, characters ÷ 4).
- The sandbox is process-level isolation, adequate for code the team's own
  prompts generated, not for adversarial code.
- Three CWEs, Python only.

---

## 11 · Future work

1. **More task groups.** The certificate counts each task once, so more
   tasks, not more samples per task, is what buys coverage.
2. Re-measure the live verifier; record real token usage from the API's
   `usage` field.
3. Better harness values for path- and directory-validated code.
4. A code-embedding ranker for more coverage at the same guarantee.
5. More CWEs, each only once it has a reliable automatic ground truth.
6. **Ship the audited labels.** A label-by-label audit on 2026-10-05 found
   34 vulnerable samples labelled SAFE or not judged, mostly
   command-injection code judged by the labelling machine's own shell
   instead of POSIX shell rules. The corrected oracles are on branch
   `wip/label-audit-2026-10-05`; measured there, every audited error is
   fixed with no new false alarms on safe prompts, held-out ROC-AUC rises
   from 0.889 to 0.902, and the certificate stays within bound on held-out
   data (9.3% per task against 10%). Details:
   `docs/ENGINEERING_LOG.md` §14.

---

## 12 · Reproducing the results

```
pip install -e ".[dev,research]"
python -m pytest tests/ -q                                  # 442 tests

# label a corpus with the current oracles
python scripts/relabel.py --generations <generations.parquet> --out-dir <dir>

# rebuild the shipped corpus from the pushed run
python scripts/repair_real_2160.py --generations <as-received parquet> --out-dir data/runs/real_sym --symmetric

# train + calibrate into a scratch directory
python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_train --corpus-version real-2040-sym

python scripts/run_eval.py                                  # metrics
codegate info
codegate scan examples/vulnerable_app --no-llm
```

The as-received corpus is on branch `corpus/real-540`
(`data/runs/real_540/generations.parquet`).

---

## 13 · Glossary

| Term | Meaning |
|---|---|
| Abstention | The oracle could not reach a verdict. Excluded, never counted as safe |
| α (alpha) | The certified maximum miss rate |
| δ (delta) | The allowed probability that the certificate itself is wrong |
| Calibration split | Labelled data used only to certify the threshold |
| Coverage | The share of functions auto-approved at the threshold |
| Detonation | Running generated code against an exploit payload to observe the outcome |
| Exchangeable | Calibration data behaves like an independent sample of the data the tool will see |
| Flavor | vulnerable / near_miss / neutral version of one task |
| Frontier | The certified threshold and coverage at each α |
| LTT | Learn-Then-Test: the fixed-sequence testing procedure that certifies the threshold |
| Miss rate, R(t) | The share of vulnerable code scoring above t (auto-approved) |
| Near-miss | Safe code shaped like the vulnerable pattern |
| Oracle | An automatic labeller for one CWE |
| t̂ (t-hat) | The certified auto-approval threshold |
| Task group | One task with its three flavors; the unit of splitting |
