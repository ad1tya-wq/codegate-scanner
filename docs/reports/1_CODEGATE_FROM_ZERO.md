# CodeGate from zero

*Report 1 of 3 — understand the project.* Report 2 explains how each part
works in detail; report 3 defends it against the hard questions.

This report assumes no background in security or statistics. It starts
from the problem, builds up every idea the project uses, and ends with
what the shipped tool does and how well. Every term in **bold** at first
use is in the glossary at the end. Every number comes from the committed
artifacts or `docs/ENGINEERING_LOG.md`, which names the command behind it.

---

## 1 · The problem, in one page

AI coding assistants write a large share of new code. Studies of their
output (Pearce et al., *Asleep at the Keyboard?*, IEEE S&P 2022) found
that a real fraction of it contains old, well-understood security bugs.
The code looks fine and runs fine, so a busy reviewer approves it.

Three of those bugs are the subject of this project:

- **SQL injection** (CWE-89). The code builds a database query by gluing
  user input into the query text. Input such as `x' OR '1'='1` then
  changes what the query means — for example, it returns every user.
- **OS command injection** (CWE-78). The code builds a shell command by
  gluing in user input. Input containing a shell separator followed by
  another command then runs that second command too.
- **Hardcoded credentials** (CWE-798). A password or API key is written
  into the source, so anyone who sees the code, a backup or the git
  history has it.

Two kinds of tool exist to catch these, and each has a hole:

| | Static analysis (pattern rules) | Asking an LLM to review every function |
|---|---|---|
| Speed and cost | fast, free | slow, paid per call |
| What it catches | only patterns someone wrote a rule for | flexible, catches new shapes |
| What it tells you about what it **missed** | nothing | nothing |

Neither answers the question a person deciding whether to merge actually
has: *of the code you did not flag, how much is still vulnerable?*

## 2 · The idea

CodeGate puts a **gate** in front of the expensive LLM:

```
every function ──► cheap score (0 = looks dangerous, 1 = looks safe)
                       │
          score ≥ t̂ ? ─┼── yes ──► auto-approved, no LLM call
                       └── no  ──► escalated to an LLM verifier
```

The interesting part is the threshold **t̂**. It is not picked by eye. It
is computed by a statistical procedure, **Learn-Then-Test**, from a set of
code samples whose true answer is known, and it comes with a guarantee
stated in advance:

> Averaged over coding tasks, at most **α = 10%** of vulnerable functions
> score above t̂ and get auto-approved — and the procedure that chose t̂
> is wrong about that with probability at most **δ = 5%**.

That guarantee is the **certificate**. It is the thing a static analyzer
or an LLM reviewer cannot give you: a bound on what the tool lets through.

Three properties make it more than a threshold that "looked good":

1. **It is computed, not asserted** — it is the outcome of a hypothesis
   test on labelled data.
2. **It does not depend on the scorer being good.** A weak scorer leads to
   a *stricter* t̂ (less code auto-approved, more escalated, more LLM
   cost). It cannot produce a false guarantee.
3. **It can say "not yet."** If the evidence supports no threshold, none is
   certified and everything is escalated. That happened to this project
   once, and it was the method working (section 4).

## 3 · Where the known answers come from

The certificate is only as good as the data it is computed from, and that
data has to be **labelled**: for each code sample, is it actually
vulnerable or not? Hand-labelling thousands of samples was not an option,
and labelling by pattern rules would make the certificate inherit the
rules' blind spots. So the project builds its own labelled data in four
steps.

**Step 1 — write prompts.** The **prompt bank** (`data/prompts/`) holds
180 programming **tasks**, 60 per vulnerability type. Each task is asked
three ways, called **flavors**:

| Flavor | What the prompt asks for | Example (one task) |
|---|---|---|
| **vulnerable** | the task, built the unsafe way | "Write `get_user(conn, username)`… build the SQL by formatting the username into the query" |
| **near_miss** | the task, built safely, but looking alarming | "…using a parameterized query" |
| **neutral** | an unrelated, harmless task | "Write `is_palindrome(s)`…" |

Near-misses are the key design decision. Without them, a scorer could
learn "anything mentioning `subprocess` is dangerous" and still look
good. Near-misses force it to learn the difference between dangerous and
merely alarming code.

**Step 2 — have real models write the code.** Four open-weight code
models, run locally through Ollama, answer every prompt once:
`qwen2.5-coder:7b`, `deepseek-coder:6.7b`, `codellama:7b` and
`codegemma:7b-instruct`. These are the **generators**. Four different
model families means four different coding habits, which the project
later uses to test whether the certificate survives a change of author.
180 tasks × 3 flavors × 4 models = 2,160 planned samples; the shipped
**corpus** is the 2,040 for which all four models answered (510 prompts ×
4).

**Step 3 — label every sample with an oracle.** An **oracle** is an
automatic judge that decides, for one sample, VULN or SAFE — or
**ABSTAIN** when it cannot tell.

- For SQL injection, the oracle *runs* the generated function with a
  database connection that records every query handed to it, passes an
  attack string in each parameter, and checks whether the attack string
  ended up inside the query **text** (injection) or only as a separately
  passed value (safe).
- For command injection, the oracle *runs* the generated function in a
  sandbox with a harmless test input in each parameter, built so that if
  the input reaches a shell it creates a marker file. A marker file that
  appears is direct proof the input was interpreted as a command.
- For hardcoded credentials, running the code cannot tell you whether a
  string is a real password, so the oracle reads the syntax tree with
  exact rules: a real-looking secret literal reaching a password
  variable, a credential call, an auth header, and so on.

**Abstain is a third answer, never a disguised "safe".** If an oracle
cannot reach a verdict — the code doesn't parse, the function never got
as far as its database call — the sample is excluded from training and
calibration. Counting such samples as safe once hid a bug that mislabelled
a third of a corpus (section 4).

**Step 4 — split by task.** Each task's samples go to one of three
**splits**, never divided: **train** (teach the scorer), **calib**
(compute the certificate) and **test** (check the certificate on data it
never saw). 24 / 24 / 12 tasks per vulnerability type.

## 4 · The journey, 0 to 100

| When | What happened | What it taught |
|---|---|---|
| Aug–Sep 2026 | Whole pipeline built against a *simulated* corpus (template code), so every part could be tested before any real model ran | Engineering first; the shipped certificate was marked **provisional** |
| Early Sep | Labels coerced to SAFE when an oracle failed hid a bug: the SQL oracle created the wrong table, so 540 of 540 samples silently "passed" | Abstain must be its own label |
| Sep | First real corpus (540 samples): **no threshold certified at any α** | The method refused to certify, correctly |
| Sep | Diagnosis: not too little data — the *labeller* was broken (called functions with the wrong number of arguments, misjudged non-SELECT queries, rejected realistic passwords) | Fix ground truth before scaling |
| Sep–Oct | Oracles repaired test-first; a 2,160-sample corpus generated on a teammate's machine | First real certificate, Oct 4 |
| Oct 4 | The certificate's own math assumed samples are independent; four models answering one task are not. Held-out data showed it promising 10% and delivering 13% | Made the certificate **cluster-aware**: each task counts once |
| Oct 5 | A label-by-label audit of every suspicious label: SQL labels all correct; 34 vulnerable samples labelled SAFE or not judged, mostly command-injection code judged by the labelling machine's Windows shell | The labeller judges commands by POSIX shell rules and runs nothing; the model is retrained on the corrected labels and ships (report 2, section 6) |

The pattern across the whole project: every serious problem was a
**labelling** problem, and every one was found by checking the data, not
by tuning the model.

## 5 · What the shipped tool does

```
codegate scan path/to/project
```

1. **Ingest** — every Python function in the project becomes a unit.
2. **Static pass** — one semgrep run with three hand-written rules flags
   the textbook cases outright.
3. **Score and gate** — every function is scored; score ≥ t̂ is
   auto-approved under the certificate, the rest are escalated.
4. **Verify** — each escalated function gets one LLM call (Groq,
   `openai/gpt-oss-120b`, JSON answer, cached by content hash). Without
   an API key, escalated functions are reported "needs review" and the
   scan still completes.
5. **Report** — terminal, JSON, SARIF or PDF. The PDF states the
   certificate, its method and its limits.

The scanner **never executes** the code it scans. Running code is only
how the training labels were made, on the team's machine, against code
the team's own prompts produced.

## 6 · How well it works (shipped model)

| Measure | Result |
|---|---|
| Corpus | 2,040 samples from 4 models; 28.3% of judged samples vulnerable; 5.6% abstained; labels audited by hand |
| Certified threshold | t̂ = 0.8023 at α = 0.10, δ = 0.05, cluster-aware over 66 task groups |
| Coverage (calibration code auto-approved, no LLM call) | 50.0% |
| Stricter option | α = 0.05 also certified: t̂ = 0.8916, 31.5% coverage (`--alpha 0.05`) |
| Held-out check: vulnerable test code auto-approved | 9.3% per task (the certified quantity; 95% interval 1.8–19.2%) against 10%; 10.7% pooled per sample |
| Scorer quality on unseen code (ROC-AUC) | 0.903 |
| Change of author (calibrate on 3 models, test the 4th) | 3 of 4 within 10% (4.2%, 3.5%, 6.4%); codegemma 10.5%, within noise |
| Demo app, without the LLM | 14 functions: 4 auto-approved, 10 escalated; every real vulnerability caught (recall 1.00, precision 0.27) |
| Automated tests | 515, all passing |

How to read it: on the calibration data, about half of all code clears
the threshold and needs no LLM call, while the guarantee caps what slips
through among the vulnerable code at 10%, averaged over tasks. On the test
split, which the certificate never saw, the share that actually slips
through is 9.3% averaged over tasks.

## 7 · What it does not claim

- **Three bug types, Python only.** Everything else is out of scope.
- **The guarantee is about the population of tasks it was calibrated on.**
  If future code looks nothing like these 180 tasks, the guarantee does
  not transfer automatically. The generator-shift experiment (report 2)
  tests one kind of change and finds three of four models within bound.
- **The scorer is simple** (a bag of hashed tokens and a logistic
  regression). That costs coverage — how much code is auto-approved — not
  correctness of the guarantee.
- **Labels are automatic.** They were audited by reading every
  suspicious one (report 2, section 6), and the shipped model is trained
  on the corrected labels. An automatic labeller can still be wrong in
  ways nobody has looked for yet; every change to it is checked against
  every safe-prompt sample of four corpora.

---

## Glossary

| Term | Meaning in this project |
|---|---|
| **α (alpha)** | The miss rate the certificate promises not to exceed: the share of vulnerable functions auto-approved, averaged over tasks. Shipped at 0.10; 0.05 is also certified. |
| **Abstain** | An oracle's third answer, "cannot tell". Abstained samples are excluded from training and calibration — never counted as safe. |
| **Auto-approve** | Let a function through without an LLM call because its score is at or above t̂. |
| **Calibration split ("calib")** | The tasks whose samples are used only to compute the certificate. |
| **Certificate** | t̂ plus the statement "averaged over tasks, at most α of vulnerable functions score ≥ t̂, with confidence 1 − δ". Stored in `data/model/calibration.json`. |
| **Cluster-aware** | Counting each task once as evidence, however many models answered it, because answers to one task are correlated. Implemented with the Hoeffding–Bentkus test. |
| **Corpus** | The collection of generated, labelled code samples: 2,040 in the shipped model. |
| **Coverage** | The share of calibration code (all of it, safe and vulnerable) at or above t̂: how much code the gate saves from the LLM. |
| **CWE** | Common Weakness Enumeration — the standard catalogue of software weakness types. CWE-89 SQL injection, CWE-78 OS command injection, CWE-798 hardcoded credentials. |
| **δ (delta)** | The allowed probability that the certificate itself is wrong. 0.05, i.e. 95% confidence. |
| **Detonation / dynamic oracle** | Running the generated function with a test input and observing what it does: for SQL, the exact query text it sends to a recording database connection; for commands, whether a harmless marker file appears. |
| **Escalate** | Send a function below t̂ to the LLM verifier (or mark it "needs review"). |
| **Exchangeability** | The statistical assumption behind the certificate: the calibration tasks and future tasks are like draws from the same pool, in no particular order. |
| **Flavor** | One of three ways a task is asked: vulnerable, near_miss, neutral. |
| **Generator** | A model that wrote corpus code: qwen2.5-coder, deepseek-coder, codellama, codegemma. |
| **Generator shift** | Calibrating on three generators and checking the miss rate on the fourth, to see whether the certificate survives a change of author. |
| **Held-out / test split** | Tasks used for neither training nor calibration, kept back to check the certificate on unseen data. |
| **Hoeffding–Bentkus** | The statistical test the certificate uses on per-task miss fractions; valid for any values between 0 and 1. |
| **LLM** | Large language model. Used twice: four local models *write* the corpus, and one hosted model *verifies* escalated functions at scan time. |
| **LTT (Learn-Then-Test)** | The procedure that turns labelled data into a certified threshold by testing candidate thresholds from strictest to loosest and stopping at the first that fails. |
| **Miss rate** | The share of vulnerable functions that are auto-approved. |
| **Near-miss** | Safe code written to look like the vulnerable version; the hard negatives that teach the scorer what actually matters. |
| **Oracle** | An automatic judge that labels one sample VULN, SAFE or ABSTAIN. |
| **Prompt bank** | The 540 prompts (180 tasks × 3 flavors) in `data/prompts/`. |
| **Provisional** | A certificate computed on simulated data; flagged in every report. The shipped certificate is not provisional. |
| **Ranker / scorer** | The cheap model that scores each function from 0 (looks dangerous) to 1 (looks safe). |
| **ROC-AUC** | How well the scores separate vulnerable from safe code: 0.5 is chance, 1.0 is perfect. |
| **Split** | Train, calib or test; assigned per task, so all of one task's samples share a split. |
| **t̂ (t-hat)** | The certified threshold. |
| **Task group** | One task with its three flavors and every model's answer to each — the unit the cluster-aware certificate counts. |
| **Verifier** | The hosted LLM that judges escalated functions at scan time. |
| **VULN / SAFE** | An oracle's verdicts: the sample contains / does not contain the vulnerability. |
