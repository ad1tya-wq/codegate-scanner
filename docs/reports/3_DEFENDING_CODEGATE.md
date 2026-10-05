# Defending CodeGate

*Report 3 of 3 — defend the project.* Report 1 explains the ideas; report 2
explains the machinery. This report states each claim the project makes,
the evidence behind it, and answers to the hardest questions a reviewer is
likely to ask. Every answer cites a number that can be reproduced
(`docs/ENGINEERING_LOG.md` names the command for each).

---

## Part A · The five claims and their evidence

### Claim 1 — The guarantee is real, not asserted

**Claim.** Averaged over coding tasks, at most 10% of vulnerable functions
are auto-approved, with 95% confidence.

**Evidence.**
- It is the output of Learn-Then-Test, a published, peer-reviewed procedure
  (Angelopoulos, Bates et al.), implemented in `gate/ltt.py` and traced
  threshold by threshold in `data/model/ltt_trace.csv`.
- The test is **cluster-aware**: each task counts once, because four
  models answering one task give correlated samples (ICC 0.66).
- In simulation with our task sizes, the cluster-aware test never certified
  a threshold that really missed more than 10% in more than 1 of 400 runs
  at any correlation level (0.3% at most, against the 5% allowed). The
  standard per-sample test did in 7–18% of runs once samples correlate —
  which is why it was replaced.
- On data the certificate never saw, 9.3% of vulnerable code was
  auto-approved per task, within the 10% bound.

### Claim 2 — The labels are trustworthy

**Evidence.**
- Two of three labellers run the code rather than match patterns: the SQL
  oracle sees the exact query text, the command oracle sees the exact
  command line (nothing is executed) and reads it with POSIX shell grammar.
- "Could not tell" is its own label and is never counted as safe.
- 515 tests, most detection tests paired with a safe twin.
- Every suspicious label was read by hand on 2026-10-05. The SQL labels
  were all right; the command-injection labeller was judging by the
  labelling machine's own (Windows) shell and was rebuilt. The shipped
  model is trained on the corrected labels: 108 of 2,040 changed, each
  explained, and no sample from a safe prompt became vulnerable.

### Claim 3 — It saves LLM calls without hiding misses

**Evidence.** 50% of calibration code clears the certified threshold and
needs no LLM call. On the demo app, static pass + gate catches every real
vulnerability (recall 1.00) while auto-approving 4 of 14 functions.

### Claim 4 — It is robust to who wrote the code

**Evidence.** Calibrated on three models and tested on the fourth's unseen
code: 4.2%, 3.5%, 6.4% within 10%, and codegemma at 10.5% (10 of 95), which
a true 10% rate produces 48% of the time. The guarantee is not *claimed* to
transfer to a new author; the experiment shows it did in practice.

### Claim 5 — The engineering can be trusted

**Evidence.** Test-first fixes from real samples, tests that never pin
model numbers, CI on two Python versions plus a clean-install smoke test,
artifacts written to scratch directories and promoted deliberately, and an
engineering log that cites a command or commit for every number.

---

## Part B · Hard questions

**Q1. Why not just run semgrep, or just ask an LLM?**
Neither says anything about what it missed. Semgrep catches the patterns it
has rules for; an LLM reviewer is a judgement with no error rate. CodeGate
uses both (semgrep first, the LLM for escalated code) and adds the one thing
neither gives: a certified bound on what is waved through.

**Q2. Isn't a 10% miss rate too high for security?**
It is a bound on the *gate*, not on the whole tool: the static pass still
runs on everything, and the bound is an upper limit (the observed rate on
calibration code at t̂ is about 2%). α is a dial: `--alpha 0.05` is also
certified and halves the bound, at the cost of escalating more code (31.5%
auto-approved instead of 50.0%). More tasks in the corpus are what make a
strict α cheap.

**Q3. Why 66 task groups? Isn't that small?**
The certificate counts tasks, not samples, so 66 is the honest size of the
evidence. That is exactly why the threshold is conservative (2% observed vs
10% certified). The plan is more tasks, not more answers per task: extra
answers to the same task are correlated and add little.

**Q4. Your corpus is LLM-written code from your own prompts. Is it
representative?**
It is representative of AI-generated code for these three weakness types,
which is the scanner's target. The statistical assumption is that future
tasks look like these 180; that is a judgement about the prompt bank, not
something statistics can prove, and the report says so. The generator-shift
experiment tests one kind of change (a new author) and the certificate held.

**Q5. Why does the certificate bound the average over tasks instead of the
per-function rate?**
Because that is what the evidence supports. Each task is one independent
piece of evidence, so the natural quantity is the average task's miss rate.
A per-function bound under the same assumptions was implemented and
measured: at this corpus size it certifies nothing at any α. Every report
now states the guarantee as "averaged over coding tasks".

**Q6. Isn't Hoeffding–Bentkus too conservative? Could you get more
coverage?**
We tried a tighter, betting-style test (Waudby-Smith & Ramdas), on the
labels before the audit. It certified more coverage at α = 0.10 (53.6%),
but its threshold then auto-approved 13.1% of held-out vulnerable code,
and it certified nothing at α = 0.05. The conservative test is the one that kept its promise on
unseen data.

**Q7. codegemma came in at 10.5%. Doesn't that break the guarantee?**
No, for two reasons. The guarantee covers code like the calibration data;
a model never seen in calibration is outside it, and the experiment exists
to measure how far it stretches. And 10 misses out of 95 is what a true 10%
rate produces 48% of the time; it is not evidence of a violation.

**Q8. ROC-AUC 0.903 isn't impressive. Why such a simple ranker?**
Because the guarantee does not depend on the ranker. A better ranker
auto-approves more code at the same bound; a worse one auto-approves less;
neither can make the bound false. The project spent its effort on labels
instead, where errors *do* affect the bound. A stronger ranker is a planned
drop-in improvement.

**Q9. Precision 0.27 on the demo app looks bad.**
That is the static pass plus gate *before* the LLM verifier, on a
14-function target. The gate's job is not to miss vulnerabilities (recall
1.00); clearing the escalated safe code is the verifier's job. On a tiny
target a strict threshold escalates most functions; that costs LLM calls,
never misses.

**Q10. Did you tune anything on the test split?**
No. The test split is used only to check the certificate after the fact.
Twice a retrain did worse on the test split and was still promoted because
its labels were more correct, most recently after the label audit (held-out
miss rate 7.6% to 9.3% per task, both within bound; scored on the same
corrected labels the old model also misses 7.6%, so the change is the new
threshold, not the labels). Choosing a model by its test score would have
biased the check.

**Q11. You execute LLM-generated code. Isn't that dangerous?**
Only in the offline labelling step, on the team's machine, against code the
team's own prompts produced, in a sandboxed process with a timeout. The
scanner never executes the code it scans, and a test proves it.

**Q12. Why did the labels change so many times during the project?**
Because each time the data was checked, it revealed a labeller defect, and
each defect was fixed test-first and measured on corpora already in hand.
That is the project's method working: the first real run certified nothing,
and the cause turned out to be the labeller, not too little data.

**Q13. How do you know the oracles are right?**
Fixtures with textbook examples (6 of 6 correct), 515 tests with safe twins,
false-alarm checks on every safe-prompt sample across several corpora after
every change, a battery of twenty safe shell idioms the command oracle must
never flag, and a full manual audit of suspicious labels (Claim 2).

**Q14. What does δ = 0.05 mean in plain words?**
If the whole calibration were repeated with fresh tasks, at most 1 time in
20 would the procedure choose a threshold that fails its 10% promise.

---

## Part C · Planned improvements

**C1. More task groups.** The direct lever on coverage, and what would make
α = 0.05 practical.

**C2. A stronger ranker** (code embeddings) for more coverage at the same
guarantee.

**C3. Re-measure the live verifier** on the real model, with real token
usage from the API.

**C4. More weakness types and languages**, each added only once it has a
reliable automatic ground truth.

---

## Part D · The one-minute defence

CodeGate scans Python for three classic AI-introduced vulnerabilities. It
sends to an expensive LLM only the code it cannot certify, and for the rest
it gives a computed guarantee: averaged over tasks, at most 10% of
vulnerable functions slip through, with 95% confidence. The guarantee comes
from a published statistical procedure, made cluster-aware after we caught
the standard version over-promising on our own data, and it held on code it
never saw and on three of four unseen model families. The labels behind it
come from running the code and were audited by hand; the model ships on
the corrected labels.
