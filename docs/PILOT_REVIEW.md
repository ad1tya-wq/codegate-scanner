# Pilot Corpus Review

> **Status, later on 2026-10-04.** The full run had already been done. It
> arrived on `corpus/real-540`, partly contaminated by a resume defect. All
> three oracle problems below are fixed, along with several more the full
> corpus exposed. Training uses a generator-symmetric 2,040-sample subset.
> Details and numbers: `docs/ENGINEERING_LOG.md` §12.8–12.9. This page is
> kept as the pilot-stage record.

**Corpus:** `data/runs/pilot/generations.parquet`, from branch `origin/corpus/pilot` (commit `27b4598`, pushed 2026-09-14)
**Labelled with:** the oracles at `feat/certificate-restoration` HEAD `7583347`
**Reproduce:**

```bash
git show 27b4598:data/runs/pilot/generations.parquet > data/runs/pilot/generations.parquet
python scripts/relabel.py --generations data/runs/pilot/generations.parquet --out-dir data/runs/pilot_labeled
```

---

## 1. Verdict

**The pilot passes every gate in the plan (Task 9).** The prompts produce vulnerable code at a high rate, every generator contributes signal, and neither safe flavor produced a single vulnerable label.

It also turned up **three oracle problems**. Generation doesn't depend on any of them, so they don't block the full run. One of them can flip vulnerable code to a SAFE label, which is the dangerous direction for the certificate, so it has to be fixed before calibration.

**Recommendation:** tell the teammate to start the full 2,160-sample run (guide Part D) now, and fix the three oracle problems in parallel. Labelling is a separate step that runs after generation, so the oracle fixes can land while the run is still going. A labeller change never means regenerating.

---

## 2. What was uploaded

| Check | Expected | Actual | |
|---|---|---|---|
| Commit contents | one parquet file, nothing else | `data/runs/pilot/generations.parquet` only (51 KB) | ✅ |
| Base commit | `feat/certificate-restoration` | parent is `7583347`, the branch HEAD | ✅ |
| Samples | 108 | **107** | ⚠️ one missing |
| Generators | the 4 in `config.yaml` | qwen2.5-coder:7b, deepseek-coder:6.7b, codellama:7b, codegemma:7b-instruct | ✅ |
| Task groups | first 3 of each CWE | CWE-78/798/89 groups 001–003 | ✅ |
| Flavors | 3 per group | all present | ✅ |
| Splits | `id % 5` rule | 001–002 → train, 003 → calib | ✅ |
| `is_simulated` | False | False for all rows | ✅ |
| Unique code strings | > 90% | 107 / 107 (100%) | ✅ |
| Empty completions | 0 | 0 | ✅ |
| Completion length | n/a | 163–3,310 chars, median 940 | ✅ |

**The missing sample** is `codellama:7b` × `CWE-78-003-neutral`. The parquet can't tell us why — most likely one request timed out or errored. It doesn't matter for the pilot. The full run writes to a different directory (`data/runs/real_2160`), so nothing from the pilot gets reused. It's worth asking the teammate whether the console showed an error at that point. If codellama drops requests at scale, the full run will come back short, and re-running the same command fills the gaps.

The teammate pulled `codegemma:7b-instruct` successfully, so `config.yaml` needs no change.

---

## 3. Labelling results

107 samples, 10 m 48 s wall-clock (≈ 6 s/sample; most of that is semgrep — see §6).

| | |
|---|---|
| Abstentions | **10 (9.3%)** |
| Vulnerable among decided | 29 / 97 (29.9%) |
| `n_vuln_calib` | 9 (a pilot has only one calib group per CWE, so this number isn't a gate) |

### By CWE and flavor

| CWE | flavor | ABSTAIN | SAFE | VULN |
|---|---|---|---|---|
| CWE-78 | vulnerable | 0 | 1 | **11** |
| | near_miss | 4 | 8 | 0 |
| | neutral | 0 | 11 | 0 |
| CWE-798 | vulnerable | 0 | 3 | **9** |
| | near_miss | 0 | 12 | 0 |
| | neutral | 2 | 10 | 0 |
| CWE-89 | vulnerable | 0 | 3 | **9** |
| | near_miss | 4 | 8 | 0 |
| | neutral | 0 | 12 | 0 |

### By generator

| Generator | vuln-flavor → VULN | yield | near_miss ABSTAIN | neutral ABSTAIN |
|---|---|---|---|---|
| codegemma:7b-instruct | 9 / 9 | **100%** | 2 | 0 |
| codellama:7b | 8 / 9 | 89% | 2 | 2 |
| qwen2.5-coder:7b | 7 / 9 | 78% | 2 | 0 |
| deepseek-coder:6.7b | 5 / 9 | 56% | 2 | 0 |

Swapping out starcoder2 paid off: codegemma, its replacement, is the strongest generator in the pilot. In real-540 starcoder2 went 0 / 163.

### For comparison: the real-540 corpus after the oracle repairs

| | real-540 (after shim) | pilot |
|---|---|---|
| Abstention | 19.2% | **9.3%** |
| CWE-78 vuln-flavor → VULN | 38 / 56 (68%) | 11 / 12 (92%) |
| CWE-89 vuln-flavor → VULN | 30 / 58 (52%) | 9 / 12 (75%) |
| near_miss / neutral → VULN | 0 | 0 |

---

## 4. Gate check (plan Task 9)

| Gate | Threshold | Result | |
|---|---|---|---|
| Abstention rate | < 10% | 9.3% | ✅ (barely, and every abstention is explained in §5) |
| Vulnerable flavor → VULN | ≥ 35% | **80.6%** (29 / 36), 95% CI 65–90% | ✅ |
| near_miss → VULN | 0 | 0 / 36 | ✅ |
| neutral → VULN | 0 | 0 / 35 | ✅ |
| Every generator ≥ 1 VULN | yes | min is deepseek with 5 | ✅ |
| Unique code strings | > 90% | 100% | ✅ |

### What this projects for the full run

The calib split will hold 24 groups × 3 CWEs × 4 generators = **288 vulnerable-flavor samples**.

| Yield assumption | `n_vuln_calib` | misses LTT can tolerate at α = 0.05 |
|---|---|---|
| Pilot point estimate, 80.6% | ≈ 232 | k ≤ 5 |
| Pilot 95% CI lower bound, 65% | ≈ 187 | k ≤ 4 |
| The plan's pessimistic case, 35% | ≈ 101 | k ≤ 1 |

All three rows clear the minimum of 59, and the first two clear the working target of ≥ 120 comfortably.

**Caveat — the pilot only exercises groups 001–003.** These came over from the old 15-group bank and are among the most direct prompts. Groups 016–060 are new and haven't been seen by any model yet. Their yield could be lower, especially for the multi-statement SQL types (UPDATE, IN-clause, JOIN). Even halving the pilot yield still clears 120. This is why the full run gets labelled and checked before any training happens (Task 10, Step 2).

---

## 5. Findings — every non-ideal sample, inspected by hand

All 17 samples that weren't a clean expected verdict (10 abstentions, plus 7 vulnerable-flavor samples labelled SAFE) were read one by one. They fall into four groups.

### 5.1 Correct: the model ignored the "write it insecurely" instruction (4 samples)

| Sample | Prompt | Generator | What the model wrote |
|---|---|---|---|
| `a286a9b0-0` | CWE-78-001 vulnerable | deepseek | `subprocess.run(['ping','-c','4',host])`, a list argv with no shell |
| `215f6fdc-0` | CWE-89-001 vulnerable | qwen | `cursor.execute(query, (username,))` |
| `f41a1c52-0` | CWE-89-001 vulnerable | deepseek | `cursor.execute(query, (username,))` |
| `74adcf88-0` | CWE-89-003 vulnerable | codellama | `cur.execute("DELETE … WHERE id = ?", (order_id,))` |

The code really is safe, so SAFE is the right label. The vulnerable flavor is a request, not a guarantee, which is why yield comes in below 100%. The labeller is doing its job here.

### 5.2 ❌ Oracle problem 1: the creds oracle misses three real hardcoded secrets (3 samples) — **must fix**

| Sample | Generator | The secret | Why it was missed |
|---|---|---|---|
| `c0da0372-0` | deepseek | `headers = {'Authorization': 'Bearer sk_live_4eC39HqLyjWDarjtT1zdp7dc'}` | Secret-named **dict keys** aren't checked, and the name-independent sweep only recognises the `AKIA…` key shape |
| `139253bb-0` | deepseek | `smtp_client.login('svc_mailer', 'Tr0ub4dor3')` | A **positional argument** to a credential call. This was already logged as a known limitation (engineering log §12.4) |
| `c022adfd-0` | qwen | `Tr0ub4dor3 = 'Tr0ub4dor3'` … `server.login(svc_mailer, Tr0ub4dor3)` | The variable name isn't secret-ish, and the literal reaches `.login()` **through a local variable** |

**Why this is the serious one.** All three are vulnerable code labelled SAFE. That cuts in the dangerous direction:

- An abstention is just thrown away.
- A missed vulnerable label sits in the calibration set looking like a "correctly approved safe sample". The certificate then reports a lower miss-rate than the scanner really has.

In this pilot, 3 of the 12 CWE-798 vulnerable samples were mislabelled. That's 25%, and it lines up with deepseek's low measured yield (2 of its 4 "misses" are oracle errors, not model behaviour).

**Fix:**

1. Treat secret-named **dict keys** and **keyword arguments** like secret-named variables. That covers `Authorization`, `password`, `api_key`, `token`, `secret`, and the other names already in the oracle's list.
2. Flag string-literal **positional arguments** to known credential sinks: `.login()`, `HTTPBasicAuth()`, `.connect()` / `psycopg2.connect()`, `smtplib.SMTP*.login`, `requests.auth.*`.
3. Resolve a `Name` argument to a credential sink back to its local string-literal assignment in the same function. One hop, no general dataflow.
4. Add `sk_live_…` / `sk_test_…` / `Bearer <token>` to the shape list. These are specific shapes, unlike the entropy sweep that caused false positives last time (§12.4).

The guard rule stays the same as before. All 12 CWE-798 near_miss samples (every one reads `os.environ`) have to stay SAFE, and every existing negative test has to stay green.

### 5.3 ⚠️ Oracle problem 2: near-miss code that validates input against an allowlist abstains (8 samples)

**Every** generator abstained on two task groups:

| Group | Validation the prompt asks for | What the harness passes as the benign value |
|---|---|---|
| CWE-78-003 near_miss | `out_format` restricted to `{"png","jpg","webp"}` | `"alice"` → `ValueError` |
| CWE-89-002 near_miss | `table_name` must be a key of `{"products": …, "items": …}` | `"alice"` → `ValueError` |

Every call, including the benign control run, gets rejected at the validation step. The function never reaches its sink, so nothing is observed and the oracle abstains. That's the correct behaviour for "no evidence". The code is safe, but the harness never gets a value past the front door.

**Why it matters even though no label is wrong:**

- These are exactly the **hard negatives** the ranker needs: code that looks alarming and is safe because of validation. Losing them makes the ranker worse at the distinction the project exists to make.
- **19 of the 120** dynamic near_miss task groups in the full bank use this allowlist pattern. If every generator abstains on them, that's ≈ 76 samples, about 3.5% of the corpus, and all of them from the most valuable flavor.

Regex validation (CWE-78-002) and `isinstance` validation (CWE-89-003) didn't hit this, because `"alice"` and `1` happen to pass them.

**Fix:** before falling back to the name-based guess, collect candidate benign values from the function's **own string constants**: members of set/tuple/list literals and dict keys that appear in `in` comparisons. Try those in the control run. Take `convert_image("alice", "png")` as an example. It reaches `subprocess.run([...], shell=False)`, and the shell-free spawn is observed as SAFE evidence. The payload still goes into every position in turn, so code that's genuinely vulnerable is still caught. This is the same "positive evidence for SAFE" rule, just with better guesses.

### 5.4 Minor: `extract_code` misses two codellama output shapes (2 abstentions; a third is correct)

| Sample | Shape | Outcome |
|---|---|---|
| `79a71158-0` (CWE-798 neutral) | Indented code with a **closing** fence and no opening one, then prose | Recoverable → should be SAFE, currently ABSTAIN |
| `71891e94-0` (CWE-798 neutral) | Code wrapped in `<details><summary>…</summary> … </details>` | Recoverable → should be SAFE, currently ABSTAIN |
| `ec4e60fe-0` (CWE-89 neutral) | Inside `<details>`, `celsius_to_fahrenheit(c)` with no `def` and no colon | Genuinely broken code. Abstaining is correct (it was labelled SAFE because there's no SQL anywhere, which is also right) |

These hit only codellama and only neutral samples here, so the cost is small. In real-540, 8 codellama samples were unparseable after extraction (starcoder2's 93 no longer matter). **Fix:** add two fallbacks to `extract_code`: (a) text before an unmatched closing fence, dedented, and (b) the body of a `<details>` block. Both apply only when the existing delimiter patterns find no `def`.

### Abstentions after all three fixes

The 2 recoverable extraction cases plus the 8 allowlist cases make 10. That's every abstention in the pilot. After the fixes, the only one expected to remain is the broken `ec4e60fe-0`, which was already a decided SAFE. Expected abstention: **≈ 0–1%**.

---

## 6. Operational notes

- **Labelling speed:** about 6 s per sample, so ≈ 3.5 h for 2,160 samples. Almost all of that is the per-sample semgrep subprocess, and **semgrep can't change any label today**. The consensus rule only uses it as `semgrep_hit AND adjudicator_verdict`, and `adjudicator_verdict` is hard-wired `False`. Running `relabel.py --no-semgrep` gives identical labels much faster. Plan Task 15 (decide the adjudicator's fate) settles this for good.
- **Top-level usage code runs inside the sandbox.** Some completions end with an example call such as `print(ping_host('www.google.com'))`. That executes when the oracle loads the module. It's harmless (sandboxed, 15 s timeout) but adds latency, and on a machine with network access it makes a real ping. This behaviour isn't new and is noted here only for completeness.
- The extracted pilot files sit under `data/runs/`, which is git-ignored, so nothing from this review touches the branch's history.

---

## 7. What happens next

### Immediate: the teammate needs a decision from you

**Give the go-ahead for Part D, the full run:**

```bash
git pull
python scripts/run_real.py --generate-only --out-dir data/runs/real_2160
```

They should see `Planned samples: 2160`. Expect 6–18 h over about two sessions, with the file sent back after each one. Nothing in §5 needs them to change anything or wait. Every fix is on the labelling side and runs on our machine after generation.

### Mine, on `feat/certificate-restoration`, once you say go (none of this needs the teammate)

| # | Task | Done when |
|---|---|---|
| 1 | **Creds oracle**: dict keys, kwargs, credential-sink positional args, one-hop local resolution, `sk_live_`/Bearer shapes (§5.2) | The 3 pilot cases → True; every existing negative and all 12 pilot near_miss → still False |
| 2 | **Allowlist-aware benign values** in the shared invocation prelude (§5.3) | Both pilot near_miss groups → SAFE (not ABSTAIN); every ground-truth vulnerable case still True |
| 3 | **`extract_code` fallbacks** for an unmatched closing fence and `<details>` (§5.4) | The 2 recoverable pilot samples parse; existing extraction tests still pass |
| 4 | **Re-label the pilot and real-540** with the fixed oracles | Pilot abstention ≤ 1%, CWE-798 vuln → VULN 12/12; real-540 near_miss / neutral → VULN still 0 (the no-new-false-positives guard) |
| 5 | **Engineering log §12.8**: pilot numbers, these findings, before/after | Every number cites a command |
| 6 | **Held-out ranker AUC** (plan Task 12) | `scores_r2.parquet` carries `split`; `run_eval.py` reports held-out and full-corpus AUC side by side, each labelled |
| 7 | **Scan-time `--alpha`** (plan Task 14) | Frontier persisted in `calibration.json` with a backwards-compatible default; an uncertified α fails cleanly and lists the valid ones |
| 8 | **Real token accounting** (plan Task 13) | Verifier records the API's `usage`; savings stay labelled as an estimate |
| 9 | **Adjudicator decision** (plan Task 15, step 2) | Recommend **removing it**, which also removes semgrep's cost from labelling. **Needs your sign-off before I touch it**, because it changes a documented part of the design |
| 10 | **Stale test counts** in README / DEMO_GUIDE / TEAM_BRIEFING / ENGINEERING_LOG §7 (say 200; actual is 303+) | Every doc matches `pytest --collect-only -q` |

Items 1–5 come first. They have to be finished and verified before the full corpus arrives, so it gets labelled exactly once with the final oracles. Items 6–10 are independent of each other and of the data.

### After the full corpus arrives (plan Tasks 10–11, 15.1)

1. Volume and diversity check: 2,160 samples, a ~540 share per generator, unique-code rate.
2. Label with `--no-semgrep`, then re-check the four flavor gates at full scale.
3. Train and calibrate to `data/runs/real_2160_train` (**never** `data/model/`), read `t_hat` / `n_vuln_calib` / coverage, and only then promote.
4. Change `corpus_version` from the hardcoded `"real-540"` to `"real-2160"` (better still, read it from `config.yaml`).
5. Generator-shift experiment on the certified corpus.
6. Update every document that carries a now-stale number.
