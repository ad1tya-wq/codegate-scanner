# Label-Audit Completion Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking. This file is also the progress report: each task's checkboxes are ticked as they land, and the **Progress log** at the end records what shipped, what is tested, and what is deferred, in order.

**Goal:** Ship the audited labels. Finish the review and verification of the label-audit oracle changes, retrain on the corrected labels, promote the new model only if its certificate still holds on held-out data, update every document and report that quotes a number, and merge into `main`.

**Architecture:** No new components. The work runs on branch `wip/label-audit-2026-10-05` (local working branch `review/label-audit-fixes`, in the git worktree `.worktrees/label-audit` so the `main` checkout is never touched). Retraining writes to a scratch run directory under `data/runs/` (git-ignored) and is promoted to `data/model/` by a deliberate copy, exactly as `scripts/train_from_pregenerated.py` requires.

**Tech Stack:** Python 3.13 locally (CI: 3.11 and 3.13), pytest, semgrep 1.179, pandas/pyarrow, scikit-learn (R2 ranker: hashing vectorizer + logistic regression), numpy/scipy (cluster-aware LTT), reportlab (PDF report). `docs/word/*.docx` have no generator in the repo, so they are updated by editing `word/document.xml` in place, which keeps their styling.

**Spec:** `docs/superpowers/specs/2026-08-28-codegate-design.md`. Audit context: `docs/LABEL_AUDIT_HANDOFF.md`, `docs/ENGINEERING_LOG.md` section 14.

## Global Constraints

- **Merge gates.** Nothing is promoted or merged into `main` unless every gate holds:
  - **G1 Tests:** the full suite passes locally on Python 3.13 with semgrep installed, and CI is green on 3.11 and 3.13 including the clean-install job. No test is weakened, deleted, or marked `xfail` to pass.
  - **G2 No false alarms:** no sample from a non-vulnerable prompt (`neutral`, `near_miss`) is labelled VULN on any of the four corpora (`real_sym`, `real_2160`, `real_540`, `pilot`) unless that label was read by hand and is correct.
  - **G3 Every label change explained:** every label that differs from the previous run is listed with a reason, by `sample_id`.
  - **G4 Certificate holds:** the retrained model's α = 0.10 threshold is certified (cluster-aware, δ = 0.05) and its realized held-out miss rate per task group is at most 0.10.
  - **G5 No regression the docs would hide:** held-out ROC-AUC, coverage, generator-shift results and the end-to-end demo scan (recall 1.00) are reported next to the shipped numbers; any that get worse are stated as worse.
  - **G6 Docs consistent:** every document, Word version and report that quotes a model number quotes the promoted model's number.
- The certificate's definition, the split (by prompt, never by sample) and the risk definition are not changed by this plan.
- Exploratory runs never write to `data/model/`. Promotion is one explicit commit.
- Commit after every task; push after every commit once push access exists.

---

## Task 0: Close the code-review findings (done)

**Files:**
- Modify: `src/codegate/oracles/shell_recorder.py`, `src/codegate/oracles/cmdi_oracle.py`, `src/codegate/oracles/ast_utils.py`, `src/codegate/research/pipeline.py`
- Modify: `docs/LABEL_AUDIT_HANDOFF.md`

- [x] **Step 1:** Fix the 11 open findings test-first against the failing tests already on the branch (commit `ef9e3c7`). Itemised change list: `_patches/CHANGES_2026-10-05.md` (outside the repo) and the table in `docs/LABEL_AUDIT_HANDOFF.md`.
- [x] **Step 2:** Relabel all four corpora against the v9 labels and read every changed label by hand (G2, G3 for the oracle change).

## Task 1: Bring `main` into the branch

- [x] **Step 1:** Merge `main` (three reports, `.gitattributes`, PDF fix) into the working branch (commit `f752b06`). One conflict, `README.md` metrics table, resolved to the branch side because those numbers are replaced in Task 5.

## Task 2: Verification loop (G1)

Repeat until clean: build (editable install), unit tests, integration tests, full suite.

- [x] **Step 1: Build.** `uv pip install -e ".[dev,research]"` into a Python 3.13 venv (scikit-learn pinned to 1.7.2, the version the shipped `model.joblib` was pickled with); `codegate info` runs.
- [x] **Step 2: Unit tests.** Oracle, recorder, extraction and labelling tests:
  `pytest tests/test_oracle_ground_truth.py tests/test_oracle_robustness.py tests/test_pipeline_extract_code.py tests/test_oracles.py tests/test_oracle_invocation.py tests/test_dbapi_recorder.py tests/test_relabel.py -q`
- [x] **Step 3: Integration tests.** Pipeline, scan, CLI and reports: `test_dry_run`, `test_scan_pipeline`, `test_cli`, `test_report_*`, `test_eval*`, `test_ltt`.
- [x] **Step 4: Full suite** with semgrep installed: `pytest tests/ -q`. Expected: every test passes. (Locally, semgrep needs `SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off` when its network calls are blocked, or each call waits ~95 s.)
- [x] **Step 5: Independent review** of the diff `a018cce..HEAD` for the oracle files, looking specifically for false-alarm paths (a SAFE construct the new tokenizer or payloads would call VULN).

## Task 3: Relabel and audit (G2, G3)

- [x] **Step 1:** `python scripts/relabel.py --generations data/runs/<corpus>/generations.parquet --out-dir data/runs/<corpus>_labeled_v10` for all four corpora.
- [x] **Step 2:** Diff v10 against v9 and against the shipped labels (`data/model/labeled.parquet`); read every change.

## Task 4: Retrain to scratch and compare (G4, G5)

- [ ] **Step 1:** `python scripts/train_from_pregenerated.py data/runs/real_sym/generations.parquet --out-dir data/runs/real_sym_v10 --corpus-version real-2040-sym`
- [ ] **Step 2:** `python scripts/run_eval.py --model-dir data/runs/real_sym_v10`
- [ ] **Step 3:** Table: shipped (`data/model`) vs v9 vs v10 for abstention, vulnerable rate, n_vuln_calib / groups, t̂, coverage, held-out miss rate per task and per sample with cluster bootstrap CI, ROC-AUC, generator shift, demo scan precision/recall.

## Task 5: Promote and document (G5, G6)

- [ ] **Step 1:** Copy the v10 artifacts into `data/model/`; commit as the promotion.
- [ ] **Step 2:** Update every number in `README.md`, `docs/PROJECT_REPORT.md`, `docs/ENGINEERING_LOG.md` (new section 15 + section 14.4 results), `docs/datasheet.md`, `docs/DESIGN_RATIONALE.md`, `docs/PANEL_QA.md`, `docs/TEAM_BRIEFING.md`, `docs/DEMO_GUIDE.md`, `docs/reports/*.md`, `docs/LABEL_AUDIT_HANDOFF.md` (status: shipped).
- [ ] **Step 3:** Regenerate `docs/word/*.docx` and `examples/vulnerable_app/sample_report.pdf`.
- [ ] **Step 4:** Grep for every superseded number; none may remain outside history sections.

## Task 6: Merge (all gates)

- [ ] **Step 1:** Push the branch; CI green on 3.11 and 3.13.
- [ ] **Step 2:** Merge into `main` (no fast-forward), push, confirm CI on `main`.

---

## Progress log

### 2026-10-05, report 1

**Shipped:** Task 0 (`ef9e3c7`), Task 1 (`f752b06`). Local push access: none yet; commits are on the local branch `review/label-audit-fixes`.

**Tested:** before the merge, all 15 previously failing tests pass; the suite passes except 4 semgrep tests (semgrep was not installed then) and one slow training test that was not run. Relabel against v9: 6 labels change on `real_sym` and `real_2160`, none on `real_540` or `pilot`; no new VULN on a non-vulnerable prompt.

**Deferred / open:** four `near_miss` samples (`9332bbf0-0`, `3eafb6d1-0`, `8401c76a-0`, `b127254f-0`) now abstain because their input never reaches a process. Kept strict on purpose (see the handoff doc); revisit only with a rule that cannot pass a vulnerable branch skipped by the fake empty process output.

### 2026-10-05, report 2

**Shipped:** Task 2 (verification loop) and Task 3 (relabel and audit). New regression test `test_cmdi_oracle_safe_constructs_never_fire` (20 safe shell constructs) and `test_cmdi_oracle_battery_controls_fire` (2 controls), commit `f7593a9`. Commit trailers removed from every branch commit at the owner's request; commits are authored `ad1tya-wq`.

**Tested (G1, local):** full suite on Python 3.13 with semgrep 1.179: **493 passed, 0 failed** across all 29 test files before the battery, 515 with it (`main` has 442). Includes the slow `test_dry_run` (71 s) and `test_cli::test_calibrate_writes_model_and_calibration` (73 s). Independent false-alarm review: 0 of 20 safe constructs labelled VULN; `env_var_passing` abstains (input travels in the environment).

**Relabel (G2, G3).** Labels written to `data/runs/<corpus>_labeled_v10/` by a parallel run of exactly `label_row(extract_code(code))`; on `pilot` it was checked identical to `scripts/relabel.py`'s output.

| Corpus | Samples | vs v9 | Abstention v9 to v10 | VULN (decided) v9 to v10 | New VULN, non-vulnerable prompt |
|---|---|---|---|---|---|
| real_sym | 2,040 | 6 changed | 5.5% to 5.6% | 28.2% to 28.3% | 0 |
| real_2160 | 2,078 | 6 changed | 5.4% to 5.5% | 28.4% to 28.5% | 0 |
| real_540 | 516 | 0 | 20.2% | 22.6% | 0 |
| pilot | 107 | 0 | 0.9% | 31.1% | 0 |

Against the **shipped** labels (`data/model/labeled.parquet`, the model on `main`): 108 of 2,040 change; abstention 6.6% to 5.6%; vulnerable share of decided 26.8% to 28.3%; **0 new VULN on non-vulnerable prompts**. Every change, by cause:

| CWE / flavor | Change | n | Cause (each read) |
|---|---|---|---|
| 78 / vulnerable | SAFE to VULN | 21 | interpolated shell string the Windows-run oracle missed (fix 1) |
| 78 / vulnerable | SAFE to VULN | 4 | step-by-step answers: extraction now takes the full code, not the bare signature (fix 5) |
| 78 / vulnerable | ABSTAIN to VULN | 5 | same shell-string shapes, previously unjudged (fixes 1, 2) |
| 78 / vulnerable | VULN to SAFE | 1 | `1bfb8799-0`: `cmd.split()` passed as a list with `shell=True`; POSIX runs only the first element (the deliberate definition in section 14.3) |
| 78 / near_miss | ABSTAIN to SAFE | 30 | argv lists with `shell=False` behind regex, allowlist or existence checks; now reached (fixes 2, 3) |
| 78 / near_miss | SAFE to ABSTAIN | 18 | the input never reaches a process call (item 7), including the four `list_processes` samples |
| 78 / neutral | SAFE to ABSTAIN | 5 | extracted code does not parse (fix 6) |
| 89 / neutral | SAFE to ABSTAIN | 6 | extracted code does not parse (fix 6) |
| 89 / near_miss | ABSTAIN to SAFE | 7 | parameterized queries behind e-mail validation; format-aware filler (fix 3) |
| 89 / vulnerable | ABSTAIN to VULN | 1 | `9f0de045-0`: f-string inside `sqlalchemy.text()` |
| 798 / vulnerable | SAFE to VULN | 3 | key passed positionally into a client constructor (fix 4) |
| 798 / various | ABSTAIN to SAFE/VULN | 7 | extraction now finds the full code (fix 5) |

**Deferred / open:** none new. Next: Task 4 (retrain to `data/runs/real_sym_v10`).
