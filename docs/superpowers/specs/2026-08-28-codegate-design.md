# CodeGate — Design Spec

**Status:** Approved by user in chat, 2026-08-28. Objectives below are locked
against Review 1 (slide 7 of `CodeGate - Review 1 PPT.pptx`); framing and
implementation are not.

## One-line pitch

We prove, with a finite-sample statistical certificate, that a cheap
classifier can auto-approve most AI-generated Python without missing more
than α% of its vulnerabilities — and we show what happens to that proof when
someone switches AI assistants.

## Locked objectives (verbatim intent from Review 1)

1. Build a Learn-Then-Test–calibrated gate certifying auto-approval
   miss-rate ≤ α at confidence 1−δ on AI-generated Python.
2. Construct a provenance-labeled benchmark (SQLi, hardcoded credentials,
   command injection) extending an existing labeled vulnerability dataset
   with per-sample generating-model labels.
3. Measure and report a certified cost–coverage frontier, stratified by
   generating-model family.

## Five design decisions that change v4's plan

### 1. Risk definition — control the monotone quantity

Control **R(t) = P(score ≤ t | vulnerable)** — "how often do we wave through
a real vulnerability" — not P(vulnerable | score ≤ t). R(t) is monotone
non-decreasing in t (it's the CDF of scores restricted to the vulnerable
population), which licenses **fixed-sequence testing** instead of
Bonferroni-over-the-grid LTT. Same calibration data, strictly tighter bound,
more certified coverage.

Calibration procedure (implemented in `src/codegate/gate/ltt.py`):

```
sort candidate thresholds ascending (most conservative / safest first)
for t in thresholds:
    k = # vulnerable calibration samples with score <= t
    n = # vulnerable calibration samples total
    p = P(Binomial(n, alpha) <= k)     # one-sided Clopper-Pearson-style p-value
    if p > delta: break                 # first rejection stops the search
    t_hat = t
return t_hat
# Guarantee: P(R(t_hat) <= alpha) >= 1 - delta, given calibration/test exchangeability
```

### 2. Sample budget drives the schedule

Clopper–Pearson at δ=0.05: need ~200 vulnerable calibration samples per
stratum to certify α=0.05 while tolerating up to 3 observed misses (0 misses
needs only ~60, but budget for noise). Leave-one-generator-out needs 3-of-4
generators per calibration fold. Target corpus: **3 CWEs × 4 generators × 60
prompts × ~3 flavors ≈ 2,160-2,400 snippets**, split 40/30/30 by **prompt**
(never by sample — prompt-level leakage invalidates the benchmark).

### 3. Near-miss negatives are mandatory

Every prompt has 3 flavors: **vulnerable** (elicits the CWE), **neutral**
(unrelated safe task), **near-miss** (safe code with vulnerable *shape* —
parameterized query that still concatenates a whitelisted identifier,
`subprocess.run(..., shell=False)` with a list arg, credential read from
`os.environ` with a hardcoded fallback default). Flavor is a covariate on
the prompt, **never** the label — the oracle labels, always. A flavor-only
baseline classifier is run as a degeneracy check: if flavor alone predicts
the label at high AUROC, the corpus is measuring the prompt template, not
vulnerability presence, and must be reworked before any ranker is trained.

### 4. Detonate what can be detonated

| CWE | Oracle | Kind |
|---|---|---|
| CWE-89 SQL injection | Import target function, seed sqlite fixture, invoke with `' OR '1'='1` payload, compare returned row count to expected | Dynamic (sandboxed exec) |
| CWE-78 OS command injection | Invoke with a payload containing a sentinel command (`; touch /tmp/cg_pwned_<nonce>`), check sentinel side-effect | Dynamic (sandboxed exec) |
| CWE-798 Hardcoded credentials | AST literal scan + Shannon entropy threshold + `detect-secrets`-style regex bank | Static |

Sandbox contract for dynamic oracles: no network, read-only root fs except a
scratch tmpfs, memory cap, PID cap, non-root user, wall-clock timeout,
executed as a subprocess inside a Docker container when the daemon is
available. **Tonight, Docker Desktop is not running**, so dynamic oracles
are implemented and unit-tested against hand-written fixture snippets
(`data/fixtures/`) using a best-effort local subprocess sandbox
(`resource` limits + timeout, no container isolation) — logged in
`NEEDS_FROM_YOU.md` as needing Docker Desktop started before running on
real (LLM-written, untrusted) generations.

Consensus label = documented rule combining Semgrep static findings +
oracle verdict (dynamic where available, static+entropy for creds) + one
LLM adjudicator call, **never** the same model as a generator or the
escalation verifier (avoids self-preference / circularity). Cohen's κ and a
hand-validated noise rate are computed on a stratified subsample.

### 5. Headline experiment: certificate decay under generator shift

Calibrate the LTT threshold on 3 of 4 generator families; deploy (test) on
the held-out 4th. Report realized R(t̂) on the held-out generator against
the certified α.

- **Holds** (realized ≤ α within the confidence band): "certified gates
  survive generator shift" — clean positive, validates the exchangeability
  assumption in the benign setting.
- **Breaks**: "a certificate calibrated on generator X silently expires when
  the team switches to generator Y" — a stronger, more publishable finding,
  and directly answers the exchangeability objection any reviewer raises.

This *is* objective 2/3's "stratified by generating model" taken to its
conclusion, so it fits inside the locked wording without renegotiating
Review 1. The originally-planned "provenance as a ranker feature" ablation
is demoted to optional/secondary — v4 already pre-accepted it as likely
null, and the data is better spent here.

## Ranker: ablation axis, not a commitment

| ID | Approach | Effort | Build order |
|---|---|---|---|
| R2 | Frozen code-embedding (CodeBERT/UniXcoder via `transformers`) → logistic regression | ~half a day | **1st** |
| R0 | Semgrep finding count/severity → monotone score | ~2 hours | 2nd |
| R1 | Handcrafted AST + taint features → LightGBM, monotone constraints | ~4 days | 3rd (stretch) |

All three ranked, ablated, and reported — "which cheap tier buys the most
certified coverage" is itself a result.

## Generator roles — avoid role reuse confounds

Never let one model serve two roles (adjudicator judging its own label,
verifier checking its own generation inflates measured accuracy by
construction). Roles: **generators** (≥3 distinct open-model families) /
**label adjudicator** (a model not used as a generator) / **escalation
verifier** (pre-registered, disclosed if it overlaps a generator role, with
a per-generator accuracy breakdown to surface self-preference bias).
Tonight, all three roles are served by a `SimulatedBackend` (deterministic,
seeded, no network) so the full pipeline is exercised end-to-end; real
backends (Ollama / OpenRouter / Groq free tiers) are implemented behind the
same interface and swapped in once the user supplies access tomorrow.

## Cut permanently (v4 scope that does not survive)

SHAP / explanation-aware escalation, Mondrian per-severity bounds
(meaningless at 3 CWEs), multi-language support, CI/GitHub Action/pre-commit
integration, inferred soft-provenance as a ranker feature, adaptive
conformal inference, real PR diffs. All are "future work," not silently
dropped — recorded here so no one re-derives the decision.

## Repository layout

```
D:\CodeGate\
  config.yaml                        frozen run parameters (alpha, delta, CWEs, generators, roles)
  src/codegate/
    config.py                        load & validate config.yaml
    schemas.py                       pandas/pyarrow schemas for every on-disk artifact
    corpus/prompts.py                loads + validates the YAML prompt bank
    generation/backends.py           Backend ABC + SimulatedBackend + Ollama/OpenRouter/Groq backends
    generation/harness.py            prompts x backends x k -> generations.parquet
    oracles/sqli_oracle.py           dynamic PoC executor, SQLi
    oracles/cmdi_oracle.py           dynamic PoC executor, command injection
    oracles/creds_oracle.py          static AST + entropy detector
    oracles/semgrep_oracle.py        Semgrep CLI wrapper -> finding features
    oracles/consensus.py             documented consensus rule -> labeled.parquet + kappa/noise report
    gate/ltt.py                      Learn-Then-Test fixed-sequence calibration (the core contribution)
    gate/risk.py                     R(t) computation, confidence intervals
    ranker/r2_embedding_lr.py        embedding + logistic regression ranker
    ranker/r0_semgrep_score.py       semgrep-count monotone score
    eval/frontier.py                 cost-coverage frontier computation
    eval/shift.py                    leave-one-generator-out certificate-decay experiment
    eval/plots.py                    matplotlib plotting helpers
  data/prompts/*.yaml                prompt bank, 3 CWEs x flavors
  data/fixtures/*.py                 hand-written known-vuln/known-safe snippets for oracle unit tests
  tests/                             one test module per src module above
  docker/poc_sandbox.Dockerfile      sandbox image definition for dynamic oracles
  scripts/run_pipeline_dry_run.py    end-to-end run on simulated data -> a real frontier plot tonight
  PROGRESS.md                        phase-wise milestone log (living document)
  NEEDS_FROM_YOU.md                  everything gated on user action (API keys, Docker Desktop, review)
```

## Self-review notes

- No placeholders: every module above has a concrete, testable
  responsibility; ambiguous ones (oracle sandboxing without Docker) are
  resolved explicitly rather than left TBD.
- Scope: this is one coherent pipeline with file-boundary interfaces
  (parquet/YAML on disk), so it is implemented as one plan with
  independently-testable tasks rather than decomposed into separate specs.
- Consistency check: the risk definition in §1 (`R(t) = P(score ≤ t |
  vulnerable)`) is used consistently by `gate/ltt.py`, `gate/risk.py`, and
  `eval/shift.py` — no other risk definition appears anywhere else in this
  spec.
