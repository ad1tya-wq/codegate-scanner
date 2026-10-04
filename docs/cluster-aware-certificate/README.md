# Cluster-aware certificate

**Status:** implemented and shipped on this branch (2026-10-04).
Full record with every number and command: `docs/ENGINEERING_LOG.md` §13
(the figures below are from the retrain in §13.1).

## The problem

LTT certifies a threshold `t̂` when `binom.cdf(k, n, α) ≤ δ`, where `n` is the
number of vulnerable calibration samples and `k` is how many of them score
above `t̂`. That binomial test assumes the `n` samples are **independent**.

Ours are not. Four models answer each task, so samples from one task are
correlated:

| | |
|---|---|
| Vulnerable calibration samples | 206, in **66 task groups** (≈ 3.1 per group) |
| Within-group correlation of scores (ICC) | **0.57** → design effect 2.2, ≈ 94 independent samples' worth of evidence |
| Per-sample certificate at α = 0.10 | `t̂ = 0.7763`, 56.4% coverage |
| …its held-out miss rate | **13.1%** against the 10% it promised |

## What was built

**The task group is the unit of evidence.** A group's loss at threshold `t`
is the fraction of its vulnerable samples scoring ≥ `t`. The risk is the
mean loss over the groups that hold a vulnerable sample. Each threshold in
LTT's fixed sequence is tested with the **Hoeffding–Bentkus** p-value for
bounded losses, the p-value used in "Learn then Test" (Angelopoulos et al.,
2021). Validity needs only *task groups* to be exchangeable; samples inside
a group may be correlated in any way.

- `gate/ltt.py`: `calibrate_threshold(..., groups=...)` and
  `hoeffding_bentkus_p_value`. Without `groups`, behaviour is unchanged.
- `config.yaml`: `certificate: cluster` (default) or `sample`.
- The pipeline derives each sample's task group from its prompt id. The
  frontier, the operating point, the generator-shift experiment and
  scan-time `--alpha` all use the cluster-aware test.
- `calibration.json` records `method` and `n_vuln_groups`. `codegate info`,
  the terminal, JSON and PDF reports all name the method.
- `scripts/run_eval.py` reports the held-out miss rate per sample and per
  task group, with a bootstrap interval that resamples whole groups.

Two candidate approaches from the original plan were not used:
- **Design-effect correction:** it rests on an estimated correlation that
  the certificate would have to trust.
- **"Any miss in the group" with an exact binomial:** valid, but it gave
  less coverage at every α except 0.05, where the two tie.

## Evidence that it works

**It keeps its promise where the old test did not.** In simulation (66
groups sized like ours, α = 0.10, δ = 0.05, 400 runs per setting), the share
of runs that certified a threshold truly missing more than α was:

| within-group correlation | per-sample (old) | cluster-aware (new) |
|---|---|---|
| 0.0 | 0.020 | 0.000 |
| 0.5 | **0.085** | 0.000 |
| 0.8 | **0.092** | 0.000 |
| 0.95 | **0.120** | 0.000 |

The allowed rate is 0.05.

**It holds on data it never saw.** At the shipped threshold (`t̂ = 0.8259`,
α = 0.10), 9.3% of vulnerable test-split samples are auto-approved, or 7.6%
averaged per task group (95% cluster bootstrap 0.8–16.7%). Both are within
the 10% target.

**Generator shift.** The experiment was fixed to calibrate on the
calibration split and judge each held-out model on data the ranker never
trained on. Three of four models stay within 10% (2.9%, 3.7%, 7.0%).
Codegemma comes in at 11.0% (10 of 91, P = 0.43 under a true 10% rate, so
within noise). The old certificate gave 13.2% for codegemma on the same
experiment.

**The cost.** Coverage drops from 56.4% to 48.8% at α = 0.10. At α = 0.05
the honest certificate approves only 29.2%, which is why the shipped
operating point stays at 0.10.

## What would improve it

- **More task groups.** The group is the unit of evidence, so more tasks
  (not more samples per task) is what buys coverage and would make α = 0.05
  practical.
- **Exchangeability of tasks** is now the assumption that matters. The tasks
  are hand-written, so whether they represent future code is a judgement
  about the prompt bank, not something the statistics can check.
