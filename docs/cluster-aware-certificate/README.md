# Cluster-aware certificate (planned — not started)

**Status:** placeholder branch, opened 2026-10-04 so this isn't forgotten. No
code yet. Start only after the α = 0.10 release on
`feat/certificate-restoration` is merged and working.

## The problem

LTT certifies a threshold `t̂` when `binom.cdf(k, n, α) ≤ δ`, where `n` is the
number of vulnerable calibration samples and `k` is how many of them score
above `t̂`. The binomial test assumes those `n` samples are **independent**.

They are not. The real corpus asks four models the same prompt, so samples
cluster by prompt and are correlated. On the shipped corpus
(`real-2040-sym`, `data/runs/real_sym_train/`):

| | |
|---|---|
| Vulnerable calibration samples (`n`) | 206 |
| …from distinct prompts | **67** (≈ 3.1 samples per prompt) |
| Certificate at α = 0.05 (sample-level) | `t̂ = 0.828`, k = 4, p = 0.022 ✓ |
| Certificate at α = 0.10 (sample-level, **shipped**) | `t̂ = 0.776`, k = 13, p = 0.043 ✓ |
| Held-out test split, realized miss rate at α = 0.05 | 9/107 = **8.4%** |
| Held-out test split, realized miss rate at α = 0.10 | 14/107 = **13.1%** |
| Task-group cluster bootstrap, test miss rate at α = 0.05 | 95% CI 0.9%–18.4% |

Neither test-split overshoot is significant on its own (P = 0.088 and 0.18
under independence), but both point the same way, and the misses
concentrate in a few task groups (7 of 9 at α = 0.05 come from two CWE-798
groups). The sample-level certificate is **optimistic**: its effective
sample size is smaller than 206. Background: `docs/ENGINEERING_LOG.md`
§12.10–12.11. This is the same reason `samples_per_prompt` stays at 1 (§12.7).

## The goal

A certificate whose guarantee survives the correlation, and which the README
can state without a caveat.

## Candidate approaches (to evaluate, not yet chosen)

1. **Prompt as the unit.** Count a prompt as "missed" if any of its
   vulnerable samples scores above `t̂`, and run LTT over prompts. This is
   exact under prompt-level exchangeability, but much stricter. On the
   current data it **does not certify at either α** with the current
   thresholds:

   | α | prompts missed at shipped `t̂` | max tolerated (n = 67) | prompts needed at k = 0 |
   |---|---|---|---|
   | 0.05 | 3 | 0 | 59 |
   | 0.10 | 8 | 2 | 29 |

   It would need a higher `t̂` (less coverage), more task groups, or both.
2. **Per-prompt miss fraction.** Use each prompt's fraction of vulnerable
   samples auto-approved as a bounded loss in `[0, 1]`, and certify its
   mean with a bound for bounded variables (Hoeffding–Bentkus, or the
   bounded-loss form of LTT). This uses partial information within a
   prompt, so it is less strict than (1). This is the leading candidate.
3. **Design-effect correction.** Estimate the intra-prompt correlation `ρ`
   and use `n_eff = n / (1 + (m − 1)ρ)`. Simple, but it rests on an
   estimated `ρ` that the certificate itself would have to trust. Probably
   better as a diagnostic than as the certificate.
4. **Grow the independent unit.** More task groups (≥ 59 vulnerable
   calibration prompts, i.e. more groups per CWE) make (1) or (2) feasible
   at α = 0.05. This is complementary to the above.

## Definition of done

- The chosen bound is implemented in `gate/` beside `calibrate_threshold`,
  with tests asserting structure and known analytic cases, never model values.
- `calibration.json` records which certificate type was used.
- A cluster bootstrap on the held-out test split is reported next to the
  certificate (`scripts/run_eval.py`).
- `README.md`'s guarantee sentence matches what is certified, with no caveat.

## Starting points in the code

- `src/codegate/gate/ltt.py::calibrate_threshold` — the current sample-level test.
- `src/codegate/research/eval/frontier.py::compute_frontier` — runs LTT per α.
- `src/codegate/research/pipeline.py::run_full_pipeline` — the calibration
  split carries `prompt_id`, so the cluster is already available there.
- `data/runs/real_sym_train/` — the corpus and scores all numbers above come
  from (git-ignored; regenerate with the commands in ENGINEERING_LOG §12.10).
