from __future__ import annotations
import re
import textwrap
from pathlib import Path

import numpy as np
import pandas as pd

from codegate.config import CodeGateConfig
from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import Backend
from codegate.research.generation.harness import run_generation
from codegate.oracles.sqli_oracle import check_sqli
from codegate.oracles.cmdi_oracle import check_cmdi
from codegate.oracles.creds_oracle import check_creds
from codegate.oracles.consensus import consensus_label, CONSENSUS_RULE_VERSION
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.gate.ltt import calibrate_threshold
from codegate.research.artifacts import save_calibration, save_model
from codegate.research.eval.frontier import compute_frontier
from codegate.research.eval.shift import run_shift_experiment
from codegate.research.eval.plots import plot_frontier, plot_shift_results
from codegate.schemas import validate_dataframe

# Function names SimulatedBackend's templates use -- see generation/backends.py
# _SIM_TEMPLATES. Real backends won't reliably use these names, so
# label_row() also handles the "function not found under any candidate
# name" case by trying an AST scan for the *first* top-level function
# defined, which is what a real model's output will actually look like.
_SIM_CANDIDATE_FN_NAMES = ["handler", "process", "run_task", "do_work"]

# Label vocabulary. 1 = vulnerable, 0 = safe, -1 = the oracle abstained.
# Abstention is a distinct third state on purpose: collapsing it into "safe"
# is a silent-failure path that corrupts both the trained ranker and the
# conformal certificate that depends on those labels.
LABEL_VULNERABLE = 1
LABEL_SAFE = 0
LABEL_ABSTAIN = -1


# Real chat-style models (unlike SimulatedBackend) wrap code in some kind
# of delimiter, with prose narration around it -- verified empirically
# 2026-09-02 against the real Track A corpus, which uses three different
# delimiter styles depending on the generator: standard markdown fences
# (```python ... ``` or bare ``` ... ```, qwen2.5-coder/deepseek-coder/
# codellama), square-bracket tags ([PYTHON] ... [/PYTHON], codellama), and
# HTML-style tags (<pre> ... </pre>, codellama). Without extraction,
# ast.parse() on the raw text raises SyntaxError on the prose,
# _first_function_name returns None, and the dynamic oracles fall back to
# SimulatedBackend's four template names -- which real models essentially
# never use -- so every dynamic-oracle CWE (89, 78) abstains almost
# entirely on exactly the flavors (vulnerable, near_miss) that need
# detonation to judge. Measured on the real 516-sample corpus: 40.7%
# overall abstention before markdown-fence extraction alone; the
# additional [PYTHON]/<pre> delimiters accounted for a further slice of
# codellama's abstentions once fenced blocks stopped being the bottleneck.
_DELIMITER_PATTERNS = [
    re.compile(r"```(?:python)?\n?(.*?)```", re.DOTALL),
    re.compile(r"\[PYTHON\]\n?(.*?)\[/PYTHON\]", re.DOTALL | re.IGNORECASE),
    re.compile(r"<pre>\n?(.*?)</pre>", re.DOTALL | re.IGNORECASE),
]
_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(", re.MULTILINE)
_DETAILS_RE = re.compile(r"<details>(.*?)</details>", re.DOTALL | re.IGNORECASE)
# Named tags only: a generic <...> pattern would also eat `a<b and c>d`.
_HTML_TAG_RE = re.compile(r"<summary>.*?</summary>|</?(?:b|br|i|em|strong|p|code|pre)\s*/?>",
                          re.DOTALL | re.IGNORECASE)


def extract_code(raw: str) -> str:
    """
    Pulls the actual implementation out of a real LLM's delimiter-wrapped
    completion (markdown fences, [PYTHON]/[/PYTHON] tags, or <pre> tags --
    see the module-level comment above for why all three are needed).
    Returns the first delimited block that defines a function -- not just
    the first one found, since some models (codellama, observed in the
    real corpus) emit a second block that's a usage example, not the
    implementation, and picking the wrong one would hand the oracle
    example-call code instead of the function definition it needs to
    detonate. Falls back to `raw` unchanged if no delimited block
    contains a `def` -- covers both a model that emits bare code with no
    wrapping at all (starcoder2, observed in the real corpus) and a model
    that emits no usable code at all (also observed: a genuine non-answer
    that should legitimately abstain downstream, not be forced into a
    false extraction).
    """
    for pattern in _DELIMITER_PATTERNS:
        for block in pattern.findall(raw):
            if _DEF_RE.search(block):
                return block

    # Two codellama shapes seen in the pilot corpus, tried only when no
    # well-formed delimiter held a def: code wrapped in an HTML <details>
    # block, and indented code followed by a closing fence that was never
    # opened. Both used to fall through to `raw`, fail to parse, and abstain.
    for block in _DETAILS_RE.findall(raw):
        body = _HTML_TAG_RE.sub("", block)
        if _DEF_RE.search(body):
            return textwrap.dedent(body).strip() + "\n"
    if not raw.lstrip().startswith("```") and "```" in raw:
        head = raw.split("```", 1)[0]
        if _DEF_RE.search(head):
            return textwrap.dedent(head).strip() + "\n"
    return raw


def _first_function_name(code: str) -> str | None:
    import ast
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return node.name
    return None


def label_row(row: pd.Series) -> dict:
    """
    Runs the appropriate oracle(s) for one generated snippet and applies the
    consensus rule, returning one `labeled` row.

    Returns LABEL_ABSTAIN when no oracle reached a verdict. Callers must
    exclude those rows rather than treating them as safe.
    """
    code = row["code"]
    cwe = row["cwe"]

    candidate_names = list(_SIM_CANDIDATE_FN_NAMES)
    first_fn = _first_function_name(code)
    if first_fn and first_fn not in candidate_names:
        candidate_names = [first_fn] + candidate_names

    dynamic_verdict = None
    static_verdict = None

    if cwe == "CWE-89":
        for fn in candidate_names:
            v = check_sqli(code, function_name=fn)
            if v is not None:
                dynamic_verdict = v
                break
    elif cwe == "CWE-78":
        for fn in candidate_names:
            v = check_cmdi(code, function_name=fn)
            if v is not None:
                dynamic_verdict = v
                break
    elif cwe == "CWE-798":
        static_verdict = check_creds(code)

    if dynamic_verdict is None and static_verdict is None:
        # The oracle could not reach a verdict (function not found, timeout,
        # harness error). This is NOT evidence of safety. Recording it as 0
        # silently poisons the corpus and biases the certificate in the
        # flattering direction -- it is what hid the CWE-89 table-name bug,
        # where 540/540 samples abstained and every one was labelled safe.
        # LABEL_ABSTAIN is excluded from training and calibration upstream.
        label = LABEL_ABSTAIN
    else:
        label = consensus_label(cwe, dynamic_verdict, static_verdict)

    return {
        "sample_id": row["sample_id"],
        "cwe": cwe,
        "label": label,
        "dynamic_verdict": dynamic_verdict,
        "static_verdict": static_verdict,
        "consensus_rule_version": CONSENSUS_RULE_VERSION,
    }


def relabel(gen_df: pd.DataFrame) -> pd.DataFrame:
    """
    Re-run the oracles over an already-generated corpus, returning a fresh
    `labeled` frame.

    Generation is the expensive half -- hours on a teammate's laptop --
    while labelling is minutes. Whenever the oracles change, this measures
    the effect against real data without regenerating anything, which is how
    an oracle repair gets validated before a new corpus run is commissioned.

    Applies `extract_code` first, exactly as `run_full_pipeline` does, so
    the two paths cannot drift apart in how they read real model output.
    """
    df = gen_df.copy()
    df["code"] = df["code"].map(extract_code)
    return pd.DataFrame([
        label_row(row)
        for _, row in df.iterrows()
    ])


def label_summary(gen_df: pd.DataFrame, labeled_df: pd.DataFrame) -> pd.DataFrame:
    """CWE x flavor x verdict crosstab -- the shape that makes an oracle
    defect visible. A flavor whose verdicts are all one value is the
    signature of an oracle that is not discriminating."""
    merged = gen_df.merge(labeled_df[["sample_id", "label"]], on="sample_id")
    merged["verdict"] = merged["label"].map({
        LABEL_VULNERABLE: "VULN", LABEL_SAFE: "SAFE", LABEL_ABSTAIN: "ABSTAIN",
    })
    return pd.crosstab([merged["cwe"], merged["flavor"]], merged["verdict"])


def run_full_pipeline(
    cfg: CodeGateConfig,
    prompts: list[Prompt],
    backends: dict[str, Backend],
    is_simulated: bool,
    out_dir: Path,
    checkpoint_path: Path | None = None,
    pregenerated_df: pd.DataFrame | None = None,
    corpus_version: str | None = None,
) -> dict:
    """
    Generation -> oracle labeling -> consensus -> R2 ranking -> LTT
    calibration -> cost-coverage frontier -> generator-shift experiment.
    Writes every intermediate artifact to `out_dir` and returns a summary
    dict. Shared by scripts/run_pipeline_dry_run.py (SimulatedBackend) and
    scripts/run_real.py (real backends) so the two never drift apart.

    `checkpoint_path` makes generation resumable -- essential for the
    multi-hour Ollama runs, harmless for the simulated dry run.

    `pregenerated_df` skips the generation step entirely and labels/trains
    directly on an already-generated DataFrame (same shape `run_generation`
    produces) -- the receiving half of docs/OLLAMA_SETUP.md's
    "host runs generation, ships back generations.parquet" workflow.
    `prompts`/`backends` are still required arguments but go unused in
    this path.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    if pregenerated_df is not None:
        gen_df = pregenerated_df
    else:
        gen_df = run_generation(
            prompts, backends,
            samples_per_prompt=cfg.samples_per_prompt,
            is_simulated=is_simulated,
            checkpoint_path=checkpoint_path,
        )
    validate_dataframe(gen_df, "generations")

    # Real chat-style models wrap code in markdown with prose narration
    # around it; extract_code() is a no-op on SimulatedBackend's already-
    # clean output (no fence found -> falls back to the raw string
    # unchanged), so this runs unconditionally rather than branching on
    # is_simulated -- one code path for both, see extract_code()'s
    # docstring for the abstention-rate evidence this fixes.
    gen_df = gen_df.copy()
    gen_df["code"] = gen_df["code"].map(extract_code)

    gen_df.to_parquet(out_dir / "generations.parquet")
    summary["n_generated"] = len(gen_df)
    print(f"Generated {len(gen_df)} snippets across {len(backends)} generators (is_simulated={is_simulated})")

    labeled_rows = [
        label_row(row)
        for _, row in gen_df.iterrows()
    ]
    labeled_df = pd.DataFrame(labeled_rows)
    labeled_df.to_parquet(out_dir / "labeled.parquet")

    # Abstentions are excluded from every downstream statistic. Reporting a
    # vulnerable rate over rows the oracle never actually judged would be
    # meaningless, and calibrating on them would invalidate the certificate.
    n_abstain = int((labeled_df["label"] == LABEL_ABSTAIN).sum())
    decided = labeled_df[labeled_df["label"] != LABEL_ABSTAIN]
    vuln_rate = float(decided["label"].mean()) if len(decided) else float("nan")
    summary["vuln_rate"] = vuln_rate
    summary["n_abstain"] = n_abstain
    print(
        f"Labeled {len(labeled_df)} snippets; {len(decided)} decided, "
        f"{n_abstain} abstained ({n_abstain / max(len(labeled_df), 1):.1%}); "
        f"vulnerable rate among decided = {vuln_rate:.2%}"
    )
    if n_abstain > 0.2 * len(labeled_df):
        print(
            f"[warn] {n_abstain}/{len(labeled_df)} oracle abstentions is high. "
            f"The oracle is likely failing to invoke the generated functions "
            f"(wrong entry-point name, or a fixture mismatch such as an "
            f"unexpected SQL table name) rather than genuinely finding them safe."
        )

    merged = gen_df.merge(labeled_df[["sample_id", "label"]], on="sample_id")
    merged = merged[merged["label"] != LABEL_ABSTAIN].reset_index(drop=True)

    train_mask = merged["split"] == "train"
    ranker = R2Ranker(random_seed=cfg.random_seed)
    ranker.fit(merged[train_mask], merged.loc[train_mask, "label"])
    scores_df = ranker.score(merged)
    scores_df.to_parquet(out_dir / "scores_r2.parquet")

    scored_merged = merged.merge(scores_df[["sample_id", "score"]], on="sample_id")
    # The task group (prompt id minus its flavor) is the unit the cluster-aware
    # certificate counts: every model's answer to one task, in any flavor, is
    # one correlated group, not several independent draws.
    scored_merged["task_group"] = scored_merged["prompt_id"].str.rsplit("-", n=1).str[0]
    calib_mask = scored_merged["split"] == "calib"
    calib_scores = scored_merged.loc[calib_mask, "score"].to_numpy()
    calib_labels = scored_merged.loc[calib_mask, "label"].to_numpy()
    calib_groups = (scored_merged.loc[calib_mask, "task_group"].to_numpy()
                    if cfg.certificate == "cluster" else None)

    n_vuln_calib = int((calib_labels == 1).sum())
    summary["n_vuln_calib"] = n_vuln_calib
    print(f"Calibration set: {len(calib_labels)} samples, {n_vuln_calib} vulnerable")

    if n_vuln_calib > 0:
        # alpha/delta come from config.yaml -- they are the project's stated
        # statistical contract and must not be hardcoded here. The sweep
        # brackets the configured alpha so the frontier shows the trade-off
        # around the operating point actually being certified.
        alphas = sorted({cfg.alpha, 0.05, 0.10, 0.20, 0.30})
        frontier_df = compute_frontier(calib_scores, calib_labels, alphas=alphas, delta=cfg.delta,
                                       groups=calib_groups)
        frontier_df.to_csv(out_dir / "frontier.csv", index=False)
        plot_frontier(frontier_df, str(out_dir / "frontier.png"))
        print(frontier_df.to_string(index=False))

        # Persist the threshold-search trace at the configured operating
        # point: it is the evidence behind t_hat, and a reviewer will ask.
        operating = calibrate_threshold(calib_scores, calib_labels, alpha=cfg.alpha, delta=cfg.delta,
                                        groups=calib_groups)
        print(f"Certificate: {operating.method}"
              + (f" over {operating.n_vuln_groups} task groups" if operating.n_vuln_groups else ""))
        pd.DataFrame(
            operating.trace, columns=["threshold", "k_vuln_auto_approved", "p_value", "certified"]
        ).to_csv(out_dir / "ltt_trace.csv", index=False)
        summary["t_hat"] = operating.t_hat
        summary["coverage"] = operating.coverage
        summary["certificate_method"] = operating.method

        # Persist the model and its certificate together -- no scanner
        # without this. is_simulated is currently the only signal for
        # whether the underlying corpus is real: a run trained on the
        # simulated corpus is provisional by definition (see
        # docs/ENGINEERING_LOG.md guardrail G1), regardless of how the
        # certificate itself turned out.
        # The caller names the corpus. This used to be hardcoded "real-540",
        # which would have stamped every later real corpus with the wrong
        # name in calibration.json and every report.
        if corpus_version is None:
            corpus_version = "simulated-v2" if is_simulated else "real-unversioned"
        is_provisional = is_simulated
        save_model(ranker, out_dir / "model.joblib")
        save_calibration(
            operating, out_dir / "calibration.json",
            corpus_version=corpus_version, is_provisional=is_provisional,
            frontier=frontier_df,   # enables scan-time --alpha
        )
        summary["corpus_version"] = corpus_version
        summary["is_provisional"] = is_provisional
    else:
        pd.DataFrame({"alpha": [], "t_hat": [], "coverage": [], "n_vuln_calib": []}).to_csv(
            out_dir / "frontier.csv", index=False
        )
        _write_placeholder_plot(out_dir / "frontier.png", "insufficient vulnerable calibration samples")
        print("WARNING: zero vulnerable calibration samples; frontier.png is a placeholder.")

    # Generator shift: calibrate on the other generators' calibration split and
    # judge the held-out generator on its samples the ranker never trained on.
    # Using every split (as this once did) let training samples, which score
    # optimistically, into both sides of the experiment.
    calib_rows = scored_merged[calib_mask]
    unseen_rows = scored_merged[scored_merged["split"] != "train"]
    scores_by_gen: dict[str, np.ndarray] = {}
    labels_by_gen: dict[str, np.ndarray] = {}
    groups_by_gen: dict[str, np.ndarray] = {}
    for gen_name, gen_group in calib_rows.groupby("generator"):
        scores_by_gen[gen_name] = gen_group["score"].to_numpy()
        labels_by_gen[gen_name] = gen_group["label"].to_numpy()
        groups_by_gen[gen_name] = gen_group["task_group"].to_numpy()

    shift_results = []
    if len(scores_by_gen) >= 2 and n_vuln_calib > 0:
        for held_out in scores_by_gen:
            unseen = unseen_rows[unseen_rows["generator"] == held_out]
            try:
                r = run_shift_experiment(
                    scores_by_gen, labels_by_gen, held_out, alpha=cfg.alpha, delta=cfg.delta,
                    groups_by_generator=groups_by_gen if cfg.certificate == "cluster" else None,
                    held_out_scores=unseen["score"].to_numpy(),
                    held_out_labels=unseen["label"].to_numpy(),
                )
                shift_results.append(r)
            except ValueError as e:
                print(f"skipping shift experiment for {held_out}: {e}")

    if shift_results:
        shift_df = pd.DataFrame([r.__dict__ for r in shift_results])
        shift_df.to_csv(out_dir / "shift_results.csv", index=False)
        plot_shift_results(shift_results, str(out_dir / "shift_results.png"))
    else:
        pd.DataFrame(columns=["held_out_generator", "t_hat", "certified_alpha",
                               "realized_risk_on_held_out", "certificate_held"]).to_csv(
            out_dir / "shift_results.csv", index=False
        )
        _write_placeholder_plot(out_dir / "shift_results.png", "insufficient data for shift experiment")

    summary["n_shift_experiments"] = len(shift_results)
    return summary


def _write_placeholder_plot(path: Path, message: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()
    ax.text(0.5, 0.5, message, ha="center", va="center")
    fig.savefig(path)
    plt.close(fig)
