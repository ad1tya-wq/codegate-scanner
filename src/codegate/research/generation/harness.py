from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd

from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import Backend, stable_seed

# Columns of one generation record, in `generations` schema order.
_RECORD_FIELDS = (
    "sample_id", "prompt_id", "cwe", "flavor",
    "generator", "code", "split", "is_simulated",
)


def _sample_id(prompt_id: str, generator_name: str, k: int) -> str:
    """
    Deterministic id for one (prompt, generator, replicate) triple.

    Must be stable across processes: resume works by recognising which
    samples are already on disk, so a random id (this used to be uuid4)
    would make every resumed run regenerate everything.
    """
    return f"{stable_seed(prompt_id, generator_name, k):08x}-{k}"


def prompt_fingerprint(prompt: Prompt) -> str:
    """
    Identifies the exact wording a sample answered. Stored with every
    checkpoint record so resume can tell a still-valid answer from an
    answer to a prompt that has since been rewritten.
    """
    return hashlib.sha256(prompt.task.encode("utf-8")).hexdigest()[:16]


def _load_checkpoint(checkpoint_path: Path) -> dict[str, dict]:
    """Read completed records from a JSONL checkpoint, keyed by sample_id."""
    if not checkpoint_path.exists():
        return {}
    done: dict[str, dict] = {}
    for line in checkpoint_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # A half-written final line from an interrupted run. Skip it;
            # that sample simply gets regenerated.
            continue
        done[record["sample_id"]] = record
    return done


def run_generation(
    prompts: list[Prompt],
    backends: dict[str, Backend],
    samples_per_prompt: int,
    is_simulated: bool,
    checkpoint_path: Path | str | None = None,
    on_progress=None,
) -> pd.DataFrame:
    """
    Generate code for every (prompt x generator x replicate) combination.

    When `checkpoint_path` is given, each successful sample is appended to a
    JSONL file as soon as it is produced, and samples already present there
    are not regenerated -- provided the prompt wording they answered still
    matches (see `prompt_fingerprint`). Matching on sample_id alone once
    reused 404 answers from an older run in the same directory, 78 of them
    to prompts that had since been rewritten. This makes a multi-hour Ollama run survive a dropped
    LAN connection, a closed lid, or a Ctrl-C: rerun the same command and it
    picks up where it stopped.

    A generation that raises (model hiccup, connection reset, timeout) is
    logged and skipped rather than aborting the run -- losing one sample out
    of 540 is acceptable, losing the other 539 is not. Skipped samples are
    absent from the checkpoint, so a later resume retries them.
    """
    ckpt = Path(checkpoint_path) if checkpoint_path is not None else None
    done = _load_checkpoint(ckpt) if ckpt is not None else {}
    if done:
        print(f"[resume] {len(done)} sample(s) already complete in {ckpt}", flush=True)

    if ckpt is not None:
        ckpt.parent.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    failures = 0
    stale = 0
    total = len(prompts) * len(backends) * samples_per_prompt
    processed = 0

    for prompt in prompts:
        for generator_name, backend in backends.items():
            for k in range(samples_per_prompt):
                processed += 1
                sample_id = _sample_id(prompt.prompt_id, generator_name, k)

                prior = done.get(sample_id)
                if prior is not None:
                    if prior.get("prompt_fingerprint") == prompt_fingerprint(prompt):
                        # Same wording, so the code is still a valid answer.
                        # The split belongs to the prompt, not the answer --
                        # always take the current one.
                        records.append({**prior, "split": prompt.split})
                        continue
                    # Reworded since, or a legacy record with no fingerprint
                    # to check: regenerate rather than reuse an answer to a
                    # question that may no longer be the one being asked.
                    stale += 1

                try:
                    code = backend.generate(
                        prompt, seed=stable_seed(prompt.prompt_id, generator_name, k)
                    )
                except Exception as exc:  # noqa: BLE001 - deliberately broad
                    failures += 1
                    print(
                        f"[warn] generation failed ({type(exc).__name__}: {exc}) "
                        f"for {prompt.prompt_id} / {generator_name} / k={k} "
                        f"-- skipping, will retry on resume",
                        file=sys.stderr, flush=True,
                    )
                    continue

                record = {
                    "sample_id": sample_id,
                    "prompt_id": prompt.prompt_id,
                    "cwe": prompt.cwe,
                    "flavor": prompt.flavor,
                    "generator": generator_name,
                    "code": code,
                    "split": prompt.split,
                    "is_simulated": is_simulated,
                }
                records.append(record)

                if ckpt is not None:
                    with ckpt.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps({**record, "prompt_fingerprint": prompt_fingerprint(prompt)}) + "\n")

                if on_progress is not None:
                    on_progress(processed, total, record)

    if stale:
        print(
            f"[resume] {stale} checkpointed sample(s) answered a different "
            f"prompt wording (or predate fingerprints) and were regenerated.",
            flush=True,
        )
    if failures:
        print(
            f"[warn] {failures} generation(s) failed and were skipped. "
            f"Rerun the same command to retry only those.",
            file=sys.stderr, flush=True,
        )

    df = pd.DataFrame(records, columns=list(_RECORD_FIELDS))
    if not df.empty:
        df["is_simulated"] = df["is_simulated"].astype(bool)
    return df
