"""
One-off repair of the 2,160-sample corpus pushed on branch corpus/real-540
(commit 54ab6e1).

That run was written into data/runs/real_540/, which still held the
September checkpoint. Resume then matched on sample_id alone, so for task
groups 001-015 it reused September's answers from the three generators the
two runs share. Measured: 404 rows are byte-identical to the September
corpus. Of those,

  * 78 answer CWE-798 prompts whose wording has changed since (the new bank
    pins a concrete literal into every vulnerable prompt). Their code
    answers a question that is no longer in the bank, so they are dropped
    and must be regenerated;
  * 189 carry the September split, reassigned since for groups 008-014.
    The code is still a valid answer to an unchanged prompt, so only the
    split is corrected, from the current bank.

The harness now fingerprints prompt wording (generation/harness.py,
`prompt_fingerprint`), so this cannot recur.

Writes, into --out-dir:
  generations.parquet               the repaired corpus (2,078 rows)
  generations.checkpoint.jsonl      the same rows, fingerprinted, so the
                                    generation host can resume and fill
                                    only the missing samples
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path

import pandas as pd
import yaml

from codegate.research.corpus.prompts import load_prompt_bank
from codegate.research.generation.harness import prompt_fingerprint

SEPTEMBER_CORPUS = ("nikhil", "data/runs/real_540/generations.parquet")


def _git_bytes(rev: str, path: str) -> bytes:
    return subprocess.run(["git", "show", f"{rev}:{path}"], check=True,
                          capture_output=True).stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generations", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--september-rev", default="origin/" + SEPTEMBER_CORPUS[0])
    parser.add_argument("--symmetric", action="store_true",
                        help="also drop every prompt not answered by all generators")
    args = parser.parse_args()

    bank = {p.prompt_id: p for p in load_prompt_bank("data/prompts")}
    new = pd.read_parquet(args.generations)
    old = pd.read_parquet(BytesIO(_git_bytes(args.september_rev, SEPTEMBER_CORPUS[1])))

    unknown = set(new["prompt_id"]) - set(bank)
    if unknown:
        sys.exit(f"prompt ids not in the current bank: {sorted(unknown)[:5]}")

    old_code = dict(zip(old["sample_id"], old["code"]))
    carried = new.apply(lambda r: old_code.get(r["sample_id"]) == r["code"], axis=1)

    # A carried-over row is stale when the prompt it answered has been
    # reworded since September. Compare wording, not ids.
    old_text = {}
    for cwe_file in ("sqli", "cmdi", "creds"):
        doc = yaml.safe_load(_git_bytes("aa7f798", f"data/prompts/{cwe_file}.yaml"))
        cwe = doc["cwe"]
        for t in doc["tasks"]:
            for flavor in ("vulnerable", "neutral", "near_miss"):
                old_text[f"{cwe}-{t['id']}-{flavor}"] = " ".join(t[flavor].split())
    reworded = new["prompt_id"].map(
        lambda pid: pid in old_text and old_text[pid] != " ".join(bank[pid].task.split()))
    stale = carried & reworded

    bank_split = new["prompt_id"].map(lambda pid: bank[pid].split)
    resplit = carried & ~stale & (new["split"] != bank_split)

    out = new[~stale].copy()
    out["split"] = out["prompt_id"].map(lambda pid: bank[pid].split)

    n_generators = new["generator"].nunique()
    if args.symmetric:
        # Keep a prompt only if every generator answered it, so each model
        # is measured on exactly the same questions. Without this the
        # missing samples cluster in CWE-798 groups 001-015 for three of the
        # four models, which skews the per-generator shift experiment.
        per_prompt = out.groupby("prompt_id")["generator"].nunique()
        complete = set(per_prompt[per_prompt == n_generators].index)
        dropped_for_symmetry = int((~out["prompt_id"].isin(complete)).sum())
        out = out[out["prompt_id"].isin(complete)].copy()
        print(f"dropped for generator symmetry: {dropped_for_symmetry} "
              f"({len(bank) - len(complete)} prompts not answered by all {n_generators})")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out.to_parquet(out_dir / "generations.parquet")
    with (out_dir / "generations.checkpoint.jsonl").open("w", encoding="utf-8") as fh:
        for rec in out.to_dict("records"):
            rec["is_simulated"] = bool(rec["is_simulated"])
            rec["prompt_fingerprint"] = prompt_fingerprint(bank[rec["prompt_id"]])
            fh.write(json.dumps(rec) + "\n")

    print(f"input rows                    : {len(new)}")
    print(f"carried over from September   : {int(carried.sum())}")
    print(f"  stale (prompt reworded)     : {int(stale.sum())}  -> dropped")
    print(f"  split corrected             : {int(resplit.sum())}")
    print(f"output rows                   : {len(out)}")
    if not args.symmetric:
        print(f"still to generate             : {len(bank) * n_generators - len(out)}")
    print(pd.crosstab(out["cwe"], out["split"]).to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
