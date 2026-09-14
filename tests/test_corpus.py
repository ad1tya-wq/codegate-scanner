import collections
import re

import pytest
from codegate.research.corpus.prompts import (
    load_prompt_bank,
    select_pilot_prompts,
    Prompt,
)

PROMPTS_DIR = "data/prompts"


def _synthetic_bank(groups_per_cwe: int = 10) -> list[Prompt]:
    prompts = []
    for cwe in ("CWE-89", "CWE-78", "CWE-798"):
        for i in range(1, groups_per_cwe + 1):
            for flavor in ("vulnerable", "neutral", "near_miss"):
                prompts.append(Prompt(
                    prompt_id=f"{cwe}-{i:03d}-{flavor}", cwe=cwe,
                    flavor=flavor, split="train", task="x",
                ))
    return prompts


def test_loads_all_three_cwe_files():
    prompts = load_prompt_bank(PROMPTS_DIR)
    cwes = {p.cwe for p in prompts}
    assert cwes == {"CWE-89", "CWE-78", "CWE-798"}


def test_every_prompt_has_all_three_flavors_per_task_group():
    prompts = load_prompt_bank(PROMPTS_DIR)
    # prompt_id convention: "<cwe>-<task_num>-<flavor>", grouped by "<cwe>-<task_num>"
    groups: dict[str, set[str]] = {}
    for p in prompts:
        group_key = p.prompt_id.rsplit("-", 1)[0]
        groups.setdefault(group_key, set()).add(p.flavor)
    for group_key, flavors in groups.items():
        assert flavors == {"vulnerable", "neutral", "near_miss"}, f"{group_key} missing a flavor: {flavors}"


def test_no_duplicate_prompt_ids():
    prompts = load_prompt_bank(PROMPTS_DIR)
    ids = [p.prompt_id for p in prompts]
    assert len(ids) == len(set(ids)), "duplicate prompt_id found"


def test_splits_are_valid_and_assigned_at_prompt_group_level():
    prompts = load_prompt_bank(PROMPTS_DIR)
    valid_splits = {"train", "calib", "test"}
    groups: dict[str, set[str]] = {}
    for p in prompts:
        assert p.split in valid_splits
        group_key = p.prompt_id.rsplit("-", 1)[0]
        groups.setdefault(group_key, set()).add(p.split)
    # every flavor of the same task must share one split (no leakage across flavors)
    for group_key, splits in groups.items():
        assert len(splits) == 1, f"{group_key} has inconsistent splits across flavors: {splits}"


def test_near_miss_flavor_text_differs_from_vulnerable_and_neutral():
    prompts = load_prompt_bank(PROMPTS_DIR)
    by_group: dict[str, dict[str, str]] = {}
    for p in prompts:
        group_key = p.prompt_id.rsplit("-", 1)[0]
        by_group.setdefault(group_key, {})[p.flavor] = p.task
    for group_key, flavors in by_group.items():
        assert flavors["near_miss"] != flavors["vulnerable"]
        assert flavors["near_miss"] != flavors["neutral"]


def test_missing_directory_raises():
    with pytest.raises(FileNotFoundError):
        load_prompt_bank("data/does_not_exist")


# --- bank size and split allocation ---------------------------------------
#
# Sized from the LTT requirement. Certifying alpha=0.05 at delta=0.05 needs
# n_vuln_calib >= 59 even when no vulnerable sample scores above t_hat, and
# >= 100 to tolerate a single one; the working target is 120. At 60 task
# groups per CWE split 24/24/12, the calibration split carries 24 groups x
# 4 generators = 96 vulnerable-flavor samples per CWE, which at the yields
# measured in ENGINEERING_LOG 12.6 projects to ~131.

GROUPS_PER_CWE = 60
SPLIT_ALLOCATION = {"train": 24, "calib": 24, "test": 12}


def _groups(prompts):
    """{(cwe, group_key): split} for every task group in the bank."""
    return {(p.cwe, p.prompt_id.rsplit("-", 1)[0]): p.split for p in prompts}


def test_prompt_bank_has_sixty_task_groups_per_cwe():
    groups = _groups(load_prompt_bank(PROMPTS_DIR))
    per_cwe = collections.Counter(cwe for cwe, _ in groups)
    assert dict(per_cwe) == {
        "CWE-89": GROUPS_PER_CWE,
        "CWE-78": GROUPS_PER_CWE,
        "CWE-798": GROUPS_PER_CWE,
    }


def test_split_allocation_is_24_24_12_per_cwe():
    groups = _groups(load_prompt_bank(PROMPTS_DIR))
    for cwe in ("CWE-89", "CWE-78", "CWE-798"):
        splits = collections.Counter(
            split for (c, _), split in groups.items() if c == cwe
        )
        assert dict(splits) == SPLIT_ALLOCATION, (cwe, dict(splits))


def test_full_bank_produces_the_planned_corpus_size():
    """540 prompts x 4 generators x 1 sample = 2,160."""
    assert len(load_prompt_bank(PROMPTS_DIR)) == GROUPS_PER_CWE * 3 * 3


def test_every_prompt_pins_an_explicit_function_signature():
    """
    The dynamic oracles invoke by signature: they read the parameter names
    to synthesise benign arguments and to place the payload. A prompt that
    does not name its function and parameters produces output the harness
    has to guess at, which is how the original arity defect stayed hidden.
    """
    signature = re.compile(r"`\w+\([^)]*\)`")
    for p in load_prompt_bank(PROMPTS_DIR):
        assert signature.search(p.task), f"{p.prompt_id} does not pin a signature"


def test_dynamic_cwe_prompts_cover_a_range_of_arities():
    """
    The arity defect (ENGINEERING_LOG 12.1) was invisible because the bank's
    signature spread was accidental. Keep it deliberate so a regression in
    signature handling shows up as failed labels rather than silence.
    """
    signature = re.compile(r"`\w+\(([^)]*)\)`")
    for cwe in ("CWE-89", "CWE-78"):
        arities = set()
        for p in load_prompt_bank(PROMPTS_DIR):
            if p.cwe != cwe or p.flavor != "vulnerable":
                continue
            match = signature.search(p.task)
            params = [a for a in match.group(1).split(",") if a.strip()]
            arities.add(len(params))
        assert len(arities) >= 3, f"{cwe} vulnerable prompts only use arities {arities}"


def test_creds_vulnerable_prompts_pin_a_concrete_literal():
    """
    Asked to hardcode a password, models write `your_password` or
    `YOUR_API_KEY` -- placeholders, which the oracle correctly clears, and
    which the bank's own near-miss shapes use as a SAFE pattern. 49 of 58
    CWE-798 vulnerable samples came back safe for this reason
    (ENGINEERING_LOG 12.5). The prompt has to name the literal.
    """
    for p in load_prompt_bank(PROMPTS_DIR):
        if p.cwe == "CWE-798" and p.flavor == "vulnerable":
            assert "the string literal `" in p.task, \
                f"{p.prompt_id} does not pin a concrete secret literal"


# --- pilot selection -------------------------------------------------------
#
# `--limit N` takes the first N prompts overall, and load_prompt_bank walks the
# YAML files in sorted order (cmdi, creds, sqli), so a 45-prompt limit is
# entirely CWE-78. A pilot run has to sample every CWE or it says nothing about
# the two whose oracles were most broken -- see docs/ENGINEERING_LOG.md s11.


def test_pilot_selects_n_task_groups_from_every_cwe():
    picked = select_pilot_prompts(_synthetic_bank(), per_cwe=3)
    assert len(picked) == 3 * 3 * 3          # 3 CWEs x 3 groups x 3 flavors
    assert {p.cwe for p in picked} == {"CWE-89", "CWE-78", "CWE-798"}
    for cwe in ("CWE-89", "CWE-78", "CWE-798"):
        groups = {p.prompt_id.rsplit("-", 1)[0] for p in picked if p.cwe == cwe}
        assert len(groups) == 3


def test_pilot_keeps_all_three_flavors_of_each_selected_group():
    picked = select_pilot_prompts(_synthetic_bank(), per_cwe=2)
    by_group: dict[str, set[str]] = {}
    for p in picked:
        by_group.setdefault(p.prompt_id.rsplit("-", 1)[0], set()).add(p.flavor)
    assert by_group
    assert all(f == {"vulnerable", "neutral", "near_miss"} for f in by_group.values())


def test_pilot_preserves_bank_order():
    bank = _synthetic_bank()
    picked = select_pilot_prompts(bank, per_cwe=2)
    assert picked == [p for p in bank if p in picked]


def test_pilot_wider_than_the_bank_returns_everything():
    bank = _synthetic_bank(groups_per_cwe=2)
    assert select_pilot_prompts(bank, per_cwe=99) == bank


def test_pilot_on_the_real_bank_covers_all_three_cwes():
    picked = select_pilot_prompts(load_prompt_bank(PROMPTS_DIR), per_cwe=3)
    assert {p.cwe for p in picked} == {"CWE-89", "CWE-78", "CWE-798"}
    assert len(picked) == 27
