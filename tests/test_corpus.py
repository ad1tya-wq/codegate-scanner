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
