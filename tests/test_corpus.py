import pytest
from codegate.research.corpus.prompts import load_prompt_bank, Prompt

PROMPTS_DIR = "data/prompts"


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
