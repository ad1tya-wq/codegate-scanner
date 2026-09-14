from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass(frozen=True)
class Prompt:
    prompt_id: str
    cwe: str
    flavor: str
    split: str
    task: str


def load_prompt_bank(prompts_dir: str) -> list[Prompt]:
    d = Path(prompts_dir)
    if not d.exists():
        raise FileNotFoundError(f"prompts_dir not found: {prompts_dir}")

    prompts: list[Prompt] = []
    for yaml_file in sorted(d.glob("*.yaml")):
        raw = yaml.safe_load(yaml_file.read_text())
        cwe = raw["cwe"]
        for task_group in raw["tasks"]:
            task_num = task_group["id"]
            split = task_group["split"]
            for flavor in ("vulnerable", "neutral", "near_miss"):
                prompt_id = f"{cwe}-{task_num}-{flavor}"
                prompts.append(Prompt(
                    prompt_id=prompt_id,
                    cwe=cwe,
                    flavor=flavor,
                    split=split,
                    task=task_group[flavor],
                ))
    return prompts


def task_group_of(prompt: Prompt) -> str:
    """
    The `<cwe>-<task_num>` key shared by a task group's three flavors.

    The flavor suffix is the last hyphen-separated field, and `near_miss`
    uses an underscore precisely so this split stays unambiguous.
    """
    return prompt.prompt_id.rsplit("-", 1)[0]


def select_pilot_prompts(prompts: list[Prompt], per_cwe: int) -> list[Prompt]:
    """
    The first `per_cwe` task groups of each CWE, all three flavors intact.

    `--limit N` takes the first N prompts overall, and `load_prompt_bank`
    walks the YAML files in sorted order (cmdi, creds, sqli), so a limit
    small enough to be quick lands entirely inside one CWE. A pilot run
    exists to measure oracle yield before committing a teammate to an
    overnight generation run, so it has to sample every CWE -- otherwise it
    says nothing about the two whose oracles were most broken.

    Input order is preserved, so generation still walks the bank in the
    same sequence and `sample_id`s stay stable across a resume.
    """
    if per_cwe < 1:
        raise ValueError(f"per_cwe must be >= 1, got {per_cwe}")

    chosen_per_cwe: dict[str, list[str]] = {}
    keep: set[str] = set()
    for p in prompts:
        group = task_group_of(p)
        groups = chosen_per_cwe.setdefault(p.cwe, [])
        if group not in groups:
            if len(groups) >= per_cwe:
                continue
            groups.append(group)
        keep.add(group)
    return [p for p in prompts if task_group_of(p) in keep]
