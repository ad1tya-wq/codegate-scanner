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
