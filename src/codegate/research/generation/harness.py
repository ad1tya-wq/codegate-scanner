from __future__ import annotations
import uuid
import pandas as pd
from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import Backend, stable_seed


def run_generation(
    prompts: list[Prompt],
    backends: dict[str, Backend],
    samples_per_prompt: int,
    is_simulated: bool,
) -> pd.DataFrame:
    rows = []
    for prompt in prompts:
        for generator_name, backend in backends.items():
            for k in range(samples_per_prompt):
                seed = stable_seed(prompt.prompt_id, generator_name, k)
                code = backend.generate(prompt, seed=seed)
                rows.append({
                    "sample_id": str(uuid.uuid4()),
                    "prompt_id": prompt.prompt_id,
                    "cwe": prompt.cwe,
                    "flavor": prompt.flavor,
                    "generator": generator_name,
                    "code": code,
                    "split": prompt.split,
                    "is_simulated": is_simulated,
                })
    return pd.DataFrame(rows)
