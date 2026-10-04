"""Checkpoint/resume for long unattended generation runs.

A 540-sample Ollama run takes 2-5 hours over a LAN connection to another
machine. A dropped connection, a model crash, or a closed laptop lid must
not cost the whole run -- and one model erroring on one prompt must not
abort the other 539 samples.
"""
import json
import pandas as pd
import pytest
from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import Backend, SimulatedBackend
from codegate.research.generation.harness import run_generation
from codegate.schemas import validate_dataframe


def _prompts(n: int = 3) -> list[Prompt]:
    return [
        Prompt(f"CWE-89-{i:03d}-vulnerable", "CWE-89", "vulnerable", "train",
               f"Write function number {i}.")
        for i in range(n)
    ]


class CountingBackend(Backend):
    """Records how many times generate() was actually invoked."""

    def __init__(self, name: str = "counter"):
        self.name = name
        self.calls = 0

    def generate(self, prompt: Prompt, seed: int) -> str:
        self.calls += 1
        return f"def f_{prompt.prompt_id.replace('-', '_')}():\n    return {seed}\n"


class FlakyBackend(Backend):
    """Raises on the Nth call, succeeds otherwise -- simulates a model hiccup."""

    def __init__(self, fail_on_call: int, name: str = "flaky"):
        self.name = name
        self.calls = 0
        self._fail_on_call = fail_on_call

    def generate(self, prompt: Prompt, seed: int) -> str:
        self.calls += 1
        if self.calls == self._fail_on_call:
            raise ConnectionError("simulated dropped connection to Ollama host")
        return "def ok():\n    pass\n"


def test_sample_ids_are_deterministic_across_runs():
    # Resume depends on being able to recognise already-generated samples,
    # so ids must not be random (they were uuid4 before).
    backends = {"b": SimulatedBackend(name="b", seed=0)}
    df1 = run_generation(_prompts(2), backends, 1, is_simulated=True)
    df2 = run_generation(_prompts(2), backends, 1, is_simulated=True)
    assert sorted(df1["sample_id"]) == sorted(df2["sample_id"])


def test_checkpoint_file_is_written_incrementally(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    backends = {"b": SimulatedBackend(name="b", seed=0)}
    run_generation(_prompts(3), backends, 1, is_simulated=True, checkpoint_path=ckpt)
    assert ckpt.exists()
    lines = [json.loads(ln) for ln in ckpt.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3
    assert {"sample_id", "prompt_id", "generator", "code"} <= set(lines[0])


def test_resume_skips_already_generated_samples(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    prompts = _prompts(4)

    first = CountingBackend()
    run_generation(prompts[:2], {"counter": first}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert first.calls == 2

    # Resuming over a superset must only generate the 2 new prompts.
    second = CountingBackend()
    df = run_generation(prompts, {"counter": second}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert second.calls == 2, "resume regenerated work already on disk"
    assert len(df) == 4, "resumed run must return the full set, not just the new samples"


def test_resumed_frame_still_matches_schema(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    backends = {"b": SimulatedBackend(name="b", seed=0)}
    run_generation(_prompts(2), backends, 1, is_simulated=True, checkpoint_path=ckpt)
    df = run_generation(_prompts(3), backends, 1, is_simulated=True, checkpoint_path=ckpt)
    validate_dataframe(df, "generations")
    assert len(df) == 3


def test_single_generation_failure_does_not_abort_the_run(tmp_path):
    # The whole point: one model hiccup must not cost the other samples.
    ckpt = tmp_path / "ckpt.jsonl"
    flaky = FlakyBackend(fail_on_call=2)
    df = run_generation(_prompts(4), {"flaky": flaky}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert flaky.calls == 4, "run stopped early instead of continuing past the failure"
    assert len(df) == 3, "the 3 successful samples should survive; the failed one is dropped"


def test_failed_sample_is_retried_on_resume(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    flaky = FlakyBackend(fail_on_call=2)
    run_generation(_prompts(4), {"flaky": flaky}, 1, is_simulated=True, checkpoint_path=ckpt)

    healthy = CountingBackend(name="flaky")
    df = run_generation(_prompts(4), {"flaky": healthy}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert healthy.calls == 1, "only the previously-failed sample should be retried"
    assert len(df) == 4


# The full 2,160 run was written into a directory still holding the
# September checkpoint. Resume matched on sample_id alone -- a hash of
# prompt_id and generator -- so 404 September answers were reused: 78 of
# them answering CWE-798 prompts that had since been rewritten, and 189
# carrying a split that had since been reassigned. These pin the fix.

def _reworded(prompts: list[Prompt]) -> list[Prompt]:
    return [Prompt(p.prompt_id, p.cwe, p.flavor, p.split, p.task + " Reworded.") for p in prompts]


def _resplit(prompts: list[Prompt], split: str) -> list[Prompt]:
    return [Prompt(p.prompt_id, p.cwe, p.flavor, split, p.task) for p in prompts]


def test_resume_regenerates_a_sample_whose_prompt_text_changed(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    run_generation(_prompts(2), {"counter": CountingBackend()}, 1, is_simulated=True, checkpoint_path=ckpt)

    second = CountingBackend()
    run_generation(_reworded(_prompts(2)), {"counter": second}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert second.calls == 2, "an answer to the old wording was reused for the new prompt"


def test_resume_reuses_the_code_but_takes_the_split_from_the_current_prompt(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    run_generation(_prompts(2), {"counter": CountingBackend()}, 1, is_simulated=True, checkpoint_path=ckpt)

    second = CountingBackend()
    df = run_generation(_resplit(_prompts(2), "calib"), {"counter": second}, 1,
                        is_simulated=True, checkpoint_path=ckpt)
    assert second.calls == 0, "same prompt text -- the code is still a valid answer"
    assert set(df["split"]) == {"calib"}, "a stale split leaked through from the checkpoint"


def test_resume_regenerates_a_legacy_record_that_cannot_be_verified(tmp_path):
    ckpt = tmp_path / "ckpt.jsonl"
    p = _prompts(1)[0]
    legacy = {"sample_id": run_generation([p], {"counter": CountingBackend()}, 1,
                                          is_simulated=True)["sample_id"][0],
              "prompt_id": p.prompt_id, "cwe": p.cwe, "flavor": p.flavor,
              "generator": "counter", "code": "def old(): pass\n",
              "split": p.split, "is_simulated": True}
    ckpt.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    second = CountingBackend()
    df = run_generation([p], {"counter": second}, 1, is_simulated=True, checkpoint_path=ckpt)
    assert second.calls == 1
    assert df["code"][0] != "def old(): pass\n"
