import pandas as pd
import pytest
from codegate.research.corpus.prompts import Prompt
from codegate.research.generation.backends import SimulatedBackend, Backend, stable_seed
from codegate.research.generation.harness import run_generation
from codegate.schemas import validate_dataframe


def test_stable_seed_does_not_use_builtin_hash():
    # Python's builtin hash() randomizes strings per-process (PYTHONHASHSEED)
    # unless disabled -- stable_seed must NOT rely on it, or every seed
    # derived from it (generation harness, SimulatedBackend construction)
    # silently stops being reproducible across separate runs. Pin the exact
    # expected value (independent sha256 computation) so a future edit that
    # reintroduces hash() would break this test rather than pass silently.
    import hashlib
    expected = int(hashlib.sha256("a|b|3".encode()).hexdigest()[:8], 16)
    assert stable_seed("a", "b", 3) == expected


def test_stable_seed_is_stable_across_calls():
    assert stable_seed("p1", "gen-a", 0) == stable_seed("p1", "gen-a", 0)


def test_stable_seed_differs_for_different_inputs():
    assert stable_seed("p1", "gen-a", 0) != stable_seed("p1", "gen-a", 1)
    assert stable_seed("p1", "gen-a", 0) != stable_seed("p1", "gen-b", 0)


def _sample_prompts() -> list[Prompt]:
    return [
        Prompt("CWE-89-001-vulnerable", "CWE-89", "vulnerable", "train",
               "Write a function get_user(conn, username) using string concatenation."),
        Prompt("CWE-89-001-neutral", "CWE-89", "neutral", "train",
               "Write a function celsius_to_fahrenheit(c)."),
        Prompt("CWE-89-001-near_miss", "CWE-89", "near_miss", "train",
               "Write a function get_user(conn, username) using a parameterized query."),
    ]


def test_simulated_backend_is_a_backend():
    backend = SimulatedBackend(name="sim-model-a", seed=0)
    assert isinstance(backend, Backend)


def test_simulated_backend_generates_nonempty_code():
    backend = SimulatedBackend(name="sim-model-a", seed=0)
    prompt = _sample_prompts()[0]
    code = backend.generate(prompt, seed=1)
    assert isinstance(code, str)
    assert len(code.strip()) > 0
    assert "def " in code  # should look like a Python function


def test_simulated_backend_is_deterministic_given_same_seed():
    backend = SimulatedBackend(name="sim-model-a", seed=0)
    prompt = _sample_prompts()[0]
    code1 = backend.generate(prompt, seed=42)
    code2 = backend.generate(prompt, seed=42)
    assert code1 == code2


def test_simulated_backend_vulnerable_flavor_looks_vulnerable_shaped():
    # SimulatedBackend must actually emit the vulnerable *pattern* for
    # vulnerable-flavor prompts (string concat SQL) so the oracles have
    # something real to label tonight, not just placeholder text.
    backend = SimulatedBackend(name="sim-model-a", seed=0)
    prompt = _sample_prompts()[0]  # vulnerable SQLi prompt
    code = backend.generate(prompt, seed=1)
    assert "+" in code or "%" in code or "f\"" in code or "f'" in code


def test_simulated_backend_near_miss_flavor_uses_parameterized_query():
    backend = SimulatedBackend(name="sim-model-a", seed=0)
    prompt = _sample_prompts()[2]  # near_miss SQLi prompt
    code = backend.generate(prompt, seed=1)
    assert "?" in code  # sqlite3 parameterized placeholder


def test_run_generation_produces_valid_schema_dataframe():
    prompts = _sample_prompts()
    backends = {"sim-model-a": SimulatedBackend(name="sim-model-a", seed=0)}
    df = run_generation(prompts, backends, samples_per_prompt=2, is_simulated=True)
    validate_dataframe(df, "generations")
    assert len(df) == len(prompts) * len(backends) * 2
    assert df["is_simulated"].all()
    assert set(df["generator"]) == {"sim-model-a"}


def test_run_generation_covers_every_generator_and_prompt():
    prompts = _sample_prompts()
    backends = {
        "sim-model-a": SimulatedBackend(name="sim-model-a", seed=0),
        "sim-model-b": SimulatedBackend(name="sim-model-b", seed=1),
    }
    df = run_generation(prompts, backends, samples_per_prompt=1, is_simulated=True)
    assert set(df["prompt_id"]) == {p.prompt_id for p in prompts}
    assert set(df["generator"]) == {"sim-model-a", "sim-model-b"}
