from __future__ import annotations
from abc import ABC, abstractmethod
import hashlib
import random
import requests
from codegate.research.corpus.prompts import Prompt


def stable_seed(*parts: object) -> int:
    """
    Deterministic, process-independent integer seed derived from arbitrary
    parts. Python's builtin hash() randomizes string hashes per-process
    (PYTHONHASHSEED) unless explicitly disabled -- never use it for
    reproducible seeding. This uses sha256 instead, so the same inputs
    always produce the same seed across separate runs of the pipeline.
    """
    joined = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(joined.encode()).hexdigest()
    return int(digest[:8], 16)


class Backend(ABC):
    name: str

    @abstractmethod
    def generate(self, prompt: Prompt, seed: int) -> str:
        """Return generated Python source code as a string."""
        raise NotImplementedError


# --- Templates the simulator draws from, keyed by (cwe, flavor). These are
# deliberately NOT the fixture files in data/fixtures/ (which are oracle
# ground truth) -- they're independent hand-written examples so the
# simulated corpus isn't literally identical to the oracle test fixtures. ---
_SIM_TEMPLATES: dict[tuple[str, str], list[str]] = {
    ("CWE-89", "vulnerable"): [
        "def {fn}(conn, {arg}):\n"
        "    query = \"SELECT * FROM users WHERE col = '\" + {arg} + \"'\"\n"
        "    return conn.execute(query).fetchall()\n",
    ],
    ("CWE-89", "near_miss"): [
        "def {fn}(conn, {arg}):\n"
        "    return conn.execute(\"SELECT * FROM users WHERE col = ?\", ({arg},)).fetchall()\n",
    ],
    ("CWE-89", "neutral"): [
        "def {fn}({arg}):\n"
        "    return {arg} * 9 / 5 + 32\n",
    ],
    ("CWE-78", "vulnerable"): [
        "import subprocess\n"
        "def {fn}({arg}):\n"
        "    return subprocess.run(f\"ping -c 1 {{{arg}}}\", shell=True, capture_output=True)\n",
    ],
    ("CWE-78", "near_miss"): [
        "import subprocess\n"
        "def {fn}({arg}):\n"
        "    return subprocess.run(['ping', '-c', '1', {arg}], shell=False, capture_output=True)\n",
    ],
    ("CWE-78", "neutral"): [
        "def {fn}({arg}):\n"
        "    return {arg}[::-1]\n",
    ],
    ("CWE-798", "vulnerable"): [
        "def {fn}():\n"
        "    password = \"Sup3rSecretPassw0rd!\"\n"
        "    return connect(password=password)\n",
    ],
    ("CWE-798", "near_miss"): [
        "import os\n"
        "def {fn}():\n"
        "    password = os.environ['DB_PASSWORD']\n"
        "    return connect(password=password)\n",
    ],
    ("CWE-798", "neutral"): [
        "def {fn}(s):\n"
        "    return s.lower().replace(' ', '-')\n",
    ],
}


class SimulatedBackend(Backend):
    """
    Deterministic, offline, no-network code generator. Produces syntactically
    valid Python that follows the CWE/flavor-appropriate pattern from
    `_SIM_TEMPLATES`, with light randomized variable/function naming so
    outputs aren't byte-identical across samples. Used to exercise the full
    pipeline end-to-end before real LLM backends are wired in.
    """

    def __init__(self, name: str, seed: int):
        self.name = name
        self._seed = seed

    def generate(self, prompt: Prompt, seed: int) -> str:
        rng = random.Random(self._stable_seed(prompt.prompt_id, seed))
        key = (prompt.cwe, prompt.flavor)
        templates = _SIM_TEMPLATES.get(key)
        if templates is None:
            templates = ["def {fn}({arg}):\n    return {arg}\n"]
        template = rng.choice(templates)
        fn_name = rng.choice(["handler", "process", "run_task", "do_work"])
        arg_name = rng.choice(["value", "data", "user_input", "payload"])
        return template.format(fn=fn_name, arg=arg_name)

    def _stable_seed(self, prompt_id: str, seed: int) -> int:
        return stable_seed(self.name, self._seed, prompt_id, seed)


class OllamaBackend(Backend):
    """Real backend: local Ollama server. Requires Ollama running (see NEEDS_FROM_YOU.md)."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.name = model
        self._model = model
        self._base_url = base_url

    def generate(self, prompt: Prompt, seed: int) -> str:
        resp = requests.post(
            f"{self._base_url}/api/generate",
            json={"model": self._model, "prompt": prompt.task, "stream": False, "options": {"seed": seed}},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["response"]


class OpenRouterBackend(Backend):
    """Real backend: OpenRouter free-tier models. Requires an API key (see NEEDS_FROM_YOU.md)."""

    def __init__(self, model: str, api_key: str):
        self.name = model
        self._model = model
        self._api_key = api_key

    def generate(self, prompt: Prompt, seed: int) -> str:
        resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self._model, "messages": [{"role": "user", "content": prompt.task}], "seed": seed},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


class GeminiBackend(Backend):
    """Real backend: Google Gemini free-tier. Requires an API key (see NEEDS_FROM_YOU.md).
    Used as the label adjudicator (see spec's "Generator roles") -- deliberately
    never one of the code generators, so it never adjudicates its own output."""

    def __init__(self, model: str, api_key: str):
        self.name = model
        self._model = model
        self._api_key = api_key

    def generate(self, prompt: Prompt, seed: int) -> str:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent",
            params={"key": self._api_key},
            json={
                "contents": [{"parts": [{"text": prompt.task}]}],
                "generationConfig": {"seed": seed},
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


class GroqBackend(Backend):
    """Real backend: Groq free-tier inference. Requires an API key (see NEEDS_FROM_YOU.md)."""

    def __init__(self, model: str, api_key: str):
        self.name = model
        self._model = model
        self._api_key = api_key

    def generate(self, prompt: Prompt, seed: int) -> str:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self._model, "messages": [{"role": "user", "content": prompt.task}], "seed": seed},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
