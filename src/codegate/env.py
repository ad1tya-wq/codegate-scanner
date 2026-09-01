from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

_loaded = False


def _ensure_env_loaded() -> None:
    global _loaded
    if _loaded:
        return
    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env")  # no-op if the file doesn't exist
    _loaded = True


def get_env(name: str, default: str) -> str:
    """
    Returns environment variable `name`, loading `.env` first if present,
    falling back to `default`. For optional settings -- use `require_env`
    when the value has no sensible default and absence should stop the run.
    """
    _ensure_env_loaded()
    return os.environ.get(name) or default


def require_env(name: str) -> str:
    """
    Returns the value of environment variable `name`, loading `.env` (repo
    root, gitignored) first if present. Raises a clear, actionable
    RuntimeError -- not a bare KeyError -- if it's missing, since this is
    the exact failure mode a user filling in `.env` for the first time will
    hit.
    """
    _ensure_env_loaded()
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable '{name}'. "
            f"Add a line '{name}=...' to .env at the repo root -- "
            f"see README.md's Quickstart section for where to get a key."
        )
    return value
