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
            f"Copy .env.example to .env at the repo root and fill it in -- "
            f"see NEEDS_FROM_YOU.md section 1 for where to get each key."
        )
    return value
