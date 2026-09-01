import pytest
import codegate.env as env_module
from codegate.env import require_env


def test_require_env_raises_clear_error_when_missing(monkeypatch):
    monkeypatch.delenv("CODEGATE_TEST_VAR_NOT_SET", raising=False)
    env_module._loaded = True  # skip .env loading, test env state directly
    with pytest.raises(RuntimeError, match="CODEGATE_TEST_VAR_NOT_SET"):
        require_env("CODEGATE_TEST_VAR_NOT_SET")


def test_require_env_returns_value_when_set(monkeypatch):
    monkeypatch.setenv("CODEGATE_TEST_VAR", "some-value")
    env_module._loaded = True
    assert require_env("CODEGATE_TEST_VAR") == "some-value"


def test_require_env_error_mentions_dotenv_and_needs_file(monkeypatch):
    monkeypatch.delenv("CODEGATE_TEST_VAR_NOT_SET", raising=False)
    env_module._loaded = True
    with pytest.raises(RuntimeError, match=r"\.env"):
        require_env("CODEGATE_TEST_VAR_NOT_SET")
