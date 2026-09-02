from pathlib import Path

import requests

import codegate.env as env_module
from codegate.scan.ingest import Unit
from codegate.scan.verifier import (
    GroqVerifierBackend,
    VerifierResult,
    build_verifier_backend,
    is_cached,
    to_finding,
    verify_unit,
    _parse_verdict,
)


def _unit(source: str = "def f(conn, u):\n    return conn.execute(u)\n") -> Unit:
    return Unit(
        file=Path("app.py"), lineno=10, end_lineno=11, func_name="f",
        source=source, content_hash="abc123", token_estimate=10,
    )


class _StubBackend:
    def __init__(self, response: str):
        self.response = response
        self.calls = 0

    def ask(self, code: str) -> str:
        self.calls += 1
        return self.response


class _RaisingBackend:
    def ask(self, code: str) -> str:
        raise requests.ConnectionError("network is down")


def test_parse_verdict_valid_json():
    raw = '{"vulnerable": true, "cwe": "CWE-89", "line": 2, "reason": "concat", "fix_hint": "parameterize"}'
    result = _parse_verdict(raw)
    assert result == VerifierResult(vulnerable=True, cwe="CWE-89", line=2, reason="concat", fix_hint="parameterize")


def test_parse_verdict_extracts_json_from_surrounding_prose():
    raw = 'Sure, here is my verdict:\n{"vulnerable": false, "cwe": null, "line": null, "reason": "fine", "fix_hint": ""}\nHope that helps!'
    result = _parse_verdict(raw)
    assert result.vulnerable is False
    assert result.cwe is None


def test_parse_verdict_malformed_json_returns_none():
    assert _parse_verdict("not json at all") is None


def test_parse_verdict_missing_vulnerable_key_returns_none():
    assert _parse_verdict('{"cwe": "CWE-89"}') is None


def test_parse_verdict_unrecognized_cwe_coerced_to_none():
    raw = '{"vulnerable": true, "cwe": "CWE-9999", "line": 1, "reason": "x", "fix_hint": "y"}'
    result = _parse_verdict(raw)
    assert result.vulnerable is True
    assert result.cwe is None


def test_verify_unit_returns_none_without_a_backend(tmp_path):
    assert verify_unit(_unit(), backend=None, cache_dir=tmp_path) is None
    assert list(tmp_path.iterdir()) == []


def test_verify_unit_returns_none_when_backend_raises(tmp_path):
    result = verify_unit(_unit(), backend=_RaisingBackend(), cache_dir=tmp_path)
    assert result is None
    assert list(tmp_path.iterdir()) == []


def test_verify_unit_returns_none_when_backend_response_unparseable(tmp_path):
    backend = _StubBackend("garbage response")
    result = verify_unit(_unit(), backend=backend, cache_dir=tmp_path)
    assert result is None
    assert list(tmp_path.iterdir()) == []  # unparseable results are never cached


def test_verify_unit_parses_and_caches_a_valid_verdict(tmp_path):
    raw = '{"vulnerable": true, "cwe": "CWE-89", "line": 2, "reason": "concat", "fix_hint": "parameterize"}'
    backend = _StubBackend(raw)
    result = verify_unit(_unit(), backend=backend, cache_dir=tmp_path)
    assert result == VerifierResult(vulnerable=True, cwe="CWE-89", line=2, reason="concat", fix_hint="parameterize")
    assert backend.calls == 1
    assert (tmp_path / "abc123.json").exists()


def test_verify_unit_second_call_hits_cache_not_the_backend(tmp_path):
    raw = '{"vulnerable": false, "cwe": null, "line": null, "reason": "fine", "fix_hint": ""}'
    backend = _StubBackend(raw)
    first = verify_unit(_unit(), backend=backend, cache_dir=tmp_path)
    second = verify_unit(_unit(), backend=backend, cache_dir=tmp_path)
    assert first == second
    assert backend.calls == 1  # second call served entirely from cache


def test_is_cached_false_when_no_cache_file_exists(tmp_path):
    assert is_cached("abc123", cache_dir=tmp_path) is False


def test_is_cached_true_for_a_valid_cache_entry(tmp_path):
    raw = '{"vulnerable": true, "cwe": "CWE-89", "line": 2, "reason": "x", "fix_hint": "y"}'
    verify_unit(_unit(), backend=_StubBackend(raw), cache_dir=tmp_path)
    assert is_cached("abc123", cache_dir=tmp_path) is True


def test_is_cached_false_for_a_corrupted_cache_file(tmp_path):
    # Regression: is_cached() used to only check Path.exists(), while
    # verify_unit() checked existence AND parseability via _load_cached().
    # A cache file that exists but fails to parse (corrupted mid-write, or
    # written by an older version with a different VerifierResult shape)
    # made is_cached() report True while verify_unit() actually fell
    # through to a real, billed backend call -- silently misclassifying a
    # paid call as a free cache hit in scan/pipeline.py's cost accounting.
    (tmp_path / "abc123.json").write_text("not valid json{{{")
    assert is_cached("abc123", cache_dir=tmp_path) is False

    # And verify_unit, given the same corrupted file, must actually call
    # the backend rather than silently trusting the broken cache entry --
    # proving the two functions now agree.
    backend = _StubBackend('{"vulnerable": true, "cwe": "CWE-89", "line": 1, "reason": "x", "fix_hint": "y"}')
    result = verify_unit(_unit(), backend=backend, cache_dir=tmp_path)
    assert backend.calls == 1
    assert result.vulnerable is True


def test_to_finding_maps_fields_and_tags_source_verifier():
    unit = _unit()
    result = VerifierResult(vulnerable=True, cwe="CWE-89", line=3, reason="concat", fix_hint="parameterize")
    finding = to_finding(unit, result)
    assert finding.source == "verifier"
    assert finding.cwe == "CWE-89"
    assert finding.line == 3
    assert finding.func_name == "f"
    assert finding.confidence == 1.0
    assert finding.fix_hint == "parameterize"


def test_to_finding_falls_back_to_unit_lineno_when_result_has_none():
    unit = _unit()
    result = VerifierResult(vulnerable=True, cwe="CWE-89", line=None, reason="concat", fix_hint="parameterize")
    finding = to_finding(unit, result)
    assert finding.line == unit.lineno


def test_build_verifier_backend_returns_none_without_a_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    env_module._loaded = True
    assert build_verifier_backend("llama-3.3-70b-groq") is None


def test_build_verifier_backend_maps_role_name_to_real_model_id(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    env_module._loaded = True
    backend = build_verifier_backend("llama-3.3-70b-groq")
    assert isinstance(backend, GroqVerifierBackend)
    assert backend._model == "openai/gpt-oss-120b"
    assert backend._api_key == "test-key"
