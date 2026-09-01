from codegate.report.accounting import compute_cost_summary
from codegate.scan.pipeline import ScanResult


def _result(**overrides) -> ScanResult:
    base = dict(
        findings=[], n_units=0, n_auto_approved=0, n_escalated=0, skipped=[],
        n_verified_confirmed=0, n_verified_cleared=0, n_verified_unresolved=0,
        n_verifier_cache_hits=0, n_verifier_calls_made=0, tokens_saved=0, tokens_spent=0,
    )
    base.update(overrides)
    return ScanResult(**base)


def test_cost_summary_with_no_llm_activity_is_all_zero():
    summary = compute_cost_summary(_result())
    assert summary.tokens_spent == 0
    assert summary.calls_made == 0
    assert summary.estimated_cost_usd == 0.0


def test_cost_summary_adds_system_prompt_overhead_per_call_made():
    summary = compute_cost_summary(_result(tokens_spent=1000, n_verifier_calls_made=2))
    assert summary.tokens_spent == 1000 + 2 * 150  # 150 = the documented per-call overhead
    assert summary.calls_made == 2


def test_cost_summary_calls_avoided_combines_auto_approved_and_cache_hits():
    summary = compute_cost_summary(_result(n_auto_approved=5, n_verifier_cache_hits=3))
    assert summary.calls_avoided == 8


def test_cost_summary_uses_the_known_price_for_the_named_model():
    a = compute_cost_summary(_result(tokens_spent=1_000_000), verifier_model="openai/gpt-oss-120b")
    b = compute_cost_summary(_result(tokens_spent=1_000_000), verifier_model="some-unknown-model")
    assert a.price_per_million_tokens_usd == 0.59
    assert b.price_per_million_tokens_usd == 0.59  # falls back to the default, not an error


def test_cost_summary_is_always_flagged_as_an_estimate():
    assert compute_cost_summary(_result()).is_estimate is True
