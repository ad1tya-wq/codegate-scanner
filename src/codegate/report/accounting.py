from __future__ import annotations
from dataclasses import dataclass

from codegate.scan.pipeline import ScanResult

# Published per-million-token prices, hardcoded (checked 2026-08-31). Only
# the verifier model needs a price -- generation-side model cost is a
# research-time concern (Track A), not something a scan report accounts
# for. Update this table by hand when the number changes; there is no
# live pricing API call here on purpose (a report must be reproducible
# from the numbers it was run with, not from whatever a price endpoint
# returns today).
_PRICE_PER_MILLION_TOKENS_USD: dict[str, float] = {
    "llama-3.3-70b-versatile": 0.59,  # Groq, blended input+output estimate
}
_DEFAULT_PRICE_PER_MILLION_TOKENS_USD = 0.59

# scan/ingest.py::_estimate_tokens' chars/4 heuristic doesn't account for
# the fixed system prompt (scan/verifier.py::_SYSTEM_PROMPT) sent with
# every fresh call -- added once per call actually made, not per unit,
# since it's a per-request constant, not a function of code size.
_SYSTEM_PROMPT_TOKEN_OVERHEAD = 150


@dataclass(frozen=True)
class CostSummary:
    tokens_saved: int
    tokens_spent: int
    calls_avoided: int
    calls_made: int
    estimated_cost_usd: float
    price_per_million_tokens_usd: float
    is_estimate: bool


def compute_cost_summary(result: ScanResult, verifier_model: str | None = None) -> CostSummary:
    """
    Turns a ScanResult's raw token/call counts into a priced summary.
    Every number here is a documented estimate, not a measurement:
    token counts come from ingest.py's chars/4 heuristic (no tiktoken
    dependency), and the system-prompt overhead is a fixed constant, not
    the exact prompt actually sent. `is_estimate` is always True today --
    kept as an explicit field, not a docstring note, so a report renderer
    can't forget to disclose it.
    """
    price = _PRICE_PER_MILLION_TOKENS_USD.get(verifier_model, _DEFAULT_PRICE_PER_MILLION_TOKENS_USD)
    tokens_spent = result.tokens_spent + result.n_verifier_calls_made * _SYSTEM_PROMPT_TOKEN_OVERHEAD
    calls_avoided = result.n_auto_approved + result.n_verifier_cache_hits

    return CostSummary(
        tokens_saved=result.tokens_saved,
        tokens_spent=tokens_spent,
        calls_avoided=calls_avoided,
        calls_made=result.n_verifier_calls_made,
        estimated_cost_usd=round(tokens_spent * price / 1_000_000, 6),
        price_per_million_tokens_usd=price,
        is_estimate=True,
    )
