from __future__ import annotations

# Consensus rule v1 (documented, see spec):
# - CWE-89 / CWE-78 (dynamic oracle available): dynamic verdict is authoritative
#   when it returns a verdict (not None). Dynamic evidence outranks static
#   pattern-matching, since it observed actual exploit behavior. When the
#   dynamic oracle abstains (None -- function not found / errored), fall back
#   to semgrep_hit AND adjudicator_verdict both agreeing.
# - CWE-798 (no dynamic oracle possible): static_verdict is authoritative when
#   present; falls back to semgrep_hit AND adjudicator_verdict otherwise.
CONSENSUS_RULE_VERSION = "v1"

_DYNAMIC_CWES = {"CWE-89", "CWE-78"}
_STATIC_ONLY_CWES = {"CWE-798"}


def consensus_label(
    cwe: str,
    semgrep_hit: bool,
    dynamic_verdict: bool | None,
    static_verdict: bool | None,
    adjudicator_verdict: bool,
) -> int:
    if cwe in _DYNAMIC_CWES:
        if dynamic_verdict is not None:
            return int(dynamic_verdict)
        return int(semgrep_hit and adjudicator_verdict)

    if cwe in _STATIC_ONLY_CWES:
        if static_verdict is not None:
            return int(static_verdict)
        return int(semgrep_hit and adjudicator_verdict)

    raise ValueError(f"consensus_label: unrecognized CWE '{cwe}', update _DYNAMIC_CWES/_STATIC_ONLY_CWES")
