from __future__ import annotations

# Consensus rule v2:
# - CWE-89 / CWE-78: the dynamic oracle's verdict, which observed the code's
#   actual behaviour.
# - CWE-798 (no dynamic oracle possible): the static oracle's verdict.
#
# v1 also carried a fallback for when the oracle abstained -- "semgrep hit AND
# LLM adjudicator agrees" -- but it could never fire: label_row returns
# LABEL_ABSTAIN before reaching this function whenever the oracle has no
# verdict, and the adjudicator was never wired in (its verdict was hard-coded
# False). Both were removed after confirming nothing read them: the ranker
# trains on code alone. See docs/ENGINEERING_LOG.md section 12.9.
CONSENSUS_RULE_VERSION = "v2"

_DYNAMIC_CWES = {"CWE-89", "CWE-78"}
_STATIC_ONLY_CWES = {"CWE-798"}


def consensus_label(
    cwe: str,
    dynamic_verdict: bool | None,
    static_verdict: bool | None,
) -> int:
    if cwe in _DYNAMIC_CWES:
        verdict = dynamic_verdict
    elif cwe in _STATIC_ONLY_CWES:
        verdict = static_verdict
    else:
        raise ValueError(f"consensus_label: unrecognized CWE '{cwe}', update _DYNAMIC_CWES/_STATIC_ONLY_CWES")

    if verdict is None:
        # Callers abstain before asking; reaching here means a caller would
        # otherwise coerce "no evidence" into a label.
        raise ValueError(f"consensus_label: no oracle verdict for {cwe} -- abstain instead")
    return int(verdict)
