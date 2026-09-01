from codegate.report.remediation import get_remediation


def test_get_remediation_returns_the_right_entry_for_each_tracked_cwe():
    for cwe in ("CWE-89", "CWE-78", "CWE-798"):
        rem = get_remediation(cwe)
        assert rem.cwe == cwe
        assert rem.before
        assert rem.after
        assert rem.explanation


def test_get_remediation_falls_back_to_manual_review_for_unrecognized_cwe():
    rem = get_remediation("UNSPECIFIED")
    assert rem.cwe == "UNSPECIFIED"
    assert rem.before == ""
    assert rem.after == ""


def test_get_remediation_never_raises_on_a_garbage_input():
    rem = get_remediation("not-a-real-cwe")
    assert rem.title == "Needs manual review"
