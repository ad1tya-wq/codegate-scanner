from __future__ import annotations
from dataclasses import dataclass

# Hand-written, hardcoded per CWE -- no LLM writes any of this. One entry
# per CWE this project tracks; deliberately not data-driven from a larger
# taxonomy, since the spec is a 3-CWE prototype and a lookup table for
# CWEs the scanner can't even detect would be dead weight.


@dataclass(frozen=True)
class Remediation:
    cwe: str
    title: str
    explanation: str
    before: str
    after: str


_REMEDIATIONS: dict[str, Remediation] = {
    "CWE-89": Remediation(
        cwe="CWE-89",
        title="SQL Injection",
        explanation=(
            "Building a SQL query by concatenating or formatting untrusted "
            "input directly into the query text lets an attacker change the "
            "query's structure -- for example closing a string literal early "
            "to inject their own WHERE clause or UNION SELECT. A "
            "parameterized query keeps the query's structure fixed and "
            "passes values through a separate channel the database driver "
            "escapes correctly, so no input can change what the query does."
        ),
        before=(
            "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "cur = conn.execute(query)"
        ),
        after=(
            "cur = conn.execute(\n"
            "    \"SELECT * FROM users WHERE username = ?\", (username,)\n"
            ")"
        ),
    ),
    "CWE-78": Remediation(
        cwe="CWE-78",
        title="OS Command Injection",
        explanation=(
            "shell=True (or os.system/os.popen) runs the command through a "
            "shell, which interprets metacharacters -- ;, |, &&, $(), "
            "backticks -- in any input that reaches the command string. "
            "Untrusted input can then chain or substitute arbitrary "
            "commands. Passing the command as a list of arguments with "
            "shell=False invokes the program directly, with no shell "
            "present to interpret metacharacters at all."
        ),
        before="subprocess.run(f\"ping -c 1 {host}\", shell=True)",
        after="subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)",
    ),
    "CWE-798": Remediation(
        cwe="CWE-798",
        title="Hardcoded Credentials",
        explanation=(
            "A credential literal in source code ships with every clone of "
            "the repository and every deployed artifact -- it is readable "
            "by anyone with source access, persists in version-control "
            "history even after being removed, and cannot be rotated "
            "without a code change and redeploy. Loading it from an "
            "environment variable or a secret store keeps it out of source "
            "entirely and lets it be rotated independently of the code."
        ),
        before="password = \"Sup3rSecretPassw0rd!\"",
        after="password = os.environ[\"DB_PASSWORD\"]",
    ),
}

_DEFAULT = Remediation(
    cwe="UNSPECIFIED",
    title="Needs manual review",
    explanation=(
        "This function was not certifiably safe under the current "
        "calibration and could not be automatically classified into one "
        "of the CWEs this scanner tracks (CWE-89, CWE-78, CWE-798). "
        "Manual review is needed to determine whether it is vulnerable."
    ),
    before="",
    after="",
)


def get_remediation(cwe: str) -> Remediation:
    """
    Looks up the hardcoded remediation for `cwe`. Never raises -- an
    unrecognized or "UNSPECIFIED" cwe (an escalated-but-unconfirmed
    finding) gets the generic manual-review entry rather than a KeyError,
    since the report must render a remediation section for every finding
    it lists, confirmed or not.
    """
    return _REMEDIATIONS.get(cwe, _DEFAULT)
