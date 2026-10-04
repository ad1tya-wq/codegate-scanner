from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from pygments import lex
from pygments.lexers import PythonLexer
from pygments.token import Comment, Keyword, Name, Number, Operator, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from codegate import __version__
from codegate.report.accounting import CostSummary, compute_cost_summary
from codegate.report.remediation import get_remediation
from codegate.scan.pipeline import ScanResult

# Token-type -> hex color for the code excerpts. A small, hand-picked
# palette (not a full pygments style plugin) since reportlab Paragraph
# markup only needs inline <font color=...> spans, not a stylesheet.
_TOKEN_COLORS = [
    (Keyword, "#0000AA"),
    (Name.Builtin, "#0086B3"),
    (String, "#008000"),
    (Number, "#AA5500"),
    (Comment, "#888888"),
    (Operator, "#AA0000"),
]

_SEVERITY_COLORS = {"ERROR": colors.HexColor("#B00020"), "WARNING": colors.HexColor("#B36B00"), "REVIEW": colors.HexColor("#555555")}


def _token_color(ttype) -> str | None:
    for prefix, color in _TOKEN_COLORS:
        if ttype in prefix:
            return color
    return None


def _highlight(code: str) -> str:
    """
    Turns Python source into reportlab Paragraph markup (a restricted
    XML subset -- <font>, <br/>, no full HTML) with per-token colors from
    pygments' lexer. Leading whitespace is preserved with non-breaking
    spaces since Paragraph collapses runs of plain spaces.
    """
    parts: list[str] = []
    for ttype, value in lex(code, PythonLexer()):
        lines = value.split("\n")
        for i, line in enumerate(lines):
            if i > 0:
                parts.append("<br/>")
            if not line:
                continue
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            text = "&nbsp;" * indent + escape(stripped)
            color = _token_color(ttype)
            parts.append(f'<font color="{color}">{text}</font>' if color else text)
    return "".join(parts)


def _read_excerpt(file: Path, line: int, context: int = 3) -> tuple[str, int]:
    """
    Returns (excerpt_text, first_line_number) for the lines around `line`
    in `file`, or ("", 0) if the file can no longer be read -- the source
    may have moved or changed between the scan and report generation.
    """
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", 0
    start = max(line - 1 - context, 0)
    end = min(line - 1 + context + 1, len(lines))
    return "\n".join(lines[start:end]), start + 1


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "Title": base["Title"],
        "Heading1": base["Heading1"],
        "Heading2": base["Heading2"],
        "Body": base["BodyText"],
        "Small": ParagraphStyle("Small", parent=base["BodyText"], fontSize=8, textColor=colors.grey),
        "Banner": ParagraphStyle(
            "Banner", parent=base["BodyText"], textColor=colors.HexColor("#7A5B00"),
            backColor=colors.HexColor("#FFF3CD"), borderPadding=8, spaceAfter=12,
        ),
        "Code": ParagraphStyle(
            "Code", fontName="Courier", fontSize=8, leading=10,
            backColor=colors.HexColor("#F5F5F5"), borderPadding=6, spaceAfter=6,
        ),
    }


def _cover_flowables(styles, result: ScanResult, target: Path, verifier_model: str | None) -> list:
    calib = result.calibration
    flow = [
        Spacer(1, 1.5 * inch),
        Paragraph("CodeGate Security Scan Report", styles["Title"]),
        Spacer(1, 0.3 * inch),
        Paragraph(f"Target: {escape(str(target))}", styles["Body"]),
        Paragraph(f"Scanned: {datetime.now(timezone.utc).isoformat()}", styles["Body"]),
        Paragraph(f"CodeGate version: {__version__}", styles["Body"]),
    ]
    if calib is not None:
        flow.append(Paragraph(
            f"Ranker: {escape(calib.ranker_id)}  |  Corpus: {escape(calib.corpus_version)}  |  "
            f"Verifier: {escape(verifier_model) if verifier_model else 'not used'}", styles["Body"]
        ))
    flow.append(Paragraph(
        f"{len(result.findings)} finding(s) across {result.n_units} scanned function(s), "
        f"{len(result.skipped)} file(s) skipped.", styles["Body"]
    ))
    if calib is not None and calib.is_provisional:
        flow.append(Spacer(1, 0.3 * inch))
        flow.append(Paragraph(
            "PROVISIONAL CERTIFICATE -- this scan's model was calibrated on "
            f"'{escape(calib.corpus_version)}', not a real corpus. Coverage and "
            "miss-rate numbers below are not yet meaningful. See "
            "docs/ENGINEERING_LOG.md.", styles["Banner"],
        ))
    flow.append(PageBreak())
    return flow


def _attribution_flowables(styles, result: ScanResult, cost: CostSummary) -> list:
    n_semgrep = sum(1 for f in result.findings if f.source == "semgrep")
    n_verifier = sum(1 for f in result.findings if f.source == "verifier")
    n_model_review = sum(1 for f in result.findings if f.source == "model")
    rows = [
        ["Source", "Count", "What it means"],
        ["Semgrep (static rules)", str(n_semgrep), "Deterministic pattern match, zero LLM cost"],
        ["ML gate (escalated)", str(result.n_escalated), "Model flagged as not-certifiably-safe"],
        ["LLM verifier (confirmed)", str(n_verifier), "Of the escalated units, confirmed vulnerable"],
        ["Needs manual review", str(n_model_review), "Escalated, not resolved by the verifier"],
        ["Auto-approved", str(result.n_auto_approved), "Cleared under the certified miss-rate <= alpha"],
    ]
    table = Table(rows, colWidths=[1.8 * inch, 0.8 * inch, 3.4 * inch])
    table.setStyle(_table_style())
    return [Paragraph("Detection Attribution", styles["Heading1"]), Spacer(1, 6), table, Spacer(1, 16)]


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B2B2B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
    ])


def _executive_summary_flowables(styles, result: ScanResult, cost: CostSummary) -> list:
    by_severity: dict[str, int] = {}
    for f in result.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    rows = [["Severity", "Count"]] + [[sev, str(n)] for sev, n in sorted(by_severity.items())]
    if len(rows) == 1:
        rows.append(["(none)", "0"])
    table = Table(rows, colWidths=[2 * inch, 2 * inch])
    table.setStyle(_table_style())
    return [
        Paragraph("Executive Summary", styles["Heading1"]),
        Paragraph(
            f"{result.n_units} function(s) scanned. {result.n_auto_approved} auto-approved "
            f"under the certificate. {result.n_escalated} escalated for review, of which "
            f"{cost.calls_made} were sent to the LLM verifier this run and {cost.calls_avoided} "
            "were resolved without one (auto-approved or already cached).",
            styles["Body"],
        ),
        Spacer(1, 6),
        table,
        Spacer(1, 16),
    ]


def _cost_flowables(styles, cost: CostSummary) -> list:
    rows = [
        ["Metric", "Value"],
        ["Tokens saved (est.)", f"{cost.tokens_saved:,}"],
        ["Tokens spent (est.)", f"{cost.tokens_spent:,}"],
        ["LLM calls avoided", str(cost.calls_avoided)],
        ["LLM calls made", str(cost.calls_made)],
        ["Estimated cost", f"${cost.estimated_cost_usd:.4f}"],
        ["Price used", f"${cost.price_per_million_tokens_usd:.2f} / 1M tokens"],
    ]
    table = Table(rows, colWidths=[2.2 * inch, 2 * inch])
    table.setStyle(_table_style())
    return [
        Paragraph("Cost & Token Accounting", styles["Heading1"]),
        table,
        Spacer(1, 6),
        Paragraph(
            "All figures on this page are estimates. Token counts use a "
            "chars/4 heuristic (no tiktoken dependency), not an exact "
            "tokenizer count; \"tokens saved\" is measured against a "
            "baseline of sending every scanned function to the LLM "
            "verifier exactly once. See docs/ENGINEERING_LOG.md for the "
            "full methodology.",
            styles["Small"],
        ),
        Spacer(1, 16),
    ]


def _findings_flowables(styles, result: ScanResult) -> list:
    flow = [Paragraph("Findings Detail", styles["Heading1"])]
    if not result.findings:
        flow.append(Paragraph("No findings.", styles["Body"]))
        return flow + [Spacer(1, 16)]

    for f in result.findings:
        rem = get_remediation(f.cwe)
        flow.append(Paragraph(f"{escape(str(f.file))}:{f.line} -- {escape(f.func_name)}()", styles["Heading2"]))
        flow.append(Paragraph(
            f"<b>{escape(f.cwe)}</b> ({escape(rem.title)}) -- severity {escape(f.severity)}, "
            f"source {escape(f.source)}, confidence {f.confidence:.2f}", styles["Body"],
        ))
        flow.append(Paragraph(escape(f.message), styles["Body"]))

        excerpt, first_line = _read_excerpt(f.file, f.line)
        if excerpt:
            flow.append(Paragraph(f"Excerpt (from line {first_line}):", styles["Small"]))
            flow.append(Paragraph(_highlight(excerpt), styles["Code"]))

        if rem.before and rem.after:
            flow.append(Paragraph("Remediation:", styles["Small"]))
            flow.append(Paragraph(escape(rem.explanation), styles["Body"]))
            flow.append(Paragraph("Before:", styles["Small"]))
            flow.append(Paragraph(_highlight(rem.before), styles["Code"]))
            flow.append(Paragraph("After:", styles["Small"]))
            flow.append(Paragraph(_highlight(rem.after), styles["Code"]))
        elif f.fix_hint:
            flow.append(Paragraph(f"Fix: {escape(f.fix_hint)}", styles["Body"]))

        flow.append(HRFlowable(width="100%", color=colors.HexColor("#DDDDDD")))
        flow.append(Spacer(1, 10))
    return flow


def _certificate_flowables(styles, result: ScanResult) -> list:
    calib = result.calibration
    flow = [Paragraph("Coverage & Certificate", styles["Heading1"])]
    if calib is None:
        flow.append(Paragraph("No certificate -- no functions were scored (nothing to certify).", styles["Body"]))
        return flow + [Spacer(1, 16)]

    rows = [
        ["Field", "Value"],
        ["Ranker", calib.ranker_id],
        ["Corpus version", calib.corpus_version],
        ["Provisional", "yes" if calib.is_provisional else "no"],
        ["t_hat (auto-approve threshold)", "none -- everything escalated" if calib.t_hat is None else f"{calib.t_hat:.4f}"],
        ["Certified max miss-rate (alpha)", f"{calib.alpha:.2%}"],
        ["Confidence (1 - delta)", f"{1 - calib.delta:.2%}"],
        ["Calibration vulnerable samples", str(calib.n_vuln_calib)],
        ["Certificate method", calib.method_description()],
        ["Created", calib.created_at],
    ]
    table = Table(rows, colWidths=[2.4 * inch, 3.6 * inch])
    table.setStyle(_table_style())
    flow.append(table)
    flow.append(Spacer(1, 6))
    flow.append(Paragraph(
        f"What this guarantees: of vulnerable functions, at most {calib.alpha:.2%} "
        f"score at or above t_hat and are auto-approved, with {1 - calib.delta:.2%} "
        "confidence -- a distribution-free certificate (Learn-Then-Test "
        "conformal risk control), not a heuristic claim. "
        + ("Each task group in the calibration data counts as one piece of "
           "evidence, however many models answered it, so correlated answers "
           "to the same task cannot inflate the certificate. "
           if calib.method == "cluster-hb" else "")
        + "It does not guarantee anything about a function scored below "
        "t_hat (escalated) beyond \"not certified safe.\"",
        styles["Body"],
    ))
    if calib.is_provisional:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph(
            "This certificate is PROVISIONAL: calibrated on a simulated "
            "corpus, not real LLM-generated code. Treat every number above "
            "as illustrative of the mechanism, not yet a real guarantee.",
            styles["Banner"],
        ))
    flow.append(Spacer(1, 16))
    return flow


def _methodology_flowables(styles) -> list:
    return [
        Paragraph("Methodology & Limitations", styles["Heading1"]),
        Paragraph(
            "CodeGate is a certified-miss-rate security scanner for Python. "
            "It escalates to an LLM only what it cannot statistically prove "
            "is safe, using Learn-Then-Test conformal risk control over a "
            "ranker trained on labeled generated code.",
            styles["Body"],
        ),
        Spacer(1, 6),
        Paragraph(
            "Scope: Python only. Three CWEs are tracked -- CWE-89 (SQL "
            "injection), CWE-78 (OS command injection), CWE-798 (hardcoded "
            "credentials). Analysis is intraprocedural (one function at a "
            "time); cross-function data flow is not modeled. The threat "
            "model is benign-accident, not adversarial -- the scanner "
            "never executes the code it scans.",
            styles["Body"],
        ),
        Spacer(1, 6),
        Paragraph(
            "Static findings (semgrep) are deterministic pattern matches "
            "against a hand-written local ruleset. Model findings come from "
            "a ranker scored against a certified threshold; unresolved "
            "model findings needed LLM verification that either wasn't "
            "attempted (--no-llm or no API key) or didn't return a usable "
            "verdict.",
            styles["Body"],
        ),
    ]


def generate_pdf(
    result: ScanResult,
    target: Path,
    output_path: Path,
    verifier_model: str | None = None,
) -> Path:
    """
    Renders the full report to `output_path`. Deterministic layout, no
    LLM writes any prose here -- every sentence in this module is
    hand-written, and every number comes from `result`/`compute_cost_summary`.
    """
    cost = compute_cost_summary(result, verifier_model)
    styles = _styles()

    story: list = []
    story += _cover_flowables(styles, result, target, verifier_model)
    story += _executive_summary_flowables(styles, result, cost)
    story += _attribution_flowables(styles, result, cost)
    story += _cost_flowables(styles, cost)
    story += _findings_flowables(styles, result)
    story.append(PageBreak())
    story += _certificate_flowables(styles, result)
    story += _methodology_flowables(styles)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="CodeGate Security Scan Report",
    )
    doc.build(story)
    return output_path
