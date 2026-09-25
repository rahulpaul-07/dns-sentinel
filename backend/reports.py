"""PDF report rendering (fpdf2) for single alerts and the full audit ledger."""
from datetime import datetime, timezone

from fpdf import FPDF

FONT = "Helvetica"  # built-in core font; no font files to ship


def pdf_text(value) -> str:
    """Coerce any value to text the Latin-1 core fonts can render.

    Explanations and queries can contain characters outside Latin-1 (arrows,
    punycode-decoded names, pasted text); without this, fpdf raises and the
    endpoint 500s.
    """
    return str("" if value is None else value).encode("latin-1", "replace").decode("latin-1")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ts(value, fmt="%Y-%m-%d %H:%M:%S") -> str:
    return value.strftime(fmt) if value else "N/A"


def _truncate(value: str, n: int) -> str:
    value = value or ""
    return value[: n - 3] + "..." if len(value) > n else value


def alert_pdf(log) -> bytes:
    """One-page incident report for a single DNSAuditLog row."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_fill_color(20, 30, 48)
    pdf.rect(0, 0, 210, 40, "F")
    pdf.set_font(FONT, "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 20, "DNSentinel: Incident Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font(FONT, "", 10)
    pdf.cell(0, 5, f"Generated: {_now()}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(15)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font(FONT, "B", 16)
    pdf.cell(0, 10, "1. Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 11)
    pdf.multi_cell(0, 7, pdf_text(
        f"Source {log.source_ip} queried '{log.query}', scored {log.risk_score} "
        f"({log.risk_level}) and classified as {log.prediction}."
    ))
    pdf.ln(5)

    pdf.set_font(FONT, "B", 12)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(95, 10, "Metric", border=1, fill=True)
    pdf.cell(95, 10, "Value", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 11)
    rows = [
        ("Incident ID", f"SOC-{log.id}"),
        ("Timestamp (UTC)", _ts(log.timestamp)),
        ("Source IP", log.source_ip),
        ("Query", _truncate(log.query, 48)),
        ("Record type", log.qtype),
        ("Risk score", log.risk_score),
        ("Severity", log.risk_level),
        ("Classification", log.prediction),
        ("Priority", f"{log.priority} ({log.priority_score})"),
        ("Analyst verdict", "False positive" if log.is_false_positive else "Not reviewed"),
    ]
    for metric, val in rows:
        pdf.cell(95, 8, metric, border=1)
        pdf.cell(95, 8, pdf_text(val), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    pdf.set_font(FONT, "B", 14)
    pdf.cell(0, 10, "2. Technical Analysis", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 10)
    pdf.multi_cell(0, 6, pdf_text(log.explanation or "No detailed explanation recorded."))
    pdf.ln(4)

    if log.mitre_data:
        pdf.set_font(FONT, "B", 14)
        pdf.cell(0, 10, "3. MITRE ATT&CK Mapping", new_x="LMARGIN", new_y="NEXT")
        for tid, technique in log.mitre_data.items():
            name = technique.get("Name", "") if isinstance(technique, dict) else technique
            pdf.set_font(FONT, "B", 10)
            pdf.cell(30, 6, pdf_text(tid))
            pdf.set_font(FONT, "", 10)
            pdf.cell(0, 6, pdf_text(name), new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


def ledger_pdf(logs: list) -> bytes:
    """Multi-page audit report over all rows (newest first)."""
    total = len(logs)
    counts = {lvl: sum(1 for x in logs if x.risk_level == lvl) for lvl in ("Critical", "High", "Medium", "Low")}
    threats = counts["Critical"] + counts["High"] + counts["Medium"]

    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_y(100)
    pdf.set_font(FONT, "B", 36)
    pdf.set_text_color(0, 242, 255)
    pdf.cell(0, 20, "DNSENTINEL", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font(FONT, "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 15, "DNS Security Audit Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(20)
    pdf.set_font(FONT, "", 12)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 10, f"Generated: {_now()}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 10, f"Events analysed: {total}", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font(FONT, "B", 20)
    pdf.cell(0, 20, "1. Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 11)
    pdf.multi_cell(0, 7, f"{total} DNS queries were scored by the detection ensemble; "
                         f"{threats} were rated Medium or above.")
    pdf.ln(8)
    pdf.set_font(FONT, "B", 12)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(95, 10, "Severity", border=1, fill=True)
    pdf.cell(95, 10, "Events", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 11)
    for level, count in counts.items():
        pdf.cell(95, 10, level, border=1)
        pdf.cell(95, 10, str(count), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)

    pdf.set_font(FONT, "B", 20)
    pdf.cell(0, 20, "2. Top Threats", new_x="LMARGIN", new_y="NEXT")
    top = [x for x in logs if x.risk_level in ("Critical", "High")][:10]
    if not top:
        pdf.set_font(FONT, "I", 11)
        pdf.cell(0, 10, "No Critical or High severity events in this period.", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font(FONT, "B", 10)
        pdf.set_fill_color(220, 38, 38)
        pdf.set_text_color(255, 255, 255)
        for w, h in ((35, "Time (UTC)"), (35, "Source IP"), (80, "Query"), (20, "Score")):
            pdf.cell(w, 10, h, border=1, fill=True)
        pdf.cell(20, 10, "Level", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font(FONT, "", 9)
        for x in top:
            pdf.cell(35, 8, _ts(x.timestamp, "%m-%d %H:%M:%S"), border=1)
            pdf.cell(35, 8, pdf_text(x.source_ip), border=1)
            pdf.cell(80, 8, pdf_text(_truncate(x.query, 42)), border=1)
            pdf.cell(20, 8, str(x.risk_score), border=1)
            pdf.cell(20, 8, pdf_text(x.risk_level), border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()
    pdf.set_font(FONT, "B", 20)
    pdf.cell(0, 20, "3. Audit Ledger (latest 100)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "B", 10)
    pdf.set_fill_color(203, 213, 225)
    for w, h in ((32, "Time (UTC)"), (35, "Source IP"), (93, "Query")):
        pdf.cell(w, 10, h, border=1, fill=True)
    pdf.cell(30, 10, "Level", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, "", 8)
    for x in logs[:100]:
        pdf.cell(32, 8, _ts(x.timestamp, "%Y-%m-%d %H:%M"), border=1)
        pdf.cell(35, 8, pdf_text(x.source_ip), border=1)
        pdf.cell(93, 8, pdf_text(_truncate(x.query, 55)), border=1)
        pdf.cell(30, 8, pdf_text(x.risk_level), border=1, new_x="LMARGIN", new_y="NEXT")
    if total > 100:
        pdf.ln(5)
        pdf.set_font(FONT, "I", 9)
        pdf.cell(0, 10, f"... and {total - 100} more events. Use the CSV export for the full ledger.",
                 new_x="LMARGIN", new_y="NEXT", align="C")

    return bytes(pdf.output())
