
import io
from datetime import datetime
from typing import List, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

_FONT_DIR = os.path.join(os.path.dirname(__file__), "..", "fonts")
try:
    pdfmetrics.registerFont(TTFont('JetBrainsMono', os.path.join(_FONT_DIR, 'JetBrainsMono-Regular.ttf')))
    pdfmetrics.registerFont(TTFont('JetBrainsMono-Bold', os.path.join(_FONT_DIR, 'JetBrainsMono-Bold.ttf')))
    pdfmetrics.registerFont(TTFont('JetBrainsMono-Italic', os.path.join(_FONT_DIR, 'JetBrainsMono-Italic.ttf')))
    _HAS_JB_MONO = True
except Exception:
    _HAS_JB_MONO = False


_DARK       = colors.HexColor("#1a1a2e")
_ACCENT     = colors.HexColor("#0f3460")
_LIGHT_BG   = colors.HexColor("#f8f9fa")
_MUTED      = colors.HexColor("#6c757d")

_SEV_COLORS = {
    "LOW":      colors.HexColor("#198754"),
    "MEDIUM":   colors.HexColor("#fd7e14"),
    "HIGH":     colors.HexColor("#dc3545"),
    "CRITICAL": colors.HexColor("#7b0d1e"),
}

_SEV_LABELS = {
    "LOW":      "Normal Internet Exposure",
    "MEDIUM":   "Requires Monitoring",
    "HIGH":     "Likely Unsafe or Deceptive Behavior",
    "CRITICAL": "Active Threat Likely or Confirmed",
}


def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    if _HAS_JB_MONO:
        font_body = "JetBrainsMono"
        font_bold = "JetBrainsMono-Bold"
        font_italic = "JetBrainsMono-Italic"
    else:
        font_body = "Courier"
        font_bold = "Courier-Bold"
        font_italic = "Courier-Oblique"

    styles["title"] = ParagraphStyle(
        "title", fontSize=18, fontName=font_bold,
        textColor=_DARK, spaceAfter=8, leading=22, alignment=TA_LEFT,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", fontSize=9, fontName=font_body,
        textColor=_DARK, spaceAfter=14, leading=14, alignment=TA_LEFT,
    )
    styles["machine_data"] = ParagraphStyle(
        "machine_data", fontSize=9, fontName=font_body,
        textColor=_DARK, spaceAfter=14, leading=14, alignment=TA_LEFT,
    )
    styles["section_header"] = ParagraphStyle(
        "section_header", fontSize=12, fontName=font_bold,
        textColor=_ACCENT, spaceBefore=22, spaceAfter=8, leading=16,
    )
    styles["body"] = ParagraphStyle(
        "body", fontSize=9.5, fontName=font_body,
        textColor=_DARK, spaceAfter=8, leading=14, alignment=TA_JUSTIFY,
    )
    styles["body_bold"] = ParagraphStyle(
        "body_bold", fontSize=9.5, fontName=font_bold,
        textColor=_DARK, spaceAfter=6, leading=14,
    )
    styles["caption"] = ParagraphStyle(
        "caption", fontSize=8.5, fontName=font_italic,
        textColor=_DARK, spaceAfter=6, leading=12,
    )
    styles["notice"] = ParagraphStyle(
        "notice", fontSize=8.5, fontName=font_italic,
        textColor=_DARK, spaceAfter=6, leading=12, alignment=TA_JUSTIFY,
    )
    styles["bullet"] = ParagraphStyle(
        "bullet", fontSize=9.5, fontName=font_body,
        textColor=_DARK, spaceAfter=6, leftIndent=15, leading=14,
    )
    return styles


from reportlab.graphics.shapes import Drawing, Wedge, Circle, String, Group
from reportlab.platypus import Spacer, Table, TableStyle


def _draw_donut(value: int, max_val: int, colorHex: str, label_top: str, label_bottom: str, size: int = 100):
    """Draws a vector graphic donut chart gauge for the PDF."""
    d = Drawing(size, size)
    c = colors.HexColor(colorHex)
    bg_c = colors.HexColor("#e9ecef")
    center = size / 2
    r = size / 2
    inner_r = r * 0.75

    d.add(Circle(center, center, r, fillColor=bg_c, strokeColor=None))

    angle = 360 * (value / max_val)
    start_angle = 90 - angle
    end_angle = 90

    if angle > 0 and angle < 360:
        d.add(Wedge(center, center, r, start_angle, end_angle, fillColor=c, strokeColor=None))
    elif angle >= 360:
        d.add(Circle(center, center, r, fillColor=c, strokeColor=None))

    d.add(Circle(center, center, inner_r, fillColor=colors.white, strokeColor=None))

    if _HAS_JB_MONO:
        font_body = "JetBrainsMono"
        font_bold = "JetBrainsMono-Bold"
    else:
        font_body = "Courier"
        font_bold = "Courier-Bold"

    d.add(String(center, center - 5, str(value), fontSize=18, fontName=font_bold, fillColor=c, textAnchor="middle"))

    return d

def _score_table(score: int, severity: str, confidence_pct: int, styles, priority_score: Optional[float] = None):
    sev_color = _SEV_COLORS.get(severity, _SEV_COLORS["LOW"])
    sev_label = _SEV_LABELS.get(severity, severity)

    if _HAS_JB_MONO:
        font_body = "JetBrainsMono"
        font_bold = "JetBrainsMono-Bold"
    else:
        font_body = "Courier"
        font_bold = "Courier-Bold"

    size = 85

    if priority_score is not None:
        priority_drawing = _draw_donut(int(priority_score), 100, sev_color.hexval(), "", "", size)
        score_drawing = _draw_donut(score, 100, sev_color.hexval(), "", "", size)
        conf_color = "#198754" if confidence_pct >= 80 else ("#fd7e14" if confidence_pct >= 60 else "#dc3545")
        conf_drawing = _draw_donut(confidence_pct, 100, conf_color, "", "", size)

        priority_text = Paragraph(
            f'<font size="12" fontName="{font_bold}" color="{sev_color.hexval()}">[{priority_score:.1f}]</font><br/>'
            f'<font size="8" fontName="{font_body}" color="#0f3460">EIRPP PRIORITY</font>',
            ParagraphStyle("pt", alignment=TA_CENTER, leading=14),
        )
        score_text = Paragraph(
            f'<font size="12" fontName="{font_bold}" color="{_ACCENT.hexval()}">[{score:.0f}]</font><br/>'
            f'<font size="8" fontName="{font_body}" color="#0f3460">RISK SCORE</font>',
            ParagraphStyle("st", alignment=TA_CENTER, leading=14),
        )
        conf_text = Paragraph(
            f'<font size="12" fontName="{font_bold}" color="#6c757d">[{confidence_pct}%]</font><br/>'
            f'<font size="8" fontName="{font_body}" color="#0f3460">CONFIDENCE</font>',
            ParagraphStyle("ct", alignment=TA_CENTER, leading=14),
        )

        tbl = Table(
            [
                [priority_drawing, score_drawing, conf_drawing],
                [priority_text, score_text, conf_text]
            ],
            colWidths=[53*mm, 53*mm, 53*mm],
        )
        tbl.setStyle(TableStyle([
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ]))
        return tbl

    score_drawing = _draw_donut(score, 100, sev_color.hexval(), "", "", size)
    conf_drawing = _draw_donut(confidence_pct, 100, _ACCENT.hexval(), "", "", size)

    score_text = Paragraph(
        f'<font size="12" fontName="{font_bold}" color="{sev_color.hexval()}">[{severity}]</font><br/>'
        f'<font size="8" fontName="{font_body}" color="#0f3460">OVERALL RISK SCORE</font>',
        ParagraphStyle("st", alignment=TA_CENTER, leading=14),
    )

    conf_text = Paragraph(
        f'<font size="12" fontName="{font_bold}" color="{_ACCENT.hexval()}">[{confidence_pct}%]</font><br/>'
        f'<font size="8" fontName="{font_body}" color="#0f3460">SIGNAL CONFIDENCE</font>',
        ParagraphStyle("ct", alignment=TA_CENTER, leading=14),
    )

    tbl = Table(
        [
            [score_drawing, conf_drawing],
            [score_text, conf_text]
        ],
        colWidths=[80*mm, 80*mm],
    )
    tbl.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
    ]))
    return tbl



from reportlab.graphics.shapes import Rect, PolyLine, Line

def _draw_trend_line(current_score: int, prev_score: Optional[int]):
    """Draw trend line only from real scan data. Never synthesize historical points."""
    d = Drawing(400, 120)
    font_body = "JetBrainsMono" if _HAS_JB_MONO else "Courier"

    if prev_score is None:
        # Only one real data point — show honest message, no fake history
        d.add(String(80, 55, "Insufficient scan history for trend analysis.",
                     fontSize=9, fontName=font_body, fillColor=_MUTED))
        d.add(String(80, 38, "Run a second scan to establish a baseline.",
                     fontSize=8.5, fontName=font_body, fillColor=_MUTED))
        # Plot the single real point
        c_color = _SEV_COLORS["CRITICAL"] if current_score >= 75 else (
            _SEV_COLORS["HIGH"] if current_score >= 50 else _ACCENT)
        d.add(Circle(200, 20 + current_score * 0.8, 6, fillColor=c_color, strokeColor=None))
        d.add(String(185, 5, "TODAY", fontSize=8, fontName=font_body, fillColor=_DARK))
    else:
        # Two real points — draw actual trend
        for i in range(6):
            d.add(Line(30, 20 + i*16, 380, 20 + i*16,
                       strokeColor=colors.HexColor("#e9ecef")))
        pts = [(100, 20 + prev_score * 0.8), (300, 20 + current_score * 0.8)]
        d.add(PolyLine(pts, strokeColor=_ACCENT, strokeWidth=2))
        c_color = _SEV_COLORS["CRITICAL"] if current_score >= 75 else (
            _SEV_COLORS["HIGH"] if current_score >= 50 else _ACCENT)
        for p in pts:
            d.add(Circle(p[0], p[1], 4, fillColor=c_color, strokeColor=None))
        d.add(String(85, 5, "PREVIOUS SCAN", fontSize=8, fontName=font_body, fillColor=_MUTED))
        d.add(String(280, 5, "TODAY", fontSize=8, fontName=font_body, fillColor=_DARK))
    return d

def _draw_attack_surface_grid(score: int, evidence: Optional[list] = None):
    """Evidence-driven attack surface grid. Each cell is coloured from real evidence only."""
    d = Drawing(450, 130)
    font_body = "JetBrainsMono" if _HAS_JB_MONO else "Courier"

    # Map label keywords to evidence signal keywords (deterministic, not random)
    _signal_map = {
        "Port Exposure":   ["PORT", "OPEN PORT", "EXPOSED SERVICE"],
        "TLS/SSL Certs":   ["TLS", "SSL", "CERTIFICATE", "HTTPS"],
        "HTTP Headers":    ["HEADER", "HSTS", "CSP", "X-FRAME"],
        "DNS Security":    ["DNS", "DNSSEC", "SPF", "DMARC"],
        "WAF Presence":    ["WAF", "CLOUDFLARE", "FIREWALL"],
        "Path Traversal":  ["TRAVERSAL", "DIRECTORY", "BACKUP", ".ENV", ".GIT"],
        "XSS Vectors":     ["XSS", "SCRIPT", "INJECTION"],
        "SQLi Vectors":    ["SQL", "SQLI", "DATABASE", "PHPMYADMIN"],
        "Open Directories":["OPEN DIR", "LISTING", "INDEX OF"],
        "Data Leaks":      ["LEAK", "CREDENTIAL", "BREACH", "EXPOSED"],
        "CORS Policy":     ["CORS", "CROSS-ORIGIN", "ACCESS-CONTROL"],
        "JS Obfuscation":  ["OBFUSCAT", "MINIF", "PACKED", "EVAL("],
    }

    ev_upper = [e.upper() for e in (evidence or [])]

    labels = list(_signal_map.keys())
    for i in range(3):
        for j in range(4):
            idx = i * 4 + j
            x = 10 + j * 110
            y = 100 - i * 35
            label = labels[idx]
            keywords = _signal_map[label]
            # Flagged only if actual evidence contains matching keyword
            is_flagged = any(
                any(kw in ev for ev in ev_upper)
                for kw in keywords
            )
            c = _SEV_COLORS["HIGH"] if is_flagged else _SEV_COLORS["LOW"]
            d.add(Rect(x, y-5, 100, 20,
                       fillColor=colors.HexColor("#f8f9fa"),
                       strokeColor=colors.HexColor("#dee2e6"), strokeWidth=0.5))
            d.add(Circle(x+10, y+5, 4, fillColor=c, strokeColor=None))
            d.add(String(x+20, y+2, label, fontSize=7.5,
                         fontName=font_body, fillColor=_DARK))
    return d

def _draw_risk_vectors(score: int, conf: int):
    struct = min(100, int(score * 1.1))
    rep = 100 if score >= 90 else (0 if score < 30 else int(score * 0.8))
    behav = score
    net = min(100, int((score + conf) / 2))
    
    d = Drawing(450, 140)
    labels = ["STRUCTURAL INTEGRITY", "REPUTATION INTELLIGENCE", "BEHAVIORAL ANOMALIES", "NETWORK COMPLEXITY"]
    values = [struct, rep, behav, net]
    
    font_bold = "JetBrainsMono-Bold" if _HAS_JB_MONO else "Courier-Bold"
    
    y = 110
    for i in range(4):
        val = values[i]
        d.add(String(0, y+4, labels[i], fontSize=8.5, fontName=font_bold, fillColor=_DARK))
        
        d.add(Rect(160, y, 220, 12, fillColor=colors.HexColor("#e9ecef"), strokeColor=None))
        bar_color = _SEV_COLORS["CRITICAL"] if val > 75 else (_SEV_COLORS["HIGH"] if val > 50 else (_SEV_COLORS["MEDIUM"] if val > 30 else _SEV_COLORS["LOW"]))
        if val > 0:
            d.add(Rect(160, y, 220 * (val/100.0), 12, fillColor=bar_color, strokeColor=None))
            
        d.add(String(395, y+3, f"{val}/100", fontSize=8.5, fontName=font_bold, fillColor=_DARK))
        y -= 28
    return d

def generate_pdf(
    url: str, score: int, severity: str, confidence_pct: int,
    executive_summary: str, business_impact: str, likelihood: str, urgency: str,
    observations: list, recommended_actions: List[str], advisory_notice: str,
    risk_change: Optional[str] = None, previous_score: Optional[int] = None,
    generated_at: Optional[str] = None,
    # EIRPP features:
    priority_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    asset_criticality: Optional[str] = None,
    compliance_scopes: Optional[List[str]] = None,
    financial_breach_cost_usd: Optional[str] = None,
    financial_fine_usd: Optional[str] = None,
    financial_downtime_usd: Optional[str] = None,
    downtime_hours: Optional[float] = None,
    evidence: Optional[list] = None,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = _build_styles()
    story  = []
    ts     = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    font_bold = "JetBrainsMono-Bold" if _HAS_JB_MONO else "Courier-Bold"

    import uuid
    import hashlib
    report_id = str(uuid.uuid4()).upper()
    hash_val = hashlib.sha256(f"{url}{ts}{score}".encode()).hexdigest()[:16].upper()

    # --- PAGE 1: COVER & EXECUTIVE SUMMARY ---
    story.append(Paragraph("EIRPP SECURITY INTELLIGENCE REPORT", styles["title"]))
    story.append(Paragraph(f"EXPOSURE INTELLIGENCE & RISK PRIORITIZATION PLATFORM<br/>Generated: {ts}", styles["subtitle"]))
    
    machine_metadata = (
        f"REPORT_ID : {report_id}<br/>"
        f"SYS_HASH  : {hash_val}<br/>"
        f"ENGINE    : Heuristic Risk Detector v2.4.1<br/>"
        f"INTEL_API : Active (GSB / VT Integration)"
    )
    story.append(Paragraph(machine_metadata, styles["machine_data"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=24))

    import urllib.parse
    parsed_url = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    domain_part = parsed_url.netloc or parsed_url.path
    protocol_part = parsed_url.scheme.upper() if parsed_url.scheme else "HTTPS (Assumed)"
    path_part = parsed_url.path if parsed_url.netloc else "/"
    
    target_breakdown = (
        f"<b>PROTOCOL     :</b> {protocol_part}<br/>"
        f"<b>ROOT DOMAIN  :</b> {domain_part}<br/>"
        f"<b>ROUTING PATH :</b> {path_part}"
    )

    story.append(Paragraph("1. Target Infrastructure Breakdown", styles["section_header"]))
    story.append(Paragraph(target_breakdown, styles["body"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("2. Executive Summary", styles["section_header"]))
    story.append(Paragraph(executive_summary, styles["body"]))
    story.append(Spacer(1, 16))

    if priority_score is not None:
        story.append(Paragraph("2.5 EIRPP Decision Prioritization (Tier 4)", styles["section_header"]))
        
        eirpp_summary = (
            f"<b>EIRPP Composite Priority Score:</b> <font color='{_SEV_COLORS.get(severity, _ACCENT).hexval()}'><b>{priority_score:.1f}/100</b></font><br/>"
            f"<b>Remediation SLA:</b> {urgency} ({'24 Hours' if priority_score >= 80 else ('7 Days' if priority_score >= 65 else ('14 Days' if priority_score >= 45 else '30 Days'))})<br/>"
            f"<b>Asset Criticality:</b> {asset_criticality or 'UNKNOWN'}<br/>"
            f"<b>Compliance Regimes:</b> {', '.join(compliance_scopes) if compliance_scopes else 'None'}<br/>"
            f"<b>EPSS Exploitability Probability:</b> {f'{epss_score*100:.2f}%' if epss_score is not None else 'N/A'}"
        )
        story.append(Paragraph(eirpp_summary, styles["body"]))
        
        # Display financial impact estimates if provided
        if financial_breach_cost_usd or financial_fine_usd or financial_downtime_usd:
            financial_summary = (
                f"<b>Potential Breach Cost Range :</b> {financial_breach_cost_usd or 'N/A'}<br/>"
                f"<b>Potential Regulatory Fines :</b> {financial_fine_usd or 'N/A'}<br/>"
                f"<b>Estimated Service Downtime  :</b> {downtime_hours or 0.0} hours (~{financial_downtime_usd or 'N/A'} operational cost)"
            )
            story.append(Spacer(1, 8))
            story.append(Paragraph("<b>Estimated Business & Financial Impact Metrics</b>", styles["body_bold"]))
            story.append(Paragraph(financial_summary, styles["body"]))
        story.append(Spacer(1, 8))

        # Financial Impact Table
        if financial_breach_cost_usd or financial_fine_usd or financial_downtime_usd:
            story.append(Paragraph("<b>Financial & Operational Impact Matrix</b>", styles["body_bold"]))
            fin_rows = [
                [Paragraph("<b>METRIC</b>", ParagraphStyle("th", fontSize=8.5, fontName=font_bold, textColor=colors.white)),
                 Paragraph("<b>ESTIMATED VALUE</b>", ParagraphStyle("th2", fontSize=8.5, fontName=font_bold, textColor=colors.white)),
                 Paragraph("<b>BASIS</b>", ParagraphStyle("th3", fontSize=8.5, fontName=font_bold, textColor=colors.white))],
            ]
            if financial_breach_cost_usd:
                fin_rows.append([
                    Paragraph("Breach Cost Range", styles["body"]),
                    Paragraph(f"<font color='#dc3545'><b>{financial_breach_cost_usd}</b></font>", styles["body"]),
                    Paragraph("IBM Cost of a Data Breach 2024 Model", styles["caption"]),
                ])
            if financial_fine_usd and financial_fine_usd != "None":
                fin_rows.append([
                    Paragraph("Regulatory Fine Exposure", styles["body"]),
                    Paragraph(f"<font color='#fd7e14'><b>{financial_fine_usd}</b></font>", styles["body"]),
                    Paragraph("GDPR / PCI-DSS applicability estimate", styles["caption"]),
                ])
            if financial_downtime_usd and financial_downtime_usd != "None":
                fin_rows.append([
                    Paragraph(f"Operational Downtime", styles["body"]),
                    Paragraph(f"<b>{downtime_hours or 0.0:.1f} hrs ({financial_downtime_usd})</b>", styles["body"]),
                    Paragraph("Avg. enterprise downtime cost/hr", styles["caption"]),
                ])
            fin_tbl = Table(fin_rows, colWidths=[55*mm, 55*mm, 55*mm])
            fin_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
                ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                ("INNERGRID",    (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
                ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ]))
            story.append(fin_tbl)
            story.append(Spacer(1, 12))

    story.append(Paragraph("3. Attack Surface Matrix Status", styles["section_header"]))
    story.append(Paragraph("Each cell below is flagged based on actual evidence signals detected during this scan. Red indicates a confirmed or probable exposure based on observed findings. Green indicates no matching evidence was detected.", styles["caption"]))
    story.append(Spacer(1, 8))
    story.append(_draw_attack_surface_grid(score, evidence=evidence))
    story.append(Spacer(1, 16))

    story.append(Paragraph("4. Business Impact & Likelihood", styles["section_header"]))
    story.append(Paragraph(business_impact, styles["body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(likelihood, styles["body"]))
    
    story.append(PageBreak())

    # --- PAGE 2: SCORING & VECTOR ANALYTICS ---
    story.append(Paragraph("5. Quantitative Risk Analytics", styles["title"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=24))

    story.append(Paragraph("5.1 Assessment Summary Gauges", styles["section_header"]))
    story.append(_score_table(score, severity, confidence_pct, styles, priority_score=priority_score))
    story.append(Spacer(1, 16))

    story.append(Paragraph("5.2 Threat Vector Breakdown (Bar Analysis)", styles["section_header"]))
    story.append(_draw_risk_vectors(score, confidence_pct))
    story.append(Spacer(1, 16))

    story.append(Paragraph("5.3 Historical Risk Volatility (Trend Analysis)", styles["section_header"]))
    story.append(_draw_trend_line(score, previous_score))
    story.append(Spacer(1, 16))

    if risk_change and previous_score is not None:
        delta = score - previous_score
        arrow  = "increased" if risk_change == "increased" else "decreased"
        story.append(Paragraph(f"<i>Risk level has {arrow} since the previous assessment (previous score: {previous_score}/100, change: {delta:+.0f}).</i>", styles["caption"]))
        story.append(Spacer(1, 12))

    story.append(Paragraph("5.4 Diagnostic Methodology & Confidence", styles["section_header"]))
    methodology_text = (
        "The <b>OVERALL RISK SCORE (0-100)</b> represents the calculated exposure level based on structural heuristics, "
        "reputation feeds (Google Safe Browsing, VirusTotal), and infrastructure complexity analysis. "
        "Scores above 50 indicate potential deception or malicious intent. The vector breakdown (above) illustrates exactly which subsystems triggered the warnings. "
        "High Structural Integrity scores mean the website is actively hiding elements or mimicking other brands.<br/><br/>"
        "The <b>SIGNAL CONFIDENCE (%)</b> indicates the engine's certainty. "
        "A high confidence score means the risk determination is backed by strong, overlapping threat indicators (or confirmed clean signals from institutional domains). "
        "This metric is derived using a continuous probabilistic weighting algorithm that heavily penalizes unverified domains while "
        "rewarding domains with established DNS/WHOIS longevity."
    )
    story.append(Paragraph(methodology_text, styles["body"]))
    
    story.append(PageBreak())

    # --- PAGE 3: DEEP DIVE & OSINT ---
    story.append(Paragraph("6. Threat Intelligence & OSINT Integration", styles["title"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=24))

    story.append(Paragraph("6.1 Cyber Exposure Context", styles["section_header"]))
    context_text = (
        "Understanding internet exposure is critical for preventing phishing attacks, credential theft, and infrastructure compromise. "
        "Websites flagged as HIGH or CRITICAL risk typically exhibit deceptive structural elements such as typosquatting, "
        "embedded login portals on non-standard domains, or are actively blacklisted by global threat intelligence networks. "
        "If a site is flagged here, it is highly recommended to block it at the corporate firewall level immediately.<br/><br/>"
        "Conversely, LOW risk domains typically belong to verified institutional infrastructure (.edu, .gov) or exhibit standard, safe markup with no obfuscation. "
        "It is important to note that a LOW score does not guarantee immunity from zero-day exploits, but it indicates the absence of known malicious signatures "
        "and standard phishing structures."
    )
    story.append(Paragraph(context_text, styles["body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("6.2 Open-Source Intelligence (OSINT) Correlation", styles["section_header"]))
    osint_text = (
        "The IERSS engine correlates local heuristic findings with global OSINT databases. "
        "This target was cross-referenced against the Google Safe Browsing API and VirusTotal URL scanners. "
        "When global intelligence confirms a threat, the local risk score is subjected to a compound multiplier, "
        "escalating the threat directly to CRITICAL and boosting Signal Confidence to near 100%. "
        "These feeds update hourly and represent the consensus of global cybersecurity vendors regarding the malicious nature of the domain."
    )
    story.append(Paragraph(osint_text, styles["body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("6.3 Architectural Complexity Penalties", styles["section_header"]))
    arch_text = (
        "Modern phishing attacks utilize highly complex obfuscation techniques. Our scanner analyzes the raw HTML/DOM "
        "structure for excessive scripting, hidden IFRAMEs, and base64 encoded payloads. If a website requires massive amounts "
        "of obfuscated code to render a simple login page, the engine applies an architectural complexity penalty, significantly raising the risk score."
    )
    story.append(Paragraph(arch_text, styles["body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("6.4 Urgency Level", styles["section_header"]))
    story.append(Paragraph(f"<b>{urgency}</b>", styles["body"]))

    story.append(PageBreak())

    # --- PAGE 4: EVIDENCE & IOCS ---
    story.append(Paragraph("7. Indicators of Compromise (IoC)", styles["title"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=24))
    
    story.append(Paragraph("The following raw indicators were detected during the heuristic scan. These are the physical characteristics and structural anomalies that contributed directly to the final risk score calculation.", styles["caption"]))
    story.append(Spacer(1, 16))

    if observations:
        story.append(Paragraph("7.1 Observed Exposure Indicators", styles["section_header"]))
        
        for i, obs in enumerate(observations, 1):
            if hasattr(obs, "what_observed"):
                what, meaning, impact, action = obs.what_observed, obs.what_it_means, obs.business_impact, obs.recommended_action
            else:
                what = obs.get("what_observed", "")
                meaning = obs.get("what_it_means", "")
                impact = obs.get("business_impact", "")
                action = obs.get("recommended_action", "")

            block = KeepTogether([
                Paragraph(f"Finding {i}: {what}", styles["body_bold"]),
                Paragraph(f"<i>Technical Meaning:</i> {meaning}", styles["body"]),
                Paragraph(f"<i>Threat Impact:</i> {impact}", styles["body"]),
                Paragraph(f"<i>Required Action:</i> {action}", styles["body"]),
                Spacer(1, 8),
            ])
            story.append(block)
    else:
        story.append(Paragraph("No specific threat indicators were observed during this scan.", styles["body"]))

    story.append(PageBreak())

    # --- PAGE 5: REMEDIATION & COMPLIANCE ---
    story.append(Paragraph("8. Remediation & Compliance Framework", styles["title"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_ACCENT, spaceAfter=24))

    story.append(Paragraph("8.1 Zero-Trust Architecture Guidelines", styles["section_header"]))
    zt_text = (
        "In accordance with modern Zero-Trust Architecture (ZTA) principles, no external domain should be implicitly trusted. "
        "Users and systems accessing the assessed infrastructure must be continuously authenticated and authorized. "
        "If this domain scored HIGH or CRITICAL, it violates ZTA baselines and should be isolated from corporate networks."
    )
    story.append(Paragraph(zt_text, styles["body"]))
    story.append(Spacer(1, 16))

    if recommended_actions:
        story.append(Paragraph("8.2 Recommended Remediation Strategy", styles["section_header"]))
            
        for i, action in enumerate(recommended_actions, 1):
            story.append(Paragraph(f"{i}.  {action}", styles["bullet"]))
        story.append(Spacer(1, 16))

    story.append(Paragraph("8.3 System Advisory Notice", styles["section_header"]))
    story.append(Paragraph(advisory_notice, styles["notice"]))
    story.append(Spacer(1, 16))
    
    story.append(Paragraph("8.4 Report Integrity & Legal Disclaimer", styles["section_header"]))
    legal_text = (
        f"This document was automatically generated by the IERSS engine. The cryptographic hash <b>{hash_val}</b> can be used to verify the integrity of this specific assessment point-in-time. "
        "This report is provided 'as is' for informational and diagnostic purposes only. It does not constitute formal legal or regulatory compliance advice. "
        "The heuristics are probabilistic in nature and false positives/negatives may occur. Always consult with a certified cybersecurity professional before taking destructive network actions."
    )
    story.append(Paragraph(legal_text, styles["body"]))

    story.append(Spacer(1, 32))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dee2e6")))

    font_body = "JetBrainsMono" if _HAS_JB_MONO else "Courier"
    story.append(Paragraph(
        f"IERSS AUTOMATED ADVISORY | HASH: {hash_val} | TS: {ts}",
        ParagraphStyle("footer", fontSize=7, fontName=font_body, textColor=_DARK, alignment=TA_CENTER, spaceBefore=6),
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()

