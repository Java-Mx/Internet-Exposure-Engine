"""
AERIS Threat Memory Timeline Visualization
==========================================
Renders a temporal timeline from actual database scan records only.

CONSTITUTION REQUIREMENT:
  - Timeline events must come from real DB scan records.
  - Hardcoded "T-30 Days", "T-14 Days" placeholder events are BANNED.
  - If fewer than 2 scans exist, render empty state with honest message.
  - DataProvenance is MANDATORY.
"""
from __future__ import annotations

import html as _html
from typing import List, Dict, Any, Optional
from visualizations.provenance import DataProvenance, provenance_footer_html, empty_state_html


def render_threat_timeline(
    scan_history: List[Dict[str, Any]],
    target: str,
    provenance: DataProvenance,
) -> str:
    """
    Render a threat timeline from actual database scan records.

    Args:
        scan_history:  List of dicts with keys: scanned_at, risk_score, severity
                       Sourced from records.database.get_domain_history()
        target:        The assessed target domain
        provenance:    DataProvenance object (MANDATORY — declares DB source)

    Returns:
        HTML string of timeline, or empty state if insufficient data.
    """
    prov_footer = provenance_footer_html(provenance)

    if not scan_history or len(scan_history) < 2:
        reason = (
            "Timeline requires at least 2 historical scans for this target. "
            f"Current scan count: {len(scan_history) if scan_history else 0}. "
            "Run additional assessments to build a trend history."
        )
        empty = empty_state_html(
            title="Insufficient Scan History for Timeline",
            reason=reason,
            icon="⌛",
        )
        return (
            f'<div class="ep" style="border-left:3px solid #6c757d;">'
            f'<div class="ep-hdr" style="background:transparent;">'
            f'<div class="ep-pulse" style="background:#6c757d;"></div>'
            f'<span class="ep-title" style="color:#a0a0a0;">Threat Memory Timeline</span>'
            f'<span class="ep-tag">DB-Backed</span>'
            f'</div>'
            f'<div class="ep-body">{empty}{prov_footer}</div>'
            f'</div>'
        )

    # Build timeline entries from real data (oldest first for display)
    entries = list(reversed(scan_history[-8:]))  # last 8 scans, oldest first
    total = len(scan_history)

    sev_color = {
        "LOW": "#198754",
        "MEDIUM": "#fd7e14",
        "HIGH": "#dc3545",
        "CRITICAL": "#7b0d1e",
    }

    timeline_items = []
    for i, entry in enumerate(entries):
        ts = str(entry.get("scanned_at", "unknown"))[:16]
        score = float(entry.get("risk_score", entry.get("score", 0)))
        sev = str(entry.get("risk_level", entry.get("severity", "LOW"))).upper()
        color = sev_color.get(sev, "#6c757d")
        is_last = (i == len(entries) - 1)

        connector = (
            f'<div style="width:1px;height:100%;background:rgba(255,255,255,0.07);'
            f'margin:0 auto;margin-top:4px;"></div>'
            if not is_last else ""
        )

        timeline_items.append(
            f'<div style="display:flex;gap:12px;padding-bottom:{0 if is_last else 10}px;">'
            f'<div style="display:flex;flex-direction:column;align-items:center;min-width:14px;">'
            f'<div style="width:10px;height:10px;border-radius:50%;background:{color};'
            f'border:2px solid rgba(0,0,0,0.4);flex-shrink:0;margin-top:3px;'
            f'box-shadow:0 0 4px {color}60;"></div>'
            f'{connector}'
            f'</div>'
            f'<div style="flex:1;padding-bottom:{0 if is_last else 4}px;">'
            f'<div style="display:flex;gap:8px;align-items:center;margin-bottom:2px;">'
            f'<span style="font-size:0.62rem;opacity:0.5;font-family:monospace;">{_html.escape(ts)}</span>'
            f'<span style="font-size:0.6rem;font-weight:800;color:{color};'
            f'padding:1px 6px;background:{color}18;border-radius:3px;">{_html.escape(sev)}</span>'
            f'</div>'
            f'<div style="font-size:0.75rem;font-weight:700;color:{color};">'
            f'Risk Score: {score:.0f}/100'
            f'</div>'
            f'</div>'
            f'</div>'
        )

    # Compute trend
    scores = [float(e.get("risk_score", e.get("score", 0))) for e in scan_history[-4:]]
    if len(scores) >= 2:
        trend_delta = scores[-1] - scores[0]
        if trend_delta > 5:
            trend_label, trend_color = "RISING ↑", "#dc3545"
        elif trend_delta < -5:
            trend_label, trend_color = "FALLING ↓", "#198754"
        else:
            trend_label, trend_color = "STABLE →", "#fd7e14"
    else:
        trend_label, trend_color = "UNKNOWN", "#6c757d"

    items_html = "".join(timeline_items)

    return (
        f'<div class="ep" style="border-left:3px solid #0dcaf0;">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,rgba(13,202,240,0.08) 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:#0dcaf0;"></div>'
        f'<span class="ep-title" style="color:#0dcaf0;">Threat Memory Timeline</span>'
        f'<span class="ep-tag">{total} Scans Recorded</span>'
        f'</div>'
        f'<div class="ep-body">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:12px;">'
        f'<div style="font-size:0.68rem;opacity:0.6;">Target: '
        f'<span style="font-weight:700;">{_html.escape(target)}</span></div>'
        f'<div style="font-size:0.68rem;font-weight:800;color:{trend_color};">'
        f'Trend: {trend_label}</div>'
        f'</div>'
        f'<div style="max-height:260px;overflow-y:auto;">'
        f'{items_html}'
        f'</div>'
        f'{prov_footer}'
        f'</div>'
        f'</div>'
    )
