"""
AERIS Data Provenance Contract
================================
Every visualization function MUST accept a DataProvenance object and render
a provenance footer. No graph or chart may render without declared data provenance.

This enforces Principle 4: Every Visualization Must Originate from Actual Evidence.

Usage:
    from visualizations.provenance import DataProvenance, provenance_footer_html

    prov = DataProvenance(
        source="threat_memory.recall()",
        dataset="aeris_scan_history",
        query="SELECT * FROM scans WHERE domain=?",
        confidence=0.82,
        record_count=7,
    )
    html = render_my_chart(data, provenance=prov)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import html as _html


@dataclass
class DataProvenance:
    """
    Declares the origin of data used in an AERIS visualization.

    Required for every visualization function. If no real data exists,
    pass DataProvenance.empty() and render an empty state instead of
    fabricated content.
    """
    source: str          # Module/function that produced this data (e.g. "threat_memory.recall()")
    dataset: str         # Logical dataset name (e.g. "aeris_scan_history")
    query: str           # Actual query or lookup performed (e.g. "SELECT FROM scans WHERE domain=X")
    confidence: float    # Data reliability 0.0–1.0
    record_count: int = 0
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    notes: str = ""      # Optional analyst notes about data limitations

    @classmethod
    def empty(cls, reason: str = "No data available") -> "DataProvenance":
        """Return a DataProvenance indicating no real data was found."""
        return cls(
            source="none",
            dataset="empty",
            query=reason,
            confidence=0.0,
            record_count=0,
        )

    @property
    def is_empty(self) -> bool:
        return self.source == "none" or self.record_count == 0

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.8:
            return "HIGH"
        elif self.confidence >= 0.5:
            return "MEDIUM"
        elif self.confidence > 0.0:
            return "LOW"
        return "NONE"

    @property
    def confidence_color(self) -> str:
        return {
            "HIGH": "#198754",
            "MEDIUM": "#fd7e14",
            "LOW": "#dc3545",
            "NONE": "#6c757d",
        }.get(self.confidence_label, "#6c757d")


def provenance_footer_html(prov: DataProvenance) -> str:
    """
    Render a standardized data provenance footer for any AERIS visualization.
    Must be included in every graph and chart rendered in the Intelligence Workspace.
    """
    conf_color = prov.confidence_color
    conf_label = prov.confidence_label
    src = _html.escape(prov.source)
    ds = _html.escape(prov.dataset)
    q = _html.escape(prov.query[:120] + ("..." if len(prov.query) > 120 else ""))
    updated = _html.escape(prov.last_updated[:19])  # truncate to seconds
    notes_html = (
        f'<div style="font-size:0.58rem;opacity:0.4;margin-top:3px;">'
        f'Note: {_html.escape(prov.notes)}</div>'
    ) if prov.notes else ""

    return (
        f'<div style="margin-top:10px;padding:7px 10px;background:rgba(0,0,0,0.18);'
        f'border:1px solid rgba(255,255,255,0.05);border-radius:4px;">'
        f'<div style="font-size:0.52rem;font-weight:800;letter-spacing:0.12em;'
        f'text-transform:uppercase;opacity:0.35;margin-bottom:5px;">Data Provenance</div>'
        f'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px 14px;font-size:0.60rem;">'
        f'<div><span style="opacity:0.4;">SOURCE:</span> <span style="opacity:0.75;">{src}</span></div>'
        f'<div><span style="opacity:0.4;">DATASET:</span> <span style="opacity:0.75;">{ds}</span></div>'
        f'<div><span style="opacity:0.4;">RECORDS:</span> <span style="opacity:0.75;">{prov.record_count}</span></div>'
        f'<div style="grid-column:1/-1;margin-top:2px;">'
        f'<span style="opacity:0.4;">QUERY:</span> '
        f'<span style="opacity:0.65;font-family:monospace;">{q}</span>'
        f'</div>'
        f'<div><span style="opacity:0.4;">CONFIDENCE:</span> '
        f'<span style="color:{conf_color};font-weight:700;">{conf_label} ({prov.confidence:.0%})</span></div>'
        f'<div><span style="opacity:0.4;">LAST UPDATED:</span> <span style="opacity:0.65;">{updated}</span></div>'
        f'</div>'
        f'{notes_html}'
        f'</div>'
    )


def empty_state_html(title: str, reason: str, icon: str = "◌") -> str:
    """
    Render a clean empty state for a visualization that has no real data.
    Use this instead of fabricated placeholder content.
    """
    title_esc = _html.escape(title)
    reason_esc = _html.escape(reason)
    return (
        f'<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;'
        f'min-height:160px;background:rgba(0,0,0,0.12);border:1px solid rgba(255,255,255,0.05);'
        f'border-radius:6px;padding:24px;">'
        f'<div style="font-size:2rem;opacity:0.18;margin-bottom:12px;">{_html.escape(icon)}</div>'
        f'<div style="font-size:0.78rem;font-weight:700;opacity:0.45;margin-bottom:6px;">{title_esc}</div>'
        f'<div style="font-size:0.68rem;opacity:0.30;text-align:center;max-width:300px;line-height:1.5;">'
        f'{reason_esc}'
        f'</div>'
        f'</div>'
    )
