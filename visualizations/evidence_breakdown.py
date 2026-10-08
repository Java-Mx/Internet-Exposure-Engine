"""
AERIS Evidence Breakdown Visualization
========================================
Renders evidence tier contribution breakdown from ACTUAL evidence chain counts.

CONSTITUTION REQUIREMENT:
  - Tier contribution percentages must be derived from real EvidenceChain item counts.
  - BANNED: `tier_weight = score * 0.28` or any other constant-multiplier approach.
  - DataProvenance is MANDATORY.
"""
from __future__ import annotations

import html as _html
from typing import List, Any, Optional
from visualizations.provenance import DataProvenance, provenance_footer_html, empty_state_html


def render_evidence_breakdown(
    evidence_items: List[Any],
    provenance: DataProvenance,
) -> str:
    """
    Render evidence tier contribution breakdown from real EvidenceChain items.

    Args:
        evidence_items:  List of EvidenceItem objects with .tier attribute
                         from EvidenceChain.items
        provenance:      DataProvenance object (MANDATORY)

    Returns:
        HTML string showing real tier distribution, or empty state.
    """
    prov_footer = provenance_footer_html(provenance)

    if not evidence_items:
        empty = empty_state_html(
            title="No Evidence Items",
            reason="Run an assessment to populate the evidence breakdown.",
            icon="◻",
        )
        return (
            f'<div class="ep" style="border-left:3px solid #6c757d;">'
            f'<div class="ep-hdr"><span class="ep-title" style="color:#a0a0a0;">'
            f'Evidence Tier Breakdown</span></div>'
            f'<div class="ep-body">{empty}{prov_footer}</div>'
            f'</div>'
        )

    # Count items per tier from actual EvidenceChain items
    tier_counts: dict = {}
    for item in evidence_items:
        tier = getattr(item, "tier", 0)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    total = max(len(evidence_items), 1)

    # Build tier display rows
    tier_config = {
        1: {"label": "Tier 1: Structural Heuristics", "color": "#dc3545"},
        2: {"label": "Tier 2: ML Ensemble", "color": "#fd7e14"},
        3: {"label": "Tier 3: Behavioral Anomaly", "color": "#ffc107"},
        4: {"label": "Tier 4: Graph & Feed Correlation", "color": "#0dcaf0"},
        0: {"label": "Unclassified", "color": "#6c757d"},
    }

    rows_html = []
    # Sort tiers: known tiers first, then unclassified
    sorted_tiers = sorted(tier_counts.keys(), key=lambda t: (t == 0, t))

    for tier in sorted_tiers:
        count = tier_counts[tier]
        pct = (count / total) * 100
        cfg = tier_config.get(tier, {"label": f"Tier {tier}", "color": "#6c757d"})
        color = cfg["color"]
        label = cfg["label"]

        rows_html.append(
            f'<div style="margin-bottom:10px;">'
            f'<div style="display:flex;justify-content:space-between;'
            f'font-size:0.72rem;margin-bottom:4px;">'
            f'<span style="font-weight:600;opacity:0.85;">{_html.escape(label)}</span>'
            f'<span style="font-weight:700;color:{color};">{count} items ({pct:.0f}%)</span>'
            f'</div>'
            f'<div style="height:5px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;">'
            f'<div style="height:100%;width:{pct:.1f}%;background:{color};'
            f'box-shadow:0 0 4px {color}60;border-radius:3px;"></div>'
            f'</div>'
            f'</div>'
        )

    return (
        f'<div class="ep" style="border-left:3px solid #20c997;">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,rgba(32,201,151,0.08) 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:#20c997;"></div>'
        f'<span class="ep-title" style="color:#20c997;">Evidence Tier Breakdown</span>'
        f'<span class="ep-tag">{total} Evidence Items</span>'
        f'</div>'
        f'<div class="ep-body">'
        f'<div style="font-size:0.68rem;opacity:0.55;margin-bottom:12px;">Real tier distribution '
        f'computed from {total} EvidenceChain items. Percentages reflect actual evidence '
        f'composition, not score-derived estimates.</div>'
        f'{"".join(rows_html)}'
        f'{prov_footer}'
        f'</div>'
        f'</div>'
    )
