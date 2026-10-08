"""
AERIS Qualitative Business Impact Framework
=============================================
Replaces the hardcoded financial dollar-amount lookup table with a structured,
evidence-backed qualitative business impact assessment.

AUDIT FINDING CORRECTED:
  - BEFORE: "$450,000 – $4,200,000 USD" derived from a Python dict keyed on
    the word "CRITICAL". No methodology. No citation. Pure fabrication.
  - AFTER: Structured qualitative categories with transparent reasoning,
    derived from actual evidence (compliance scopes, criticality, severity,
    evidence flags) — no invented dollar figures.

CONSTITUTION REQUIREMENT:
  - No financial dollar amounts fabricated from lookup tables.
  - Business impact must be traceable to evidence.
  - Qualitative categories are honest; quantitative models require real data.
"""
from __future__ import annotations

import html as _html
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class QualitativeBusinessImpact:
    """
    Evidence-backed qualitative business impact assessment.
    Replaces fabricated financial ranges.
    """
    blast_radius: str           # "External-Facing" / "Internal" / "Regulatory-Scope"
    operational_impact: str     # e.g. "HIGH", "MEDIUM", "LOW"
    compliance_risk: List[str]  # List of triggered compliance frameworks
    stakeholder_scope: str      # e.g. "Customer-Facing", "Internal Only"
    sla_urgency: str            # From PrioritizationEngine
    rationale: str              # Plain-language explanation of impact
    data_sources: List[str]     # What evidence drove this assessment
    confidence: float           # 0.0 – 1.0

    @property
    def operational_impact_color(self) -> str:
        return {
            "HIGH": "#dc3545",
            "MEDIUM": "#fd7e14",
            "LOW": "#198754",
            "CRITICAL": "#7b0d1e",
        }.get(self.operational_impact, "#6c757d")


def compute_qualitative_impact(
    severity: str,
    asset_criticality: str,
    is_customer_facing: bool,
    compliance_scopes: List[str],
    evidence: List[str],
    sla_days: int,
    priority_urgency: str,
) -> QualitativeBusinessImpact:
    """
    Compute qualitative business impact from actual assessment inputs.
    All fields are derived from real evidence and configuration — not lookup tables.

    Args:
        severity:           Risk severity from heuristic/ML pipeline (LOW/MEDIUM/HIGH/CRITICAL)
        asset_criticality:  Analyst-provided asset criticality (LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN)
        is_customer_facing: Whether the asset is directly customer-facing
        compliance_scopes:  List of applicable compliance frameworks (e.g. ["PCI-DSS", "GDPR"])
        evidence:           Raw evidence strings from assessment
        sla_days:           SLA remediation window from PrioritizationEngine
        priority_urgency:   Urgency label from PrioritizationEngine

    Returns:
        QualitativeBusinessImpact with evidence-backed qualitative assessment.
    """
    # Determine blast radius from evidence + config
    if is_customer_facing:
        blast_radius = "External / Customer-Facing"
    elif compliance_scopes:
        blast_radius = "Regulatory Scope"
    else:
        blast_radius = "Internal / Perimeter"

    # Map effective operational impact
    severity_upper = severity.upper()
    criticality_upper = asset_criticality.upper() if asset_criticality else "UNKNOWN"

    # Take the higher of severity and criticality
    _level_order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    sev_val = _level_order.get(severity_upper, 0)
    crit_val = _level_order.get(criticality_upper, 0)
    effective_level = severity_upper if sev_val >= crit_val else criticality_upper
    if effective_level == "UNKNOWN":
        effective_level = severity_upper

    # Stakeholder scope
    stakeholder_scope = (
        "Customer-Facing (External Users Exposed)"
        if is_customer_facing
        else "Internal (Employee/System Access)"
    )

    # Compliance risk from actual scope list
    compliance_risk = list(compliance_scopes) if compliance_scopes else ["None declared"]

    # Build data source list honestly
    data_sources = [
        f"Asset Criticality: {criticality_upper} (analyst-provided)",
        f"Risk Severity: {severity_upper} (pipeline-computed)",
        f"Customer-Facing: {'Yes' if is_customer_facing else 'No'} (analyst-provided)",
    ]
    if compliance_scopes:
        data_sources.append(f"Compliance: {', '.join(compliance_scopes)} (analyst-provided)")
    if any("VIRUSTOTAL" in e.upper() for e in evidence):
        data_sources.append("VirusTotal: Threat feed response included")
    if any("GOOGLE SAFE BROWSING" in e.upper() for e in evidence):
        data_sources.append("Google Safe Browsing: Threat feed response included")
    if any("TYPOSQUATTING" in e.upper() for e in evidence):
        data_sources.append("Typosquatting pattern detected in structural analysis")

    # SLA urgency label
    if sla_days <= 1:
        sla_urgency = "IMMEDIATE — Remediate within 24 hours"
    elif sla_days <= 7:
        sla_urgency = f"URGENT — Remediate within {sla_days} days"
    else:
        sla_urgency = f"SCHEDULED — Remediate within {sla_days} days"

    # Build rationale from actual inputs
    rationale_parts = [
        f"This asset is classified as {criticality_upper} criticality",
        f"with {severity_upper} risk severity.",
    ]
    if is_customer_facing:
        rationale_parts.append(
            "As a customer-facing asset, exposure directly affects end-user trust and may trigger "
            "notification obligations under applicable privacy regulations."
        )
    if compliance_scopes:
        rationale_parts.append(
            f"The following compliance frameworks are in scope: {', '.join(compliance_scopes)}. "
            "A confirmed exposure may require regulatory notification within defined timeframes."
        )
    if any("TYPOSQUATTING" in e.upper() for e in evidence):
        rationale_parts.append(
            "Typosquatting indicators suggest active brand exploitation risk, "
            "which increases likelihood of credential harvesting or reputational damage."
        )
    rationale_parts.append(
        f"Remediation priority is {priority_urgency.upper()} with a {sla_days}-day SLA target."
    )

    rationale = " ".join(rationale_parts)

    # Confidence: high when we have real compliance/criticality data
    conf = 0.5
    if criticality_upper not in ("UNKNOWN", ""):
        conf += 0.15
    if compliance_scopes:
        conf += 0.15
    if any("VIRUSTOTAL" in e.upper() or "GOOGLE SAFE BROWSING" in e.upper() for e in evidence):
        conf += 0.20
    conf = min(conf, 1.0)

    return QualitativeBusinessImpact(
        blast_radius=blast_radius,
        operational_impact=effective_level,
        compliance_risk=compliance_risk,
        stakeholder_scope=stakeholder_scope,
        sla_urgency=sla_urgency,
        rationale=rationale,
        data_sources=data_sources,
        confidence=conf,
    )


def render_business_impact_panel(
    impact: QualitativeBusinessImpact,
) -> str:
    """
    Render the qualitative business impact panel.
    No dollar amounts. No fabricated figures.
    """
    color = impact.operational_impact_color
    compliance_items = "".join(
        f'<span style="display:inline-block;margin:2px 4px 2px 0;padding:2px 8px;'
        f'background:{color}18;border:1px solid {color}40;border-radius:3px;'
        f'font-size:0.62rem;font-weight:700;color:{color};">{_html.escape(c)}</span>'
        for c in impact.compliance_risk
    )
    sources_html = "".join(
        f'<div style="font-size:0.62rem;opacity:0.5;padding:2px 0;">'
        f'→ {_html.escape(s)}</div>'
        for s in impact.data_sources
    )

    return (
        f'<div class="ep" style="border-left:3px solid {color};">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,{color}12 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:{color};"></div>'
        f'<span class="ep-title" style="color:{color};">Business Impact Intelligence</span>'
        f'<span class="ep-tag">Evidence-Backed</span>'
        f'</div>'
        f'<div class="ep-body">'
        # Operational impact + blast radius
        f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">'
        f'<div>'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:4px;">Operational Impact</div>'
        f'<div style="font-size:1.5rem;font-weight:800;color:{color};line-height:1;">{_html.escape(impact.operational_impact)}</div>'
        f'</div>'
        f'<div>'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:4px;">Blast Radius</div>'
        f'<div style="font-size:0.82rem;font-weight:700;line-height:1.3;">{_html.escape(impact.blast_radius)}</div>'
        f'</div>'
        f'</div>'
        # Stakeholder scope + SLA
        f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">'
        f'<div>'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:4px;">Stakeholder Scope</div>'
        f'<div style="font-size:0.78rem;font-weight:600;opacity:0.85;">{_html.escape(impact.stakeholder_scope)}</div>'
        f'</div>'
        f'<div>'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:4px;">Remediation SLA</div>'
        f'<div style="font-size:0.78rem;font-weight:700;color:{color};">{_html.escape(impact.sla_urgency)}</div>'
        f'</div>'
        f'</div>'
        # Compliance risk
        f'<div style="margin-bottom:12px;">'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:6px;">Compliance Risk Scope</div>'
        f'{compliance_items}'
        f'</div>'
        # Rationale
        f'<div style="background:rgba(0,0,0,0.14);border:1px solid rgba(255,255,255,0.05);'
        f'border-radius:5px;padding:10px 12px;margin-bottom:10px;">'
        f'<div style="font-size:0.57rem;text-transform:uppercase;letter-spacing:0.10em;opacity:0.40;margin-bottom:5px;">Impact Rationale</div>'
        f'<div style="font-size:0.75rem;line-height:1.6;opacity:0.85;">{_html.escape(impact.rationale)}</div>'
        f'</div>'
        # Data sources (transparency)
        f'<details style="margin-top:8px;">'
        f'<summary style="font-size:0.60rem;opacity:0.40;cursor:pointer;letter-spacing:0.06em;'
        f'text-transform:uppercase;">▶ Data Sources ({len(impact.data_sources)})</summary>'
        f'<div style="margin-top:6px;">{sources_html}</div>'
        f'</details>'
        f'</div>'
        f'</div>'
    )
