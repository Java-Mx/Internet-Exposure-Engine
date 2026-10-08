"""
AERIS Report Panel Component
=============================
Renders executive summaries, qualitative business impact categories,
remediation roadmaps, and regulatory compliance scopes.
"""
import streamlit as st
from utils.helpers import get_sev_color

def render_report_panel(
    biz_report: Any,
    priority_item: Any,
    severity: str,
    asset_criticality: str,
    is_customer_facing: bool,
    compliance_scopes: list,
    theme_color: str,
    theme_bg: str,
    sla_days: int
) -> None:
    """Renders the executive summary, business impact, likelihood, and action roadmaps."""
    # ── Executive Summary ─────────────────────────────────────────────
    st.markdown('<div style="height:20px;"></div>', unsafe_allow_html=True)
    with st.expander("Executive Summary", expanded=True):
        st.write(biz_report.executive_summary)

    # ── Qualitative Business Impact Scoping ───────────────────────────
    if priority_item and priority_item.impact:
        imp = priority_item.impact
        crit_str = asset_criticality.upper()
        
        # Determine qualitative impact tier instead of fake dollar values
        if crit_str == "CRITICAL" or severity == "CRITICAL":
            impact_tier = "CRITICAL BUSINESS IMPACT"
            impact_desc = "Major operational outage risk. Core revenue streams compromised. Mandated reporting required."
            impact_color = "#dc3545"
            downtime_lbl = "Critical Priority Recovery Target"
        elif crit_str == "HIGH" or severity == "HIGH":
            impact_tier = "HIGH BUSINESS IMPACT"
            impact_desc = "Broad operational disruption risk. Customer-facing downtime. Standard breach notice obligations."
            impact_color = "#dc3545"
            downtime_lbl = "High Priority Recovery Target"
        elif crit_str == "MEDIUM" or severity == "MEDIUM":
            impact_tier = "MEDIUM BUSINESS IMPACT"
            impact_desc = "Localized system disruption risk. Minor regulatory notice. Standard user notifications."
            impact_color = "#fd7e14"
            downtime_lbl = "Standard Priority Recovery Target"
        else:
            impact_tier = "LOW BUSINESS IMPACT"
            impact_desc = "Minimal potential for business disruption. No regulatory notifications required."
            impact_color = "#198754"
            downtime_lbl = "Low Priority Recovery Target"

        st.markdown(
            f'<div class="ep" style="border-left:3px solid {impact_color};margin-top:20px;">'
            f'<div class="ep-hdr" style="background:linear-gradient(90deg,rgba(220,53,69,0.14) 0%,transparent 100%);">'
            f'<div class="ep-pulse" style="background:{impact_color};"></div>'
            f'<span class="ep-title" style="color:{impact_color};">Qualitative Business Exposure Estimates</span>'
            f'<span class="ep-tag">Operational Model</span>'
            f'</div>'
            f'<div class="ep-body">'
            f'<div class="ep-stats">'
            # Left: breach cost
            f'<div class="ep-stat">'
            f'<div class="ep-lbl">Qualitative Exposure Tier</div>'
            f'<div class="ep-val" style="font-size:1.15rem;font-weight:800;color:{impact_color};margin-bottom:3px;">{impact_tier}</div>'
            f'<div style="font-size:0.66rem;opacity:0.50;">{impact_desc}</div>'
            f'</div>'
            # Right: downtime
            f'<div class="ep-stat">'
            f'<div class="ep-lbl">{downtime_lbl}</div>'
            f'<div class="ep-val" style="font-size:1.15rem;font-weight:800;color:{theme_color};margin-bottom:3px;">{imp.estimated_downtime_hours:.1f} Hours RTO</div>'
            f'<div style="font-size:0.66rem;opacity:0.50;">Estimated recovery time target based on asset criticality classification.</div>'
            f'</div>'
            f'</div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Business Impact + Likelihood ──────────────────────────────────
    st.markdown('<div style="height:20px;"></div>', unsafe_allow_html=True)
    bi_col, _bi_gap, lh_col = st.columns([10, 0.6, 10])
    with bi_col:
        with st.expander("Business Impact Analysis & Exposed Scope", expanded=True):
            if priority_item and priority_item.impact:
                imp = priority_item.impact
                crit_str = asset_criticality.upper()
                reputational_radius = "CRITICAL (Direct External User Exposure)" if is_customer_facing else "MODERATE (Internal Administrative Scope)"
                operational_severity = "HIGH INTERRUPTION" if crit_str in ["CRITICAL", "HIGH"] else "MODERATE / LOCAL DEGRADATION"
                compliance_str = ", ".join(compliance_scopes) if compliance_scopes else "Standard SOC2 Security Controls"

                st.markdown(
                    f'<div class="ep" style="border-left:3px solid {theme_color}; margin-top:8px; margin-bottom:12px;">'
                    f'<div class="ep-hdr" style="background:linear-gradient(90deg,{theme_color}14 0%,transparent 100%);">'
                    f'<div class="ep-pulse" style="background:{theme_color};"></div>'
                    f'<span class="ep-title" style="color:{theme_color};">Business Impact Metrics</span>'
                    f'<span class="ep-tag">Operational Scope</span>'
                    f'</div>'
                    f'<div class="ep-body">'
                    f'<div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; font-size:0.78rem;">'
                    f'<div>'
                    f'<div class="ep-lbl">Compliance Exposure</div>'
                    f'<div class="ep-val-sm" style="font-weight:700; margin-top:2px;">{compliance_str}</div>'
                    f'</div>'
                    f'<div>'
                    f'<div class="ep-lbl">Downtime Target Class</div>'
                    f'<div class="ep-val" style="color:{theme_color}; font-size:0.98rem; font-weight:800; margin-top:2px;">{crit_str}</div>'
                    f'</div>'
                    f'<div>'
                    f'<div class="ep-lbl">Reputational Blast Radius</div>'
                    f'<div class="ep-val-sm" style="font-weight:700; margin-top:2px; color:{"#dc3545" if is_customer_facing else "inherit"};">{reputational_radius}</div>'
                    f'</div>'
                    f'<div>'
                    f'<div class="ep-lbl">Operational Severity</div>'
                    f'<div class="ep-val-sm" style="font-weight:700; margin-top:2px; color:{theme_color};">{operational_severity}</div>'
                    f'</div>'
                    f'</div>'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )

                st.markdown(
                    f'<div style="font-size:0.8rem; line-height:1.5; margin-top:8px;">'
                    f'- **Customer Impact:** {imp.customer_impact}<br/>'
                    f'- **Reputational Risk:** {imp.reputational_risk}<br/>'
                    f'- **Operational Disruption:** {imp.operational_disruption}'
                    f'</div>',
                    unsafe_allow_html=True
                )
            else:
                st.write(biz_report.business_impact)
    with _bi_gap:
        pass
    with lh_col:
        with st.expander("Likelihood of Misuse Analysis", expanded=True):
            st.write(biz_report.likelihood)

    # ── Urgency classification line ───────────────────────────────────
    st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
    urgency_color = get_sev_color(severity)
    from utils.svg_indicators import get_svg_indicator
    st.markdown(
        f'<div class="block-guide" style="border-left:4px solid {urgency_color}; background:{theme_bg}; padding:6px 12px; display:flex; align-items:center; justify-content:space-between; border-radius:4px; border:1px solid rgba(255,255,255,0.05);">'
        f'<div style="font-size:0.62rem; text-transform:uppercase; letter-spacing:0.1em; opacity:0.5; font-weight:700;">Urgency Level Classification</div>'
        f'<div style="font-size:0.85rem; font-weight:800; color:{urgency_color}; font-family:monospace; display:flex; align-items:center; gap:6px;">'
        f'{get_svg_indicator("sla_breach" if severity in ("HIGH", "CRITICAL") else "confidence_stable", size=11)} '
        f'{biz_report.urgency.upper()}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Recommended Actions ───────────────────────────────────────────
    st.markdown('<div style="height:20px;"></div>', unsafe_allow_html=True)
    with st.expander("Remediation Action Roadmap & SLAs", expanded=True):
        if priority_item:
            sla_lbl = "IMMEDIATE [24 hours]" if sla_days == 1 else (f"URGENT [{sla_days} days]" if sla_days == 7 else f"SCHEDULED [{sla_days} days]")
            st.markdown(
                f'<div class="block-guide" style="border-left: 3px solid #dc3545; background: rgba(220, 53, 69, 0.03); padding:12px 16px; margin-bottom:14px;">'
                f'<b>Target Remediation SLA:</b> <span style="color:#dc3545; font-weight:700;">{sla_lbl}</span><br/>'
                f'<b>Primary Action:</b> {priority_item.recommended_action}'
                f'</div>',
                unsafe_allow_html=True
            )

        actions_list = biz_report.recommended_actions[:8]
        if priority_item and priority_item.recommended_action and priority_item.recommended_action not in actions_list:
            actions_list = [priority_item.recommended_action] + actions_list

        for idx, act in enumerate(actions_list, 1):
            st.markdown(f"**Action {idx}:** {act}")
