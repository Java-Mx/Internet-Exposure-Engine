"""
AERIS Score Display Component
==============================
Renders risk scores, priority ratings, and severity badges.
"""
import streamlit as st
from utils.helpers import get_sev_color, get_analysis_depth_label, get_trust_verdict

def render_score_display(
    score: float,
    severity: str,
    priority_score: float,
    priority_urgency: str,
    confidence: float,
    business_unit: str,
    asset_criticality: str,
    theme_color: str
) -> None:
    """Renders the main score strip and trust verdict banner."""
    sev_color = get_sev_color(severity)
    p_color = get_sev_color(priority_urgency)
    conf_pct = int(confidence * 100)
    depth_label, depth_desc = get_analysis_depth_label(conf_pct)
    conf_color = "#198754" if conf_pct >= 80 else ("#fd7e14" if conf_pct >= 60 else "#dc3545")

    # 4-column stats
    st.markdown(
        f'<div class="ep" style="border-left:3px solid {theme_color};margin-top:18px;">'
        f'<div class="ep-hdr" style="background:linear-gradient(90deg,{theme_color}18 0%,transparent 100%);">'
        f'<div class="ep-pulse" style="background:{theme_color};"></div>'
        f'<span class="ep-title" style="color:{theme_color};">Assessment Scores</span>'
        f'<span class="ep-tag">EIRPP v2</span>'
        f'</div>'
        f'<div class="ep-body">'
        f'<div class="ep-stats">'
        # Stat 1: EIRPP Priority
        f'<div class="ep-stat">'
        f'<div class="ep-lbl">EIRPP Priority Score</div>'
        f'<div class="ep-val" style="font-size:2.1rem;font-weight:800;color:{p_color};line-height:1;">{priority_score:.0f}</div>'
        f'<div style="font-size:0.55rem;opacity:0.38;letter-spacing:0.06em;margin-top:2px;">OUT OF 100</div>'
        f'</div>'
        # Stat 2: Technical Risk
        f'<div class="ep-stat">'
        f'<div class="ep-lbl">Technical Risk Score</div>'
        f'<div class="ep-val" style="font-size:2.1rem;font-weight:800;color:{sev_color};line-height:1;">{score:.0f}</div>'
        f'<div style="font-size:0.55rem;opacity:0.38;letter-spacing:0.06em;margin-top:2px;">OUT OF 100</div>'
        f'</div>'
        # Stat 3: Context
        f'<div class="ep-stat">'
        f'<div class="ep-lbl">Context & Criticality</div>'
        f'<div style="margin-bottom:6px;"><span class="sev-badge sev-{severity}">RISK: {severity}</span></div>'
        f'<div style="font-size:0.78rem;font-weight:700;color:{theme_color};margin-bottom:2px;">BU: {business_unit[:18]}</div>'
        f'<div style="font-size:0.57rem;opacity:0.40;letter-spacing:0.07em;text-transform:uppercase;">Criticality: {asset_criticality}</div>'
        f'</div>'
        # Stat 4: Analysis Depth
        f'<div class="ep-stat">'
        f'<div class="ep-lbl">Analysis Depth</div>'
        f'<div class="ep-val" style="font-size:1.4rem;font-weight:800;color:{conf_color};margin-bottom:3px;">{depth_label}</div>'
        f'<div style="font-size:0.66rem;opacity:0.50;line-height:1.4;">{depth_desc}</div>'
        f'</div>'
        f'</div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    
    # Trust Verdict
    v_title, v_body = get_trust_verdict(severity)
    st.markdown(
        f'<div class="verdict-banner verdict-{severity}">'
        f'<div class="verdict-title">{v_title}</div>'
        f'<div class="verdict-body">{v_body}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
