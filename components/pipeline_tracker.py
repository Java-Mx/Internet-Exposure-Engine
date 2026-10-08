"""
AERIS Pipeline Tracker Component
=================================
Renders the multi-layer intelligence execution pipeline status.
"""
import streamlit as st
from utils.svg_indicators import get_svg_indicator

def render_pipeline_tracker(done_up_to: int) -> None:
    """Renders the pipeline tracker in the UI."""
    steps = [
        ("Exposure Discovery (Layer 1-3 Heuristics & ML)", "exposure"),
        ("Evidence Correlation (Layer 3 Cross-Scan Analysis)", "correlation"),
        ("Threat Reasoning (Layer 5 Offline Deterministic Logic)", "reasoning"),
        ("Business Context (Layer 6 Operational & SLA Estimation)", "context"),
        ("Risk Prioritization (Layer 4 Prioritization & Centrality)", "prioritization"),
        ("Governance Validation (Layer 7 Cryptographic & Audit Signature)", "governance"),
    ]
    
    rows = []
    rows.append('<div class="pipeline-box" style="margin-top:14px; border:1px solid rgba(255,255,255,0.06); border-radius:8px; overflow:hidden;">')
    rows.append('<div class="pipeline-hdr" style="display:flex; align-items:center; justify-content:space-between; padding:10px 16px; background:rgba(25,135,84,0.08); border-bottom:1px solid rgba(255,255,255,0.06); height:38px;"><span style="display:flex; align-items:center; gap:10px; font-size:0.75rem; font-weight:800; text-transform:uppercase; letter-spacing:0.06em; color:#e0e0e0;">Multi-Layer Intelligence Pipeline Execution</span><span style="color:#198754; font-weight:800; font-size:0.7rem; letter-spacing:0.08em; display:flex; align-items:center; gap:8px;">' + get_svg_indicator("governance_verified", size=13) + ' VALIDATED</span></div>')
    rows.append('<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; padding:12px 16px; background:rgba(0,0,0,0.22);">')
    
    for i, (label, _) in enumerate(steps):
        if i < done_up_to:
            rows.append(
                f'<div style="font-size:0.72rem; color:#198754; font-weight:700; display:flex; align-items:center; gap:12px; height:24px; text-transform:uppercase; letter-spacing:0.05em;">'
                f'{get_svg_indicator("layer_complete", size=12)} {label}'
                f'</div>'
            )
        elif i == done_up_to:
            rows.append(
                f'<div style="font-size:0.72rem; color:#ffc107; font-weight:700; display:flex; align-items:center; gap:12px; height:24px; text-transform:uppercase; letter-spacing:0.05em;">'
                f'{get_svg_indicator("in_progress", size=12)} {label}'
                f'</div>'
            )
        else:
            rows.append(
                f'<div style="font-size:0.72rem; color:#6c757d; font-weight:700; display:flex; align-items:center; gap:12px; height:24px; text-transform:uppercase; letter-spacing:0.05em; opacity:0.4;">'
                f'{get_svg_indicator("audit_locked", size=12)} {label}'
                f'</div>'
            )
            
    rows.append('</div>')
    rows.append('</div>')
    st.markdown("\n".join(rows), unsafe_allow_html=True)
