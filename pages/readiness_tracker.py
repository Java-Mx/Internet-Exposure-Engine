"""
AERIS Admin: Enterprise Readiness Tracker Page
================================================
Evaluates and displays checks for enterprise compliance (authentication,
auditing, logging, safety limits). Gated to Admin role.
"""
import streamlit as st
import html as _html
import yaml
from pathlib import Path
from datetime import datetime

from governance.readiness_checker import run_checks, compute_scores, update_yaml

YAML_PATH = Path("governance/enterprise_readiness.yaml")

def render_readiness_tracker() -> None:
    st.title("Admin: Enterprise Readiness Tracker")
    st.markdown(
        "Verifies compliance with enterprise architecture directives, security foundations, "
        "governance controls, and the AERIS Constitution."
    )
    st.divider()

    # Load YAML results
    yaml_data = {}
    if YAML_PATH.exists():
        try:
            with open(YAML_PATH, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)
        except Exception as err:
            st.error(f"Error loading readiness YAML: {err}")

    root = yaml_data.get("aeris_enterprise_readiness", yaml_data.get("aerис_enterprise_readiness", {}))
    overall_score = root.get("overall_score", 0)
    last_computed = root.get("last_computed", "Never")

    # Recheck button
    if st.button("Run Diagnostics & Recompute Readiness", type="primary"):
        with st.spinner("Analyzing codebase against checklist..."):
            try:
                results = run_checks()
                scores = compute_scores(results)
                update_yaml(results, scores)
                st.success("Readiness checklist updated successfully!")
                st.rerun()
            except Exception as err:
                st.error(f"Failed to run checks: {err}")

    # Display overall score
    score_color = "#198754" if overall_score >= 90 else ("#fd7e14" if overall_score >= 70 else "#dc3545")
    st.markdown(
        f'<div class="card" style="border-left:5px solid {score_color}; text-align:left;">'
        f'<div style="font-size:2.5rem; font-weight:900; color:{score_color}; font-family:monospace; line-height:1;">{overall_score}%</div>'
        f'<div class="card-label" style="margin-top:6px;">Overall Enterprise Readiness Score</div>'
        f'<div style="font-size:0.75rem; opacity:0.5; margin-top:8px;">Last Scanned: {last_computed}</div>'
        f'</div>',
        unsafe_allow_html=True
    )
    
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    # Categories list
    categories = root.get("categories", {})
    if not categories:
        st.info("Run diagnostics to initialize category scores.")
        return

    # Render category breakdown
    for cat_name, cat_data in categories.items():
        score = cat_data.get("score", 0)
        status = cat_data.get("status", "failing")
        color = "#198754" if score == 100 else ("#fd7e14" if score >= 50 else "#dc3545")
        
        with st.expander(f"⚙️ {cat_name.replace('_', ' ')} — {score}% ({status.upper()})"):
            checks = cat_data.get("checks", {})
            for check_id, check_info in checks.items():
                passing = check_info.get("passing", False)
                desc = check_info.get("description", check_id)
                icon = "🟢 Passing" if passing else "🔴 Failing"
                
                # Dynamic visual rows
                st.markdown(
                    f'<div style="padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.02); display:flex; justify-content:space-between;">'
                    f'<span>{_html.escape(desc)}</span>'
                    f'<span style="font-weight:700; color:{"#198754" if passing else "#dc3545"}">{icon}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
