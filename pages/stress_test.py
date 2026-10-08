"""
AERIS Adversarial Stress Test Page
===================================
Executes and reviews the automated extreme input testing suite.
"""
import streamlit as st
import json
import os
import sys
import subprocess
import html as _html
from pathlib import Path

def render_stress_test() -> None:
    st.title("Adversarial Stress Test Suite")
    st.markdown(
        "Execute and review the automated extreme input testing suite. This suite fires "
        "500+ malformed paths, homoglyphs, and known malicious domains against the engine "
        "to ensure 0% crash rate and 100% safety reliability under duress."
    )
    st.divider()

    col_run, col_space = st.columns([1, 4])
    with col_run:
        run_btn = st.button("Run Full Suite", use_container_width=True, type="primary")
        
    if run_btn:
        with st.spinner("Executing 8-Phase Stress Test (this may take up to 4 minutes)..."):
            script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "stress", "stress_runner.py")
            # Enforce utf-8 to prevent unicode print errors on Windows
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            
            proc = subprocess.run([sys.executable, script_path, "--quiet"], capture_output=True, text=True, env=env)
            if proc.returncode == 0:
                st.success("Stress Test Suite completed successfully! Verdict updated.")
            else:
                st.error("Stress Test Suite exited with errors. Check the logs.")

    verdict_path = Path("tests/stress/reports/final_verdict.json")
    if verdict_path.exists():
        try:
            with open(verdict_path, "r", encoding="utf-8") as f:
                v_data = json.load(f)
                
            verdict = v_data.get("verdict", "Unknown")
            v_color = "#198754" if verdict == "Production Safe" else ("#fd7e14" if verdict == "Partially Reliable" else "#dc3545")
            
            st.markdown(
                f'<div class="card" style="border-left:5px solid {v_color}; text-align:left;">'
                f'<h3 style="color:{v_color}; margin-bottom:5px;">System Grading: {_html.escape(verdict)}</h3>'
                f'<div style="opacity:0.8;">{_html.escape(v_data.get("verdict_explanation", ""))}</div>'
                f'</div>', unsafe_allow_html=True
            )
            st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
            
            # Performance Metrics
            m = v_data.get("metrics", {})
            m1, m2, m3, m4 = st.columns(4)
            
            def _st_stat(lbl, v, c="#198754"):
                return f'<div class="card" style="min-height:120px;"><div style="font-size:1.8rem;font-weight:800;color:{c};">{_html.escape(str(v))}</div><div class="card-label">{lbl}</div></div>'
                
            with m1: st.markdown(_st_stat("Total Tests", m.get("total_tests", 0), "#e0e0e0"), unsafe_allow_html=True)
            with m2: 
                errs = m.get("total_errors", 0)
                st.markdown(_st_stat("Total Errors Found", errs, "#198754" if errs == 0 else "#dc3545"), unsafe_allow_html=True)
            with m3: st.markdown(_st_stat("Safety Pass Rate", f"{m.get('safety_pass_rate_pct', 0)}%"), unsafe_allow_html=True)
            with m4: st.markdown(_st_stat("Avg Scenario Pass Rate", f"{m.get('average_pass_rate_pct', 0)}%"), unsafe_allow_html=True)
            
            # Details & Weaknesses
            st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
            weaknesses = v_data.get("weaknesses", [])
            if weaknesses:
                st.warning("Identified Weaknesses & Flaws")
                for w in weaknesses:
                    st.markdown(f"- {_html.escape(w)}")
            else:
                st.success("Zero weaknesses detected! The pipeline successfully defended against all evasion techniques.")
                
            # JSON Payload
            with st.expander("View Raw Verdict JSON"):
                st.json(v_data)
        except Exception as err:
            st.error(f"Error loading stress test reports: {err}")
    else:
        st.info("No prior stress test results found. Click 'Run Full Suite' to generate the first verdict.")
