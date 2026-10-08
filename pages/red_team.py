"""
AERIS Red-Team Adversarial Testing Page
========================================
Runs advanced attacker scenarios and verifies detection rate.
"""
import streamlit as st
import pandas as pd
import os
import sys
import subprocess
import html as _html
from pathlib import Path

def render_red_team() -> None:
    st.title("Red-Team Adversarial Testing")
    st.markdown(
        "Simulate advanced attacker scenarios including brand impersonation, "
        "homograph attacks, URL obfuscation, CDN masking, and redirect chains. "
        "Verify the engine detects all evasion techniques with zero false negatives."
    )
    st.divider()

    col_run, col_space = st.columns([1, 4])
    with col_run:
        rt_run_btn = st.button("Run Red-Team Suite", use_container_width=True, type="primary")

    if rt_run_btn:
        with st.spinner("Executing adversarial red-team tests…"):
            script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "red_team", "red_team_tester.py")
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            proc = subprocess.run([sys.executable, script_path], capture_output=True, text=True, env=env)
            if proc.returncode == 0:
                st.success("Red-Team Suite completed! Results updated below.")
            else:
                st.error("Red-Team Suite exited with errors.")
                with st.expander("View stderr"):
                    st.code(proc.stderr or "(no output)")

    # ── Display CSV Results
    csv_path = Path("tests/red_team/red_team_test_results.csv")
    if csv_path.exists():
        try:
            df = pd.read_csv(csv_path)

            total = len(df)
            fn_count = int(df["is_false_negative"].sum())
            success_rate = ((total - fn_count) / total) * 100 if total else 0

            sr_color = "#198754" if success_rate == 100 else ("#fd7e14" if success_rate >= 80 else "#dc3545")
            st.markdown(
                f'<div class="card" style="border-left:5px solid {sr_color}; text-align:left;">'
                f'<h3 style="color:{sr_color}; margin-bottom:5px;">Detection Success Rate: {success_rate:.1f}%</h3>'
                f'<div style="opacity:0.8;">{total} adversarial cases tested — {fn_count} false negative(s)</div>'
                f'</div>', unsafe_allow_html=True
            )
            st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

            m1, m2, m3 = st.columns(3)
            def _rt_stat(lbl, v, c="#198754"):
                return f'<div class="card" style="min-height:120px;"><div style="font-size:2.2rem;font-weight:800;color:{c};">{_html.escape(str(v))}</div><div class="card-label">{lbl}</div></div>'
                
            with m1: st.markdown(_rt_stat("Total Cases", total, "#e0e0e0"), unsafe_allow_html=True)
            with m2: st.markdown(_rt_stat("False Negatives", fn_count, "#198754" if fn_count == 0 else "#dc3545"), unsafe_allow_html=True)
            with m3: st.markdown(_rt_stat("Success Rate", f"{success_rate:.1f}%", sr_color), unsafe_allow_html=True)

            st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

            # Results table
            st.subheader("Detailed Results")
            display = df[["domain", "attack_type", "predicted_risk_level", "risk_score", "confidence", "is_false_negative"]].copy()
            display.columns = ["Domain", "Attack Type", "Risk Level", "Score", "Confidence", "False Negative"]
            display["Score"] = display["Score"].apply(lambda x: f"{x:.1f}")
            display["Confidence"] = display["Confidence"].apply(lambda x: f"{x:.2f}")
            display["False Negative"] = display["False Negative"].apply(lambda x: "YES" if x else "No")

            st.dataframe(display, use_container_width=True)

            # Report markdown
            report_path = Path("tests/red_team/red_team_security_report.md")
            if report_path.exists():
                with st.expander("View Full Security Report"):
                    st.markdown(report_path.read_text(encoding="utf-8"))
        except Exception as err:
            st.error(f"Error loading red-team reports: {err}")
    else:
        st.info("No prior red-team results found. Click 'Run Red-Team Suite' to generate them.")
