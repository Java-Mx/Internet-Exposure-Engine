"""
AERIS Admin: Anti-Theater Scanner Page
=======================================
Runs static analysis across the codebase to identify hardcoded intelligence,
simulated processing delays, or unvalidated metrics. Gated to Admin role.
"""
import streamlit as st
import html as _html
from pathlib import Path
from governance.anti_theater_scanner import run_scan, TheaterFinding

def render_anti_theater_scanner() -> None:
    st.title("Admin: Anti-Theater Scanner")
    st.markdown(
        "Runs programmatic static analysis across the AERIS codebase to detect "
        "intelligence theater violations (e.g. hardcoded IP/ASN nodes, fabricated metrics, "
        "or simulated operational delays)."
    )
    st.divider()

    # Trigger scan button
    if st.button("Run Anti-Theater Code Audit", type="primary"):
        st.session_state["theater_scan_run"] = True
        with st.spinner("Analyzing codebase files..."):
            try:
                findings = run_scan()
                st.session_state["theater_findings"] = findings
                st.success("Anti-theater audit scan completed successfully!")
            except Exception as err:
                st.error(f"Scanner error: {err}")

    # Display findings if they exist in session state
    findings = st.session_state.get("theater_findings")
    
    if findings is not None:
        # Count severities
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        # Display summary counts
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(
                f'<div class="card" style="border-left:4px solid #dc3545;"><div style="font-size:1.8rem;font-weight:800;color:#dc3545;">{critical_count}</div><div class="card-label">🔴 Critical Findings</div></div>',
                unsafe_allow_html=True
            )
        with c2:
            st.markdown(
                f'<div class="card" style="border-left:4px solid #fd7e14;"><div style="font-size:1.8rem;font-weight:800;color:#fd7e14;">{high_count}</div><div class="card-label">🟠 High Findings</div></div>',
                unsafe_allow_html=True
            )
        with c3:
            st.markdown(
                f'<div class="card" style="border-left:4px solid #ffc107;"><div style="font-size:1.8rem;font-weight:800;color:#ffc107;">{medium_count}</div><div class="card-label">🟡 Medium Findings</div></div>',
                unsafe_allow_html=True
            )
        with c4:
            st.markdown(
                f'<div class="card" style="border-left:4px solid #198754;"><div style="font-size:1.8rem;font-weight:800;color:#198754;">{low_count}</div><div class="card-label">🟢 Low Findings</div></div>',
                unsafe_allow_html=True
            )

        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

        if not findings:
            st.success("✅ Clean Scan: No intelligence theater patterns or hardcoded mock indicators found in active modules.")
        else:
            st.warning(f"Found {len(findings)} theater pattern violations across codebase. Review details below:")
            
            # Print tabular detail of findings
            for idx, f in enumerate(findings, 1):
                icon = f.severity_icon
                color = "#dc3545" if f.severity == "CRITICAL" else ("#fd7e14" if f.severity == "HIGH" else ("#ffc107" if f.severity == "MEDIUM" else "#198754"))
                
                st.markdown(
                    f'<div class="card" style="border-left:5px solid {color}; text-align:left; padding:12px; margin-bottom:10px;">'
                    f'<div style="font-weight:800; color:{color}; font-size:0.85rem;">Finding {idx}: {icon} {f.pattern_name} ({f.severity})</div>'
                    f'<div style="font-size:0.75rem; font-family:monospace; margin-top:4px;"><b>File:</b> {f.file}:{f.line_number}</div>'
                    f'<div style="font-size:0.75rem; font-family:monospace; margin-top:2px; background:rgba(0,0,0,0.15); padding:4px 8px; border-radius:3px;"><code>{_html.escape(f.line_content)}</code></div>'
                    f'<div style="font-size:0.72rem; opacity:0.85; margin-top:6px;"><b>Description:</b> {_html.escape(f.description)}</div>'
                    f'<div style="font-size:0.72rem; color:{color}; margin-top:4px; font-weight:700;"><b>Remediation:</b> {_html.escape(f.remediation)}</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
    else:
        st.info("Trigger a codebase audit scan to generate a report.")
