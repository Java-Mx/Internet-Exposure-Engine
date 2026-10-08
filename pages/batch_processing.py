"""
AERIS Batch Processing Page
=============================
Upload a CSV containing a domain/url list and scan multiple targets concurrently.
"""
import streamlit as st
import pandas as pd
import concurrent.futures
import time
import re
import html as _html
from datetime import datetime
from services.assessment_service import run_heuristic_analysis

def render_batch_processing() -> None:
    st.title("Batch Processing")
    st.markdown(
        "Upload a CSV file containing a column named `domain` or `url` to scan multiple targets concurrently. "
        "The system processes targets in parallel, enabling bulk threat tiering."
    )
    
    upload = st.file_uploader("Upload CSV (max 100 on standard tier)", type=["csv"])
    if upload:
        try:
            df = pd.read_csv(upload)
            col = "domain" if "domain" in df.columns else ("url" if "url" in df.columns else df.columns[0])
            domains = df[col].dropna().astype(str).tolist()
            
            st.info(f"Found {len(domains)} targets in `{_html.escape(col)}` column.")
            
            if st.button("Start Batch Analysis", type="primary"):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                rows = []

                def _scan(d):
                    t0 = time.time()
                    try:
                        r = run_heuristic_analysis(d)
                        ms = (time.time() - t0) * 1000
                        if r:
                            t2_vote = '-'
                            t3_mod = '-'
                            for ev in r.get('evidence', []):
                                if '[ML-T2]' in ev:
                                    m = re.search(r'predicted=(\w+)', ev)
                                    if m: t2_vote = m.group(1)
                                if '[ML-T3]' in ev:
                                    m = re.search(r'modifier=([+-]\d+\.\d+)', ev)
                                    if m: t3_mod = m.group(1)
                            return {
                                "Domain": d, 
                                "Risk Score": r.get("risk_score"), 
                                "Risk Level": r.get("risk_level"),
                                "Confidence": f"{float(r.get('confidence', 0))*100:.0f}%", 
                                "ML Tier 2": t2_vote,
                                "ML Tier 3": t3_mod,
                                "Time (ms)": f"{ms:.0f}"
                            }
                    except Exception:
                        pass
                    return {
                        "Domain": d, "Risk Score": "Error", "Risk Level": "Error", 
                        "Confidence": "", "ML Tier 2": "", "ML Tier 3": "", "Time (ms)": ""
                    }

                total = len(domains)
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                    futs = {pool.submit(_scan, d): d for d in domains}
                    done = 0
                    for f in concurrent.futures.as_completed(futs):
                        done += 1
                        progress_bar.progress(done / total)
                        status_text.text(f"Processed {done}/{total}")
                        rows.append(f.result())
                
                out_df = pd.DataFrame(rows)
                st.success(f"Batch analysis of {total} domains complete.")
                
                st.dataframe(out_df, use_container_width=True)
                
                csv_bytes = out_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "Download Results (CSV)",
                    data=csv_bytes,
                    file_name=f"IERSS_BatchResults_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    type="primary"
                )
                
        except Exception as e:
            st.error(f"Error processing batch: {e}")
