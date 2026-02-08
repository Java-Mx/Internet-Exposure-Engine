"""
Brutal Model Tester - Diversified Site Scanning
Generates a 'test_results.csv' with Ground Truth for accuracy benchmarking.
"""

import sys
from pathlib import Path
import json
import csv
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from risk_scoring.heuristic_detector import analyze_url_risk

# Diversified test set with labels (Ground Truth)
BRUTAL_TEST_SET = [
    # --- Malicious / High Risk ---
    # Phishing (Classic)
    ("br-icloud.com.br", "malicious", "Phishing"),
    ("paypal.com.secure-webscr.tk", "malicious", "Phishing"),
    ("netflix-account-update.xyz", "malicious", "Phishing"),
    ("steam-community-login.ru", "malicious", "Phishing"),
    ("wellsfargo-verify.web.app", "malicious", "Phishing"),
    
    # Typosquatting / Brand Imitation
    ("fac3b00k.tk", "malicious", "Typosquatting"),
    ("g00gle.dev", "malicious", "Typosquatting"),
    ("micr0soft-security.net", "malicious", "Typosquatting"),
    ("amaze-on-deals.info", "malicious", "Brand Imitation"),
    ("apple-support-id.me", "malicious", "Brand Imitation"),
    
    # Vulnerable Apps & Exposures
    ("testphp.vulnweb.com", "malicious", "Vulnerable App"),
    ("demo.testfire.net", "malicious", "Vulnerable App"),
    ("bwapp.hakhub.net", "malicious", "Vulnerable App"),
    ("http://www.raci.it/component/user/reset.html", "malicious", "Defacement"),
    ("192.168.1.1", "malicious", "Internal IP Exposure"),
    ("dev-admin-panel.local:8080", "malicious", "Admin Exposure"),
    ("staging-db-01.company.internal:5432", "malicious", "Database Exposure"),
    
    # DGA / Cryptojacking / Command & Control (Simulated Patterns)
    ("q8x2p9w4z1.top", "malicious", "DGA (Potential C2)"),
    ("m-static-01.xyz/miner.js", "malicious", "Cryptojacking"),
    ("update-agent.cc/payload.bin", "malicious", "Malware C2"),
    
    # --- Benign / Safe ---
    ("google.com", "benign", "Search Engine"),
    ("github.com", "benign", "Development"),
    ("microsoft.com", "benign", "Tech Brand"),
    ("apple.com", "benign", "Tech Brand"),
    ("wikipedia.org", "benign", "Educational"),
    ("amazon.com", "benign", "E-commerce"),
    ("cloudflare.com", "benign", "Security/CDN"),
    ("python.org", "benign", "Programming"),
    ("stackoverflow.com", "benign", "Community"),
    ("linkedin.com", "benign", "Social/Professional"),
    ("medium.com", "benign", "Content/Blog"),
    ("nytimes.com", "benign", "News"),
    ("bbc.co.uk", "benign", "News"),
    ("nasa.gov", "benign", "Government"),
    ("mit.edu", "benign", "Education"),
    ("docker.com", "benign", "DevOps Tool"),
    ("npm.js", "benign", "Developer Ecosystem"),
    ("adobe.com", "benign", "Creative Software"),
    ("slack.com", "benign", "Communication"),
    ("zoom.us", "benign", "Communication"),
]

from risk_scanner import AutomatedPipeline, parse_input_list

def run_brutal_test():
    results = []
    print(f"Initializing Production Pipeline for Brutal Test...")
    pipeline = AutomatedPipeline()
    
    print(f"Starting Brutal Test on {len(BRUTAL_TEST_SET)} targets...")
    
    # Pre-parse assets
    assets = []
    for url, label, subtype in BRUTAL_TEST_SET:
        parsed = parse_input_list(url)[0]
        parsed['ground_truth'] = label
        parsed['subtype'] = subtype
        assets.append(parsed)
    
    # Run full pipeline
    pipeline_results = pipeline.run(assets)
    reports = pipeline_results.get('risk_reports', [])
    
    for i, report in enumerate(reports):
        url = assets[i].get('domain') or assets[i].get('ip')
        ground_truth = assets[i].get('ground_truth')
        score = report.get('risk_score', 0)
        
        # Determine prediction based on score (standard 30 threshold for vulnerable)
        predicted_label = "malicious" if score >= 30 else "benign"
        
        results.append({
            "url": url,
            "ground_truth": ground_truth,
            "predicted": predicted_label,
            "score": score,
            "level": report.get('risk_level'),
            "subtype": assets[i].get('subtype'),
            "timestamp": datetime.now().isoformat()
        })
        print(f"[{i+1}/{len(assets)}] Scanned {url}: Score {score} ({report.get('risk_level')})")
    
    # Save to CSV for Streamlit app
    output_path = Path("data/test_results.csv")
    output_path.parent.mkdir(exist_ok=True)
    
    if results:
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    
    print(f"\nBrutal Test Complete! Results saved to {output_path}")

if __name__ == "__main__":
    run_brutal_test()
