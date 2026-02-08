"""
Phishing Detection Accuracy Tester (Reproduction Script)

Tests the HeuristicRiskDetector against problematic URLs from 
the malicious_phish.csv dataset to confirm false negatives.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from risk_scoring.heuristic_detector import analyze_url_risk

# Problematic URLs from malicious_phish.csv (reported as False Positives/Negatives)
TEST_URLS = [
    ("br-icloud.com.br", "phishing"),
    ("http://www.szabadmunkaero.hu/cimoldal.html?start=12", "defacement"),
    ("http://larcadelcarnevale.com/catalogo/palloncini", "defacement"),
    ("http://www.raci.it/component/user/reset.html", "defacement"),
    ("paypal.com.secure-webscr.tk", "phishing"),
    ("netflix-account-update.xyz", "phishing"),
    ("steam-community-login.ru", "phishing"),
]

def run_tests():
    print(f"{'URL':<60} | {'Type':<10} | {'Score':<8} | {'Level':<10} | {'Status'}")
    print("-" * 105)
    
    failures = 0
    for url, label in TEST_URLS:
        result = analyze_url_risk(url)
        score = result['risk_score']
        level = result['risk_level']
        
        # We expect Malicious urls to be at least MEDIUM (30+) or HIGH (50+)
        passed = score >= 30
        status = "PASSED" if passed else "FAILED (False Negative)"
        if not passed:
            failures += 1
            
        print(f"{url[:60]:<60} | {label:<10} | {score:<8} | {level:<10} | {status}")

    print("-" * 105)
    print(f"Total Failures: {failures}/{len(TEST_URLS)}")

if __name__ == "__main__":
    run_tests()
