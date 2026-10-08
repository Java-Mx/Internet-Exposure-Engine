"""
AERIS Model Evaluation Pipeline
================================
Runs classification verification over benchmark datasets and saves metrics.
"""
import os
import sys
import json
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from research.datasets.download_datasets import bootstrap_mock_datasets
from research.evaluation.metrics import compute_classification_metrics
from risk_scoring.heuristic_detector import HeuristicRiskDetector
from risk_scoring.reputation_aggregator import ReputationResult

# Set up global mocks for offline execution
_mock_resp = MagicMock()
_mock_resp.status_code = 200
_mock_resp.text = "<html><title>Safe Brand Portal</title></html>"

patch_requests = patch("requests.get", return_value=_mock_resp)
patch_dns = patch("socket.gethostbyname", return_value="127.0.0.1")  # nosec: unittest.mock patch — offline DNS isolation, not a real IP
patch_addrinfo = patch("socket.getaddrinfo", return_value=[(2, 1, 0, "", ("127.0.0.1", 0))])  # nosec: unittest.mock patch — offline DNS isolation, not a real IP
patch_fqdn = patch("socket.getfqdn", return_value="localhost")

patch_ssl = patch("risk_scoring.patches.check_ssl_certificate", return_value=(0.0, "1", "SSL Valid (Mock)"))
patch_age = patch("risk_scoring.patches.check_domain_age", return_value=(365.0, "1", "Domain is old (Mock)"))
patch_html = patch("risk_scoring.patches.scan_html_content", return_value=[])
patch_uh = patch("risk_scoring.patches.check_urlhaus", return_value=(0.0, "1", "Not listed in URLhaus (Mock)"))
patch_rep = patch("risk_scoring.reputation_aggregator.check_reputation", return_value=ReputationResult(
    gsb_result=None, vt_result=None, is_unsafe=False, tier1_score=0.0,
    evidence_strings=[], sources_checked=[], sources_flagged=[], fully_checked=True
))

def start_mocks():
    patch_requests.start()
    patch_dns.start()
    patch_addrinfo.start()
    patch_fqdn.start()
    patch_ssl.start()
    patch_age.start()
    patch_html.start()
    patch_uh.start()
    patch_rep.start()

def stop_mocks():
    patch_requests.stop()
    patch_dns.stop()
    patch_addrinfo.stop()
    patch_fqdn.stop()
    patch_ssl.stop()
    patch_age.stop()
    patch_html.stop()
    patch_uh.stop()
    patch_rep.stop()

def run_evaluation_pipeline():
    # Make sure mock data is present
    bootstrap_mock_datasets()
    
    # Start offline network patches
    start_mocks()
    
    benign_path = Path(__file__).parent.parent / "datasets" / "tranco_sample.csv"
    malicious_path = Path(__file__).parent.parent / "datasets" / "phishtank_sample.csv"
    
    y_true = []
    y_pred = []
    
    detector = HeuristicRiskDetector()
    
    print("Evaluating benign dataset...")
    with open(benign_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"]
            res = detector.get_complete_analysis(domain)
            risk_lvl = res.get("risk_level", "LOW")
            pred = 1 if risk_lvl in ("HIGH", "CRITICAL") else 0
            y_true.append(0)
            y_pred.append(pred)
            print(f"  Domain: {domain} -> Pred: {pred} (True: 0)")
            
    print("Evaluating malicious dataset...")
    with open(malicious_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"]
            res = detector.get_complete_analysis(url)
            risk_lvl = res.get("risk_level", "LOW")
            pred = 1 if risk_lvl in ("HIGH", "CRITICAL") else 0
            y_true.append(1)
            y_pred.append(pred)
            print(f"  URL: {url} -> Pred: {pred} (True: 1)")
            
    # Stop patches
    stop_mocks()
    
    # Calculate metrics
    metrics = compute_classification_metrics(y_true, y_pred)
    
    # Save results
    results_dir = Path(__file__).parent / "results"
    os.makedirs(results_dir, exist_ok=True)
    
    metrics_data = {
        "overall_accuracy": metrics.accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1_score": metrics.f1_score,
        "false_positive_rate": metrics.false_positive_rate,
        "false_negative_rate": metrics.false_negative_rate,
        "confusion_matrix": {
            "tp": metrics.tp,
            "fp": metrics.fp,
            "tn": metrics.tn,
            "fn": metrics.fn
        }
    }
    
    output_file = results_dir / "latest.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)
        
    print("\n" + "=" * 40)
    print("  EVALUATION COMPLETED")
    print("=" * 40)
    print(f"Accuracy:  {metrics.accuracy:.2%}")
    print(f"Precision: {metrics.precision:.2%}")
    print(f"Recall:    {metrics.recall:.2%}")
    print(f"F1 Score:  {metrics.f1_score:.2%}")
    print(f"FPR:       {metrics.false_positive_rate:.2%}")
    print(f"FNR:       {metrics.false_negative_rate:.2%}")
    print(f"Saved:     {output_file}")
    print("=" * 40 + "\n")

if __name__ == "__main__":
    run_evaluation_pipeline()
