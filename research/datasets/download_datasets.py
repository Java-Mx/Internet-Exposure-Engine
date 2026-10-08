"""
AERIS Dataset Downloader
=========================
Downloads benign and malicious samples for verification.
"""
import os
import csv
from pathlib import Path

DATASET_DIR = Path(__file__).parent

def bootstrap_mock_datasets():
    """Create mock data if offline or downloads fail."""
    os.makedirs(DATASET_DIR, exist_ok=True)
    
    benign_file = DATASET_DIR / "tranco_sample.csv"
    if not benign_file.exists():
        with open(benign_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["rank", "domain"])
            writer.writerow(["1", "google.com"])
            writer.writerow(["2", "facebook.com"])
            writer.writerow(["3", "apple.com"])
            writer.writerow(["4", "microsoft.com"])
            writer.writerow(["5", "amazon.com"])
        print(f"Created mock benign dataset: {benign_file}")
        
    malicious_file = DATASET_DIR / "phishtank_sample.csv"
    if not malicious_file.exists():
        with open(malicious_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["phish_id", "url", "phish_detail_url", "submission_time", "verified", "verification_time", "online", "target"])
            writer.writerow(["1001", "http://paypa1-security-login.com", "http://phishtank.com/phish?id=1001", "2026-06-08T00:00:00Z", "yes", "2026-06-08T01:00:00Z", "yes", "PayPal"])
            writer.writerow(["1002", "https://apple-id-verify-alert.net", "http://phishtank.com/phish?id=1002", "2026-06-08T00:00:00Z", "yes", "2026-06-08T01:00:00Z", "yes", "Apple"])
        print(f"Created mock malicious dataset: {malicious_file}")

if __name__ == "__main__":
    print("Bootstrapping evaluation datasets...")
    bootstrap_mock_datasets()
    print("Dataset bootstrapping complete.")
