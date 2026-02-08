
import sys
from pathlib import Path
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scan_engine import ScanEngine
from risk_scanner import parse_input_list, AutomatedPipeline

def direct_verification():
    test_urls = [
        "geographic.org/geographic_names/v/ve_014.html",
        "paperbackswap.com/Sadie-Rose-Adventure-Hilda-Stahl/book/0891076352/",
        "baseball-almanac.com/players/player.php?p=hergeda01",
        "biographi.ca/EN/ShowBio.asp?BioId=41243",
        "deborahfrances-white.com/stand-up.html"
    ]
    
    print("\n" + "="*80)
    print("DIRECT PIPELINE VERIFICATION")
    print("="*80)
    
    # 1. Parse URLs to Dictionaries
    parsed_assets = []
    for url in test_urls:
        parsed = parse_input_list(url)
        if parsed:
            parsed_assets.append(parsed[0])
            print(f"Parsed: {url}")

    # 2. Run AutomatedPipeline directly
    print("\nRunning AutomatedPipeline...")
    pipeline = AutomatedPipeline()
    results = pipeline.run(parsed_assets)
    
    # 3. Analyze Results
    print("\n[RESULTS]")
    for report in results.get('risk_reports', []):
        asset_label = report.get('asset', {}).get('url', 'Unknown')
        risk_level = report.get('risk_level', 'UNKNOWN')
        risk_score = report.get('risk_score', 0)
        print(f"  - {asset_label:<70} | {risk_level:<10} | Score: {risk_score}")
        if report.get('evidence'):
            print(f"    Evidence: {', '.join(report['evidence'][:2])}")

    print("\n" + "="*80)
    print("VERIFICATION COMPLETE")
    print("="*80)

if __name__ == "__main__":
    direct_verification()
