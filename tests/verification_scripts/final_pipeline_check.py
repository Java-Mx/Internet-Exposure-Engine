
import sys
from pathlib import Path
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scan_engine import ScanEngine
from risk_scanner import parse_input_list

def final_end_to_end_check():
    test_urls = [
        "geographic.org/geographic_names/v/ve_014.html",
        "paperbackswap.com/Sadie-Rose-Adventure-Hilda-Stahl/book/0891076352/",
        "baseball-almanac.com/players/player.php?p=hergeda01",
        "biographi.ca/EN/ShowBio.asp?BioId=41243",
        "deborahfrances-white.com/stand-up.html"
    ]
    
    print("\n" + "="*80)
    print("FINAL END-TO-END PIPELINE CHECK")
    print("="*80)
    
    engine = ScanEngine()
    
    # 1. Test Parsing separately first
    print("\n[STEP 1] Parsing Validation:")
    parsed_assets = []
    for url in test_urls:
        parsed = parse_input_list(url)
        if parsed:
            p = parsed[0]
            parsed_assets.append(p)
            print(f"  OK: {url} -> Domain: {p['domain']}, URL: {p['url']}")
        else:
            print(f"  FAILED: {url}")

    # 2. Run Full Pipeline
    print("\n[STEP 2] Full Pipeline Execution (Features & Risk Scoring):")
    results_list = []
    try:
        # ScanEngine expects a list of parsed asset dictionaries
        results_generator = engine.scan_with_progress(parsed_assets)
        
        for update in results_generator:
            # update is a ScanProgress object
            if update.stage == 'complete' and update.result:
                results_list.append(update.result)
            
            if update.is_complete or update.stage == 'done':
                print(f"  Scan Completed. Total Assets: {len(results_list)}")
                break
            
            if update.asset:
                print(f"  Stage: {update.stage:<12} | Asset: {update.asset}")
    except Exception:
        import traceback
        traceback.print_exc()
        return

    if results_list:
        print("\n[STEP 3] Risk Summary:")
        for report in results_list:
            asset_data = report.get('asset', {})
            asset_label = asset_data.get('url') if isinstance(asset_data, dict) else str(asset_data)
            risk_level = report.get('risk_level', 'UNKNOWN')
            risk_score = report.get('risk_score', 0)
            print(f"  - {asset_label:<70} | {risk_level:<10} | Score: {risk_score}")
            if report.get('evidence'):
                # Clean up evidence for display
                clean_evidence = [e.replace('Pattern: ', '').split(':')[0] for e in report.get('evidence', [])]
                print(f"    Indicators: {', '.join(clean_evidence[:3])}")

    print("\n" + "="*80)
    print("VERIFICATION COMPLETE")
    print("="*80)

if __name__ == "__main__":
    final_end_to_end_check()
