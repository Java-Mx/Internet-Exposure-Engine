"""
NVD CVE Model Test Script

Tests the ML model with real NVD CVE data from the JSON file.
Part of Security Audit - Step 8: High-Risk Validation
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.model_audit import ModelAuditor, SEVERITY_LABELS


def load_nvd_cve_data(filepath: str, max_items: int = 50) -> List[Dict[str, Any]]:
    """Load CVE data from NVD JSON file."""
    print(f"Loading NVD CVE data from: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading file: {e}")
        return []
    
    # Handle different NVD JSON formats
    if 'CVE_Items' in data:
        items = data['CVE_Items'][:max_items]
    elif 'vulnerabilities' in data:
        items = data['vulnerabilities'][:max_items]
    else:
        print(f"Unknown format. Keys: {list(data.keys())}")
        return []
    
    print(f"Found {len(items)} CVE items")
    return items


def extract_cvss_from_cve(cve_item: Dict[str, Any]) -> float:
    """Extract CVSS score from CVE item."""
    # Try NVD 2.0 format
    if 'cve' in cve_item:
        cve = cve_item['cve']
        if 'metrics' in cve:
            metrics = cve['metrics']
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            # Try CVSS v3.0
            if 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            # Try CVSS v2
            if 'cvssMetricV2' in metrics:
                return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
    
    # Try CVE_Items format
    if 'impact' in cve_item:
        impact = cve_item['impact']
        if 'baseMetricV3' in impact:
            return impact['baseMetricV3']['cvssV3']['baseScore']
        if 'baseMetricV2' in impact:
            return impact['baseMetricV2']['cvssV2']['baseScore']
    
    return 0.0


def extract_cve_id(cve_item: Dict[str, Any]) -> str:
    """Extract CVE ID from item."""
    if 'cve' in cve_item:
        cve = cve_item['cve']
        if 'id' in cve:
            return cve['id']
        if 'CVE_data_meta' in cve:
            return cve['CVE_data_meta'].get('ID', 'UNKNOWN')
    return 'UNKNOWN'


def test_model_with_cve_data(filepath: str):
    """Test the ML model with CVE data."""
    print("=" * 70)
    print("NVD CVE MODEL TEST")
    print("=" * 70)
    
    # Load CVE data
    cve_items = load_nvd_cve_data(filepath, max_items=20)
    
    if not cve_items:
        print("No CVE items to process")
        return
    
    # Initialize model auditor
    auditor = ModelAuditor()
    
    # Process each CVE
    results = []
    
    print("\n### Processing CVE Items ###\n")
    
    for i, cve_item in enumerate(cve_items, 1):
        cve_id = extract_cve_id(cve_item)
        cvss_score = extract_cvss_from_cve(cve_item)
        
        # Create test asset with CVE data
        asset = auditor.create_test_asset(
            domain=f"affected-system-{i}.example.com",
            port=443,
            service='https',
            cvss_score=cvss_score if cvss_score > 0 else None
        )
        
        # Get prediction
        result = auditor.predict_with_explanation(asset)
        
        print(f"{i:2d}. {cve_id}")
        print(f"    CVSS: {cvss_score:.1f}")
        print(f"    Prediction: {result.get('prediction_label', 'N/A')}")
        print(f"    Confidence: {result.get('confidence', 0) * 100:.1f}%")
        print()
        
        results.append({
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'ml_prediction': result.get('prediction_label'),
            'confidence': result.get('confidence', 0)
        })
    
    # Summary
    print("\n### SUMMARY ###\n")
    
    # Count by prediction
    predictions = [r['ml_prediction'] for r in results]
    for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        count = predictions.count(level)
        pct = count / len(results) * 100 if results else 0
        print(f"  {level}: {count} ({pct:.1f}%)")
    
    # Correlation with CVSS
    print("\n### CVSS vs ML Correlation ###")
    high_cvss = [r for r in results if r['cvss_score'] >= 7.0]
    high_ml = [r for r in results if r['ml_prediction'] in ['HIGH', 'CRITICAL']]
    
    print(f"  CVEs with CVSS >= 7.0: {len(high_cvss)}")
    print(f"  CVEs with HIGH/CRITICAL ML: {len(high_ml)}")
    
    # Check alignment
    aligned = sum(1 for r in results 
                  if (r['cvss_score'] >= 7.0 and r['ml_prediction'] in ['HIGH', 'CRITICAL'])
                  or (r['cvss_score'] < 7.0 and r['ml_prediction'] in ['LOW', 'MEDIUM']))
    
    alignment_pct = aligned / len(results) * 100 if results else 0
    print(f"  Alignment with CVSS: {alignment_pct:.1f}%")
    
    return results


if __name__ == '__main__':
    filepath = 'nvdcve-2.0-2026.json'
    
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    
    test_model_with_cve_data(filepath)
