"""
CVE Model Test - Simulated Data
Tests ML model with various CVE severity scenarios.
"""

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.model_audit import ModelAuditor

def run_test():
    auditor = ModelAuditor()

    # Simulate CVE scenarios with different CVSS scores
    test_cases = [
        {'name': 'CVE-2026-0001', 'cvss': 9.8, 'port': 443, 'service': 'https'},
        {'name': 'CVE-2026-0002', 'cvss': 8.5, 'port': 3306, 'service': 'mysql'},
        {'name': 'CVE-2026-0003', 'cvss': 7.5, 'port': 22, 'service': 'ssh'},
        {'name': 'CVE-2026-0004', 'cvss': 6.1, 'port': 80, 'service': 'http'},
        {'name': 'CVE-2026-0005', 'cvss': 4.3, 'port': 443, 'service': 'https'},
        {'name': 'CVE-2026-0006', 'cvss': 2.1, 'port': 443, 'service': 'https'},
        {'name': 'CVE-2026-0007', 'cvss': 9.9, 'port': 23, 'service': 'telnet'},
        {'name': 'CVE-2026-0008', 'cvss': 8.0, 'port': 3389, 'service': 'rdp'},
    ]

    print('='*70)
    print('CVE TEST RESULTS')
    print('='*70)

    for tc in test_cases:
        asset = auditor.create_test_asset(
            domain=f"vuln-{tc['name'].lower()}.example.com",
            port=tc['port'],
            service=tc['service'],
            cvss_score=tc['cvss']
        )
        result = auditor.predict_with_explanation(asset)
        label = result.get('prediction_label', 'N/A')
        conf = result.get('confidence', 0) * 100
        print(f"{tc['name']:15} CVSS: {tc['cvss']:4.1f}  Port: {tc['port']:5}  -> {label:10} ({conf:.0f}%)")

    print('='*70)

if __name__ == '__main__':
    run_test()
