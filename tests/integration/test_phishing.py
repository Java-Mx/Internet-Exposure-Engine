"""
Phishing Dataset Test - Rigorous Model Testing

Tests the risk scoring system against a dataset of known phishing/malicious URLs.
Handles various URL formats intelligently (with/without scheme, paths, etc.)
"""

import sys
import csv
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import codecs

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from risk_scoring.heuristic_detector import get_heuristic_detector, HeuristicRiskDetector


def smart_parse_url(url: str) -> Tuple[str, int, str]:
    """
    Intelligently parse URL regardless of format.
    
    Handles:
    - Plain domain: example.com
    - With scheme: http://example.com or https://example.com
    - With path: example.com/path/to/page
    - With port: example.com:8080
    - IP addresses: 192.168.1.1
    
    Returns:
        Tuple of (domain, port, service)
    """
    url = url.strip()
    
    # Default values
    port = 443
    service = 'https'
    
    # Remove scheme
    if url.startswith('https://'):
        url = url[8:]
        port = 443
        service = 'https'
    elif url.startswith('http://'):
        url = url[7:]
        port = 80
        service = 'http'
    elif url.startswith('ftp://'):
        url = url[6:]
        port = 21
        service = 'ftp'
    
    # Remove path (everything after first /)
    if '/' in url:
        url = url.split('/')[0]
    
    # Check for port specification
    if ':' in url:
        parts = url.rsplit(':', 1)
        url = parts[0]
        try:
            port = int(parts[1])
            if port == 80:
                service = 'http'
            elif port == 443:
                service = 'https'
            elif port == 22:
                service = 'ssh'
            elif port == 21:
                service = 'ftp'
        except ValueError:
            pass
    
    # Clean up domain
    domain = url.lower().strip()
    
    return domain, port, service


def load_phishing_csv(filepath: str, max_urls: int = 100) -> List[Dict[str, Any]]:
    """
    Load URLs from phishing CSV file with multiple encoding attempts.
    
    Args:
        filepath: Path to CSV file
        max_urls: Maximum URLs to load
        
    Returns:
        List of parsed URL dictionaries
    """
    urls = []
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                # Try to detect if it's CSV format
                first_line = f.readline()
                f.seek(0)
                
                # Check if it has headers
                has_header = 'url' in first_line.lower() or ',' in first_line
                
                if has_header and ',' in first_line:
                    reader = csv.DictReader(f)
                    for i, row in enumerate(reader):
                        if i >= max_urls:
                            break
                        # Try to find URL column
                        url = (row.get('url') or row.get('URL') or 
                               row.get('domain') or row.get('Domain') or
                               list(row.values())[0] if row else None)
                        
                        if url and len(url) > 3:
                            domain, port, service = smart_parse_url(url)
                            if domain:
                                urls.append({
                                    'original_url': url,
                                    'domain': domain,
                                    'port': port,
                                    'service': service
                                })
                else:
                    # Plain text, one URL per line
                    for i, line in enumerate(f):
                        if i >= max_urls:
                            break
                        url = line.strip()
                        if url and len(url) > 3 and not url.startswith('#'):
                            domain, port, service = smart_parse_url(url)
                            if domain:
                                urls.append({
                                    'original_url': url,
                                    'domain': domain,
                                    'port': port,
                                    'service': service
                                })
                
                if urls:
                    print(f"Loaded {len(urls)} URLs using {encoding} encoding")
                    return urls
                    
        except Exception as e:
            print(f"Failed with {encoding}: {e}")
            continue
    
    return urls


def run_phishing_test(filepath: str = 'malicious_phish.csv', max_urls: int = 50):
    """
    Run comprehensive phishing detection test.
    
    Args:
        filepath: Path to phishing CSV
        max_urls: Max URLs to test
    """
    print("=" * 70)
    print("PHISHING DATASET TEST")
    print(f"Testing: {filepath}")
    print(f"Max URLs: {max_urls}")
    print("=" * 70)
    
    # Load URLs
    print("\n### Loading URLs ###")
    urls = load_phishing_csv(filepath, max_urls)
    
    if not urls:
        print("ERROR: Could not load any URLs from the file")
        print("\nTrying with sample phishing URLs instead...")
        
        # Fallback to sample known phishing URLs
        sample_urls = [
            'testphp.vulnweb.com',
            'demo.testfire.net',
            'login-paypal-secure.suspicious.tk',
            'apple-id-verify.ml',
            'banking-update.gq',
            'secure-login-microsoft.cf',
            'http://phishing.example.com/login.php',
            'https://admin.suspicious-domain.ru',
            'ftp://files.malware-host.cn',
            '192.168.1.100:8080',
        ]
        
        urls = []
        for url in sample_urls:
            domain, port, service = smart_parse_url(url)
            urls.append({
                'original_url': url,
                'domain': domain,
                'port': port,
                'service': service
            })
        
        print(f"Using {len(urls)} sample URLs")
    
    # Initialize detector
    detector = get_heuristic_detector()
    
    # Test each URL
    print("\n### Testing URLs ###\n")
    
    results = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    for i, url_data in enumerate(urls, 1):
        domain = url_data['domain']
        port = url_data['port']
        
        # Analyze
        analysis = detector.get_complete_analysis(domain, port)
        
        risk_score = analysis['risk_score']
        risk_level = analysis['risk_level']
        evidence = analysis['evidence'][:2]  # First 2 evidence items
        
        # Store result
        results[risk_level].append({
            'url': url_data['original_url'],
            'domain': domain,
            'score': risk_score,
            'evidence': evidence
        })
        
        # Print progress for first 20 and summary after
        if i <= 20:
            print(f"{i:3d}. [{risk_level:8}] {risk_score:5.1f}  {domain[:40]}")
            if risk_level in ['CRITICAL', 'HIGH']:
                for ev in evidence:
                    print(f"        -> {ev[:60]}")
        elif i == 21:
            print("... (continuing in background)")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    total = len(urls)
    print(f"\nTotal URLs tested: {total}")
    print(f"\nRisk Distribution:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = len(results[level])
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {level:8}: {count:4} ({pct:5.1f}%) {bar}")
    
    # Detection rate for phishing
    detected = len(results['CRITICAL']) + len(results['HIGH']) + len(results['MEDIUM'])
    detection_rate = (detected / total * 100) if total > 0 else 0
    print(f"\nPhishing Detection Rate: {detected}/{total} = {detection_rate:.1f}%")
    
    # Show top 5 critical/high
    print("\n### Top Detections ###")
    top = results['CRITICAL'][:5] + results['HIGH'][:3]
    for item in top:
        print(f"  {item['score']:5.1f} [{item['domain'][:35]}]")
        for ev in item['evidence']:
            print(f"         {ev[:55]}")
    
    return results


if __name__ == '__main__':
    import sys
    
    filepath = 'malicious_phish.csv'
    max_urls = 50
    
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    if len(sys.argv) > 2:
        max_urls = int(sys.argv[2])
    
    run_phishing_test(filepath, max_urls)
