
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from risk_scanner import parse_input_list

test_cases = [
    ("geographic.org/admin", True),
    ("paperbackswap.com/login", True),
    ("example.com/config.php", True),
    ("biographi.ca", False),
    ("https://example.com/git", True)
]

print("--- URL PARSING VERIFICATION ---")
all_passed = True
for case, should_have_path in test_cases:
    results = parse_input_list(case)
    res = results[0]
    url = res.get('url', '')
    domain = res.get('domain', '')
    
    # Check if path is in the url field
    has_path = '/' in case and not case.startswith('http')
    path_preserved = '/' in url.replace('http://', '').replace('https://', '')
    
    status = "PASS" if path_preserved == should_have_path else "FAIL"
    if status == "FAIL": all_passed = False
    
    print(f"INPUT : {case}")
    print(f"DOMAIN: {domain}")
    print(f"URL   : {url}")
    print(f"STATUS: {status}")
    print("-" * 30)

if all_passed:
    print("VERIFICATION SUCCESSFUL: Paths are preserved for all test cases.")
else:
    print("VERIFICATION FAILED: Some paths were lost during parsing.")
