
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from risk_scanner import parse_input_list

test_cases = [
    "geographic.org/geographic_names/v/ve_014.html",
    "paperbackswap.com/Sadie-Rose-Adventure-Hilda-Stahl/book/0891076352/",
    "baseball-almanac.com/players/player.php?p=hergeda01",
    "biographi.ca/EN/ShowBio.asp?BioId=41243",
    "deborahfrances-white.com/stand-up.html",
    "example.com",
    "https://example.com/admin"
]

print("--- START TEST ---")
for case in test_cases:
    results = parse_input_list(case)
    if results:
        res = results[0]
        domain = res.get('domain', 'N/A')
        url = res.get('url', 'N/A')
        # Check if path is in the final URL
        path_part = case.split('/', 1)[1] if '/' in case and not case.startswith('http') else ""
        path_preserved = path_part in url if path_part else "No Path in Input"
        print(f"INPUT: {case}")
        print(f"DOMAIN: {domain}")
        print(f"URL: {url}")
        print(f"PATH PRESERVED: {path_preserved}")
        print("-" * 20)
    else:
        print(f"INPUT: {case} -> FAILED")
print("--- END TEST ---")
