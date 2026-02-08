
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from risk_scanner import AutomatedPipeline

p = AutomatedPipeline()
asset = {
    'domain': 'example.com',
    'ip': None,
    'port': 443,
    'service': 'https',
    'url': 'example.com/admin',
    'full_url': 'https://example.com/admin'
}

print("Running pipeline for single dict asset...")
try:
    results = p.run([asset])
    print("SUCCESS")
    print(f"Risk Level: {results['risk_reports'][0]['risk_level']}")
except Exception as e:
    import traceback
    traceback.print_exc()
