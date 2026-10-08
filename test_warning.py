import sys
import os
from pathlib import Path
import traceback
import warnings

def custom_showwarning(message, category, filename, lineno, file=None, line=None):
    if "sklearn.utils.parallel.delayed" in str(message):
        print("\n" + "="*80)
        print(f"WARNING DETECTED: {category.__name__}: {message}")
        print(f"File: {filename}, Line: {lineno}")
        print("STACK TRACE:")
        traceback.print_stack()
        print("="*80 + "\n")
        sys.stdout.flush()
    original_showwarning(message, category, filename, lineno, file, line)

original_showwarning = warnings.showwarning
warnings.showwarning = custom_showwarning

ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

import research.evaluation.run_phase4 as rp4
rp4.pre_populate_stateful_database = lambda urls, labels: print("Mocked database pre-population.")

os.environ["LIMIT"] = "5"
print("Starting main evaluation runner...")
sys.stdout.flush()
try:
    rp4.main()
except Exception as e:
    print(f"Main exited with exception: {type(e).__name__}: {e}")
    sys.stdout.flush()
