import os
import sys
import subprocess
import re
from pathlib import Path
from typing import List, Tuple

BASE_DIR = Path(__file__).parent.parent
TARGET_FILES = [
    "intelligence/threat_memory.py",
    "intelligence/correlation_engine.py",
    "risk_scoring/signal_integrator.py"
]

MUTATION_MAP = {
    r"\b>\b": "<=",
    r"\b<\b": ">=",
    r"\b==\b": "!=",
    r"\b!=\b": "==",
    r"\band\b": "or",
    r"\bor\b": "and",
}

class MutationTester:
    def __init__(self, target_file_rel: str):
        self.target_path = BASE_DIR / target_file_rel
        self.test_file = f"tests/unit/test_{Path(target_file_rel).stem}.py"
        self.original_content = self.target_path.read_text(encoding="utf-8")
        
    def run_tests(self) -> bool:
        """Run pytest for this module. Returns True if tests pass, False if they fail."""
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pytest", self.test_file, "-q", "--no-cov"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=150  # Increased from 60s: threat_memory tests take ~70s
            )
            return res.returncode == 0
        except subprocess.TimeoutExpired:
            # Infinite loop mutant - counts as killed
            return False

    def generate_mutants(self) -> List[Tuple[int, str, str, str]]:
        """
        Generate list of mutations: (line_number, pattern, original_line, mutated_line)
        """
        mutants = []
        lines = self.original_content.splitlines()
        
        in_docstring = False
        for idx, line in enumerate(lines):
            stripped = line.strip()
            
            # Track triple-quoted docstring blocks
            if stripped.startswith('"""') or stripped.endswith('"""') or stripped.startswith("'''") or stripped.endswith("'''"):
                if (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 3) or \
                   (stripped.startswith("'''") and stripped.endswith("'''") and len(stripped) > 3):
                    continue
                in_docstring = not in_docstring
                continue
                
            if in_docstring:
                continue
                
            # Skip comments, imports, log statements, and print statements
            if not stripped or stripped.startswith("#") or stripped.startswith("import ") or stripped.startswith("from ") or \
               stripped.startswith("logger.") or stripped.startswith("self.logger.") or stripped.startswith("print(") or \
               stripped.startswith("sys.exit("):
                continue
                
            for pattern, replacement in MUTATION_MAP.items():
                if re.search(pattern, line):
                    mutated_line = re.sub(pattern, replacement, line, count=1)
                    mutants.append((idx + 1, pattern, line, mutated_line))
        return mutants

    def execute_mutation_testing(self) -> dict:
        mutants = self.generate_mutants()
        if not mutants:
            return {"total": 0, "killed": 0, "survived": 0, "score": 100.0}

        print(f"\nRunning Mutation Tests for {self.target_path.name}...")
        print(f"Total potential mutants: {len(mutants)}")
        
        killed = 0
        survived_details = []
        
        # Verify baseline tests pass before mutating
        res = subprocess.run(
            [sys.executable, "-m", "pytest", self.test_file, "-vv", "--no-cov"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=150  # Increased from 60s: some test suites take ~70s
        )
        if res.returncode != 0:
            print("  [ERROR] Baseline tests are failing. Fix tests first.")
            print("STDOUT:")
            print(res.stdout)
            print("STDERR:")
            print(res.stderr)
            return {"error": "Baseline tests failing"}

        lines = self.original_content.splitlines()
        
        for i, (line_num, pattern, orig, mut) in enumerate(mutants):
            # Inject mutant
            mutated_lines = list(lines)
            mutated_lines[line_num - 1] = mut
            self.target_path.write_text("\n".join(mutated_lines), encoding="utf-8")
            
            # Run test suite
            test_passed = self.run_tests()
            
            if test_passed:
                # Mutant survived (bad: tests didn't catch it)
                survived_details.append((line_num, orig.strip(), mut.strip()))
                print(f"  [SURVIVED] Mutant {i+1} on line {line_num}: {orig.strip()} -> {mut.strip()}")
            else:
                # Mutant killed (good: tests failed)
                killed += 1
                
        # Restore original file
        self.target_path.write_text(self.original_content, encoding="utf-8")
        
        total = len(mutants)
        score = (killed / total) * 100.0
        print(f"Mutation testing complete for {self.target_path.name}: {killed}/{total} mutants killed ({score:.1f}% score)")
        
        return {
            "total": total,
            "killed": killed,
            "survived": len(survived_details),
            "score": score,
            "survived_details": survived_details
        }

if __name__ == "__main__":
    overall_score = 0.0
    valid_runs = 0
    for tf in TARGET_FILES:
        try:
            tester = MutationTester(tf)
            result = tester.execute_mutation_testing()
            if "score" in result:
                overall_score += result["score"]
                valid_runs += 1
        except Exception as e:
            print(f"Error testing {tf}: {e}")
            
    if valid_runs > 0:
        avg_score = overall_score / valid_runs
        print(f"\n==================================================")
        print(f"AERIS Overall Mutation Score: {avg_score:.1f}%")
        print(f"==================================================")
        sys.exit(0 if avg_score >= 80.0 else 1)
    sys.exit(1)
