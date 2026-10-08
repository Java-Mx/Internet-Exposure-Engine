# AERIS Research & Evaluation Framework

This directory contains the tools and methodology for performing empirical evaluations of the AERIS risk detection engine.

## Evaluation Process

1. **Bootstrap Dataset**: Use the download script to fetch benign and malicious URLs:
   ```bash
   python research/datasets/download_datasets.py
   ```
2. **Run Evaluation**: Run the classification metrics evaluator:
   ```bash
   python research/evaluation/run_evaluation.py
   ```
3. **Analyze Ablations**: Run ablation studies to measure individual tier contributions:
   ```bash
   python research/ablation/tier_ablation.py
   ```
4. **Compare Baselines**: Benchmark AERIS against VT-only and GSB-only baselines:
   ```bash
   python research/benchmarks/baseline_comparison.py
   ```
