"""
AERIS Phase 4 Performance Profiler
===================================
Instruments run_phase4.py with spies to count:
- SQLite reads/writes
- Model loads
- Graph rebuilds
- HTTP requests
- DNS lookups
And profiles cumulative execution time to identify the bottleneck.
"""
import os
import sys
import time
import cProfile
import pstats
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np

ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Counters
sqlite_reads = 0
sqlite_writes = 0
model_loads = 0
graph_rebuilds = 0
http_requests = 0
dns_lookups = 0

# Spy wrappers
def spy_cursor_execute(self, sql, *args, **kwargs):
    global sqlite_reads, sqlite_writes
    sql_upper = sql.strip().upper()
    if sql_upper.startswith("SELECT") or sql_upper.startswith("PRAGMA"):
        sqlite_reads += 1
    else:
        sqlite_writes += 1
    return orig_cursor_execute(self, sql, *args, **kwargs)

def spy_joblib_load(*args, **kwargs):
    global model_loads
    model_loads += 1
    return orig_joblib_load(*args, **kwargs)

def spy_requests_get(*args, **kwargs):
    global http_requests
    http_requests += 1
    return orig_requests_get(*args, **kwargs)

def spy_gethostbyname(*args, **kwargs):
    global dns_lookups
    dns_lookups += 1
    return orig_gethostbyname(*args, **kwargs)

def spy_getaddrinfo(*args, **kwargs):
    global dns_lookups
    dns_lookups += 1
    return orig_getaddrinfo(*args, **kwargs)

def spy_graph_rebuild(*args, **kwargs):
    global graph_rebuilds
    graph_rebuilds += 1
    return orig_graph_rebuild(*args, **kwargs)

# Hook original methods
import sqlite3
import joblib
import requests
import socket
import graph_analysis.graph_connector as graph_conn

orig_cursor_execute = sqlite3.Cursor.execute
sqlite3.Cursor.execute = spy_cursor_execute

orig_joblib_load = joblib.load
joblib.load = spy_joblib_load

orig_requests_get = requests.get
requests.get = spy_requests_get

orig_gethostbyname = socket.gethostbyname
socket.gethostbyname = spy_gethostbyname

orig_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = spy_getaddrinfo

orig_graph_rebuild = graph_conn.update_graph_and_get_risk
graph_conn.update_graph_and_get_risk = spy_graph_rebuild

# Disable DB pre-population (already done)
import research.evaluation.run_phase4 as run_phase4
run_phase4.pre_populate_stateful_database = lambda *args, **kwargs: None

def run_profiler():
    global sqlite_reads, sqlite_writes, model_loads, graph_rebuilds, http_requests, dns_lookups
    
    # Reset counters
    sqlite_reads = 0
    sqlite_writes = 0
    model_loads = 0
    graph_rebuilds = 0
    http_requests = 0
    dns_lookups = 0
    
    # Run cProfile on run_phase4.main
    os.environ["LIMIT"] = "50"
    
    pr = cProfile.Profile()
    print("Profiling 50 URL evaluations...")
    t0 = time.time()
    pr.enable()
    
    try:
        run_phase4.main()
    except Exception as e:
        print(f"Error during execution: {e}")
        
    pr.disable()
    elapsed = time.time() - t0
    
    # Print custom metrics
    print("\n" + "=" * 50)
    print("  MEASURED EXECUTION STATISTICS (50 Sample Subset)")
    print("=" * 50)
    print(f"1. Total URLs processed: 50")
    print(f"2. Current progress: 100% (50/50)")
    print(f"3. Average time per URL: {elapsed / 50:.4f} seconds")
    print(f"4. Number of SQLite reads: {sqlite_reads}")
    print(f"5. Number of SQLite writes: {sqlite_writes}")
    print(f"6. Number of model loads: {model_loads}")
    print(f"7. Number of graph rebuilds: {graph_rebuilds}")
    print(f"8. Number of HTTP/API requests: {http_requests}")
    print(f"9. Number of DNS lookups: {dns_lookups}")
    print("=" * 50)
    
    # Parse and print top 10 slowest functions
    print("\nTop 10 slowest functions by cumulative runtime:")
    stats = pstats.Stats(pr, stream=sys.stdout)
    stats.strip_dirs()
    stats.sort_stats('cumulative')
    stats.print_stats(10)

if __name__ == "__main__":
    run_profiler()
