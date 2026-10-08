"""
AERIS Telemetry, Diagnostics & Metrics Engine
=============================================
Provides SIEM-compatible JSON logging, dynamic Prometheus performance metrics,
and detailed readiness/liveness health endpoints.
"""
from __future__ import annotations

import os
import json
import time
import logging
import psutil
import shutil
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Any, List
from .db import db_manager

logger = logging.getLogger("exposure_discovery.portal.telemetry")

class SIEMJSONFormatter(logging.Formatter):
    """SIEM-compatible formatter that structures logging outputs into JSON packets."""
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "@timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "caller": f"{record.filename}:{record.lineno}",
            "process_id": record.process,
            "thread_name": record.threadName,
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


class EnterpriseMetricsCollector:
    """
    Thread-safe, self-contained Prometheus metric compiler.
    Eliminates external exporter library dependencies.
    """
    def __init__(self):
        self.lock = Lock()
        self.request_counts: Dict[str, int] = {}       # route -> count
        self.active_jobs: int = 0
        self.completed_scans: int = 0
        self.failed_scans: int = 0
        self.exposure_alerts: int = 0
        self.rate_limit_blocks: int = 0
        self.scan_latencies: List[float] = []          # list of durations

    def record_request(self, path: str) -> None:
        with self.lock:
            self.request_counts[path] = self.request_counts.get(path, 0) + 1

    def increment_jobs(self) -> None:
        with self.lock:
            self.active_jobs += 1

    def decrement_jobs(self, success: bool = True) -> None:
        with self.lock:
            self.active_jobs = max(0, self.active_jobs - 1)
            if success:
                self.completed_scans += 1
            else:
                self.failed_scans += 1

    def record_latency(self, duration: float) -> None:
        with self.lock:
            self.scan_latencies.append(duration)
            if len(self.scan_latencies) > 1000:
                self.scan_latencies.pop(0)  # ring buffer

    def record_rate_limit(self) -> None:
        with self.lock:
            self.rate_limit_blocks += 1

    def record_exposure(self) -> None:
        with self.lock:
            self.exposure_alerts += 1

    def export_prometheus(self) -> str:
        """Translates metrics into standard Prometheus ASCII scrape specifications."""
        lines = []
        with self.lock:
            # Active jobs gauge
            lines.append("# HELP aeris_active_jobs Number of exposure scans currently executing.")
            lines.append("# TYPE aeris_active_jobs gauge")
            lines.append(f"aeris_active_jobs {self.active_jobs}")

            # Completed scans counter
            lines.append("# HELP aeris_scans_completed_total Total number of successfully completed scans.")
            lines.append("# TYPE aeris_scans_completed_total counter")
            lines.append(f"aeris_scans_completed_total {self.completed_scans}")

            # Failed scans counter
            lines.append("# HELP aeris_scans_failed_total Total number of aborted or failed scans.")
            lines.append("# TYPE aeris_scans_failed_total counter")
            lines.append(f"aeris_scans_failed_total {self.failed_scans}")

            # Exposure alert count gauge
            lines.append("# HELP aeris_exposure_alerts_discovered Number of high/critical risk exposures discovered.")
            lines.append("# TYPE aeris_exposure_alerts_discovered gauge")
            lines.append(f"aeris_exposure_alerts_discovered {self.exposure_alerts}")

            # Rate limit count
            lines.append("# HELP aeris_rate_limit_blocks_total Total number of blocked requests due to rate limits.")
            lines.append("# TYPE aeris_rate_limit_blocks_total counter")
            lines.append(f"aeris_rate_limit_blocks_total {self.rate_limit_blocks}")

            # Latency summary
            avg_latency = sum(self.scan_latencies) / len(self.scan_latencies) if self.scan_latencies else 0.0
            lines.append("# HELP aeris_scan_latency_seconds_average Running average of exposure scan processing time.")
            lines.append("# TYPE aeris_scan_latency_seconds_average gauge")
            lines.append(f"aeris_scan_latency_seconds_average {avg_latency:.4f}")

            # Request route counters
            lines.append("# HELP aeris_http_requests_total Total number of HTTP gateway requests.")
            lines.append("# TYPE aeris_http_requests_total counter")
            for path, count in self.request_counts.items():
                lines.append(f'aeris_http_requests_total{{path="{path}"}} {count}')

        return "\n".join(lines) + "\n"


class HealthCheckEngine:
    """
    Diagnostics manager validating database connections, system memory limits,
    and filesystem write availability.
    """
    @staticmethod
    def get_system_diagnostics() -> Dict[str, Any]:
        """Calculates system health metadata."""
        # 1. Test database ping
        db_ok = False
        db_details = "unavailable"
        try:
            with db_manager.get_connection() as conn:
                conn.execute("SELECT 1").fetchone()
            db_ok = True
            db_details = "active"
        except Exception as e:
            db_details = str(e)

        # 2. Check Disk space
        total, used, free = shutil.disk_usage(db_manager.db_path.parent)
        disk_ok = (free / total) > 0.05  # >5% space free
        disk_status = "healthy" if disk_ok else "warning: storage low"

        # 3. Check memory allocation
        mem = psutil.virtual_memory()
        mem_ok = mem.percent < 95.0
        mem_status = "healthy" if mem_ok else "warning: memory exhausted"

        overall = "healthy" if (db_ok and disk_ok and mem_ok) else "degraded"

        return {
            "status": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": {"status": "up" if db_ok else "down", "details": db_details},
                "disk": {
                    "status": disk_status,
                    "free_bytes": free,
                    "percent_free": round((free / total) * 100, 2)
                },
                "memory": {
                    "status": mem_status,
                    "percent_used": mem.percent
                }
            }
        }


# Global metrics instance
metrics_collector = EnterpriseMetricsCollector()


def configure_siem_logging(level: str = "INFO") -> None:
    """Configures the root logging outputs to format standard logs as JSON packets."""
    logger_root = logging.getLogger("exposure_discovery")
    logger_root.setLevel(getattr(logging, level.upper()))
    
    # Remove existing stdout handlers
    for h in list(logger_root.handlers):
        logger_root.removeHandler(h)

    sh = logging.StreamHandler()
    sh.setFormatter(SIEMJSONFormatter())
    logger_root.addHandler(sh)
    logger.info("[Telemetry] Structured SIEM JSON logger configured.")
