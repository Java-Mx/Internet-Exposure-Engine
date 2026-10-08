"""
AERIS Asynchronous Scan Scheduling Core
=======================================
Implements a self-contained, thread-safe background job queue and worker pool,
decoupling high-latency network scanning from synchronous API gateway requests.
"""
from __future__ import annotations

import uuid
import queue
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from .tenancy import set_tenant_context, clear_tenant_context
from .telemetry import metrics_collector
from .workflow import WorkflowManager
from .governance import EvidenceSigner

logger = logging.getLogger("exposure_discovery.portal.scheduler")

class TaskScheduler:
    """
    Thread-safe job orchestrator executing exposure scans using a background worker thread.
    """
    def __init__(self, max_workers: int = 2):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.job_lock = threading.Lock()
        self.task_queue: queue.Queue = queue.Queue()
        self.max_workers = max_workers
        self.workers: list[threading.Thread] = []
        self._running = True
        self._start_workers()

    def _start_workers(self) -> None:
        """Starts background worker daemon threads."""
        for i in range(self.max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"AERIS-Worker-{i}", daemon=True)
            t.start()
            self.workers.append(t)
        logger.info(f"[Scheduler] Background worker pool started with {self.max_workers} threads.")

    def _worker_loop(self) -> None:
        """Watch the task queue, pop scan jobs, and execute the scoring pipeline."""
        from risk_scoring.heuristic_detector import HeuristicRiskDetector
        detector = HeuristicRiskDetector()

        while self._running:
            try:
                # Block for a short duration to support clean shutdowns
                job_id = self.task_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            with self.job_lock:
                job = self.jobs.get(job_id)
            
            if not job:
                self.task_queue.task_done()
                continue

            # Update job status
            self._update_job_status(job_id, "RUNNING")
            metrics_collector.increment_jobs()
            start_time = datetime.now(timezone.utc)

            # Establish tenant context for the executing thread
            tenant_id = job["tenant_id"]
            set_tenant_context(tenant_id)

            success = False
            try:
                target = job["target"]
                port = job["port"]
                
                logger.info(f"[Scheduler] Thread starting scan {job_id} for target '{target}' under tenant '{tenant_id}'.")
                
                # Execute Pipeline
                result = detector.get_complete_analysis(target, port=port)
                
                # Cryptographically sign the evidence
                signature = EvidenceSigner.sign_result(result)
                result["signature"] = signature

                # Auto-escalation workflow integration:
                # If risk_score >= 50 (High/Critical), auto-register in incident workflow
                score = result.get("risk_score", 0.0)
                level = result.get("risk_level", "LOW")
                
                if score >= 50.0:
                    metrics_collector.record_exposure()
                    WorkflowManager.register_new_exposure(target, "Web Exposure Alert", level)

                # Persist completed metrics
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                metrics_collector.record_latency(elapsed)

                with self.job_lock:
                    job["status"] = "COMPLETED"
                    job["completed_at"] = datetime.now(timezone.utc).isoformat()
                    job["result"] = result
                success = True
                logger.info(f"[Scheduler] Scan {job_id} for '{target}' completed successfully in {elapsed:.2f}s.")

            except Exception as e:
                logger.error(f"[Scheduler] Scan {job_id} failed: {e}", exc_info=True)
                with self.job_lock:
                    job["status"] = "FAILED"
                    job["completed_at"] = datetime.now(timezone.utc).isoformat()
                    job["error"] = str(e)
            finally:
                metrics_collector.decrement_jobs(success=success)
                clear_tenant_context()
                self.task_queue.task_done()

    def _update_job_status(self, job_id: str, status: str) -> None:
        with self.job_lock:
            if job_id in self.jobs:
                self.jobs[job_id]["status"] = status
                self.jobs[job_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    def submit_scan(self, target: str, port: int, tenant_id: str) -> str:
        """Pushes a new scan into the thread queue. Returns unique Job ID."""
        job_id = str(uuid.uuid4())
        job = {
            "id": job_id,
            "tenant_id": tenant_id,
            "target": target,
            "port": port,
            "status": "PENDING",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "result": None,
            "error": None
        }
        with self.job_lock:
            self.jobs[job_id] = job

        self.task_queue.put(job_id)
        logger.info(f"[Scheduler] Scan job {job_id} submitted to queue for target '{target}'.")
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves details, progress, or outcomes for a scan job."""
        with self.job_lock:
            return self.jobs.get(job_id)

    def shutdown(self) -> None:
        """Gracefully terminates worker threads."""
        self._running = False
        logger.info("[Scheduler] Shutdown initiated for background workers.")

# Global instance
scan_scheduler = TaskScheduler()
