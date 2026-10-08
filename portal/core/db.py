"""
AERIS Core Database Engine
==========================
Persistent SQLite connection manager and schema initialization for the
enterprise multi-tenant platform.
"""
from __future__ import annotations

import os
import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("exposure_discovery.portal.db")

# Dynamic DB Path mapping
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "records" / "data" / "ierss.db"

class DatabaseManager:
    """
    Manages connections and transactions to the SQLite core database.
    Integrates all enterprise tables for RBAC, multi-tenancy, and workflows.
    """
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schemas()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a configured sqlite3 connection with WAL mode enabled."""
        from records.db_manager import SQLiteConnectionWithStatus
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0, factory=SQLiteConnectionWithStatus)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except Exception:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            raise

    def _init_schemas(self) -> None:
        """Creates the enterprise relational tables if they do not exist."""
        try:
            with self.get_connection() as conn:
                # 1. Tenants Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tenants (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        industry TEXT NOT NULL DEFAULT 'other',
                        compliance_scope TEXT NOT NULL DEFAULT '[]',
                        created_at TEXT NOT NULL
                    )
                """)

                # 2. Users Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('CISO', 'SOC_MANAGER', 'ANALYST', 'AUDITOR')),
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                    )
                """)

                # 3. Workflow Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS workflow (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        exposure_type TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('DISCOVERED', 'UNDER_REVIEW', 'CONFIRMED', 'MITIGATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE')),
                        assigned_to TEXT,
                        sla_deadline TEXT NOT NULL,
                        notes TEXT NOT NULL DEFAULT '',
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                    )
                """)

                # 4. Analyst Feedback Table (Operational Feedback Loops)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS analyst_feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        signal_id TEXT NOT NULL,
                        feedback_type TEXT NOT NULL CHECK(feedback_type IN ('FALSE_POSITIVE', 'FALSE_NEGATIVE', 'CORRECTED_SEVERITY')),
                        comments TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
                        UNIQUE(hostname, signal_id)
                    )
                """)

                # 5. Cryptographic Evidence Signatures
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        scan_hash TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        signed_at TEXT NOT NULL,
                        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                    )
                """)

                # 6. Immutable Governance Audit Trail
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_trail (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        username TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        details TEXT NOT NULL DEFAULT '',
                        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                    )
                """)
                conn.commit()
                logger.info("[DatabaseManager] Enterprise schemas initialized successfully.")
        except Exception as e:
            logger.critical(f"[DatabaseManager] Schema initialization failed: {e}")

# Global Instance
db_manager = DatabaseManager()
