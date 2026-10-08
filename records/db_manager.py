"""
AERIS SQLite Database & Migration Manager
===========================================
Handles single-point connections to the unified 'aeris.db' database,
enables WAL mode/foreign keys, and performs automated versioned schema migrations.
"""
import os
import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Base records directory for database storage
_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(_DB_DIR, exist_ok=True)
DB_PATH = os.path.join(_DB_DIR, "aeris.db")

CURRENT_SCHEMA_VERSION = 1


class SQLiteConnectionWithStatus(sqlite3.Connection):
    def is_connected(self) -> bool:
        return True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


def get_db_connection() -> sqlite3.Connection:
    """
    Establish a connection to the unified SQLite aeris.db.
    Applies WAL journaling mode, enables foreign key support, and runs auto-migrations.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0, factory=SQLiteConnectionWithStatus)
        conn.row_factory = sqlite3.Row
        
        # Enable write-ahead logging (WAL) for high concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        # Enforce foreign key constraints
        conn.execute("PRAGMA foreign_keys=ON")
        
        # Check and apply migrations
        initialize_and_migrate(conn)
        
        return conn
    except Exception as e:
        logger.error(f"[DBManager] Failed to connect to SQLite at {DB_PATH}: {e}")
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        raise


def initialize_and_migrate(conn: sqlite3.Connection) -> None:
    """
    Checks the schema version and applies necessary migrations sequentially.
    """
    cursor = conn.cursor()
    
    # Ensure schema version tracker exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_info (
            key TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    
    # Retrieve current database schema version
    cursor.execute("SELECT version FROM schema_info WHERE key = 'schema_version'")
    row = cursor.fetchone()
    current_version = row["version"] if row else 0
    
    if current_version == 0:
        logger.info("[DBManager] Initializing schema version 1 tables...")
        
        # scans table (records)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT,
                ip TEXT DEFAULT '',
                asn TEXT DEFAULT '',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)")
        
        # reputation_results table (records)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reputation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                gsb_result TEXT,
                virustotal_result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # feedback_reports table (records)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                reported_issue TEXT,
                user_comment TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # audit_trail table (ai_governance)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT UNIQUE NOT NULL,
                layer TEXT,
                target TEXT,
                decision TEXT,
                rationale TEXT,
                input_hash TEXT,
                confidence_composite REAL,
                severity TEXT,
                reviewer TEXT DEFAULT 'AERIS-AUTO',
                evidence_count INTEGER DEFAULT 0,
                campaign_matches TEXT,
                llm_augmented INTEGER DEFAULT 0,
                recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_at_target ON audit_trail(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_at_layer ON audit_trail(layer)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_at_recorded ON audit_trail(recorded_at)")
        
        # threat_memory table (intelligence)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ip TEXT,
                asn TEXT,
                risk_score REAL,
                severity TEXT,
                campaign_ids TEXT,
                evidence_hash TEXT,
                scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tm_domain ON threat_memory(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tm_ip ON threat_memory(ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tm_asn ON threat_memory(asn)")
        
        # graph_nodes table (graph_analysis)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                initial_risk REAL NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # graph_edges table (graph_analysis)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS graph_edges (
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                PRIMARY KEY (source_id, target_id, relation_type)
            )
        """)
        
        cursor.execute("INSERT OR IGNORE INTO schema_info (key, version) VALUES ('schema_version', 1)")
        conn.commit()
        current_version = 1
        logger.info("[DBManager] Schema version 1 initialized successfully.")
        
    # Sequential migrations can be added here as current_version increases:
    # if current_version < 2:
    #     _migrate_to_v2(cursor)
    #     current_version = 2
    #     cursor.execute("UPDATE schema_info SET version = 2 WHERE key = 'schema_version'")
    #     conn.commit()
