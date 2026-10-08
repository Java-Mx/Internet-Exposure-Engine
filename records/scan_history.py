
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any


_DB_DIR  = os.path.join(os.path.dirname(__file__))
_DB_PATH = os.path.join(_DB_DIR, "scan_history.db")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    scanned_at  TEXT    NOT NULL,
    score       REAL    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  REAL    NOT NULL DEFAULT 0.5,
    findings    TEXT    NOT NULL DEFAULT '[]',
    report_json TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scanned_at ON scans(scanned_at DESC);
"""

_INSERT_SQL = (
    "INSERT INTO scans (domain, url, scanned_at, score, severity, confidence, findings, report_json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)


def _connect() -> sqlite3.Connection:
    """Open (or create) the SQLite scan history database with WAL mode."""
    from records.db_manager import SQLiteConnectionWithStatus
    os.makedirs(_DB_DIR, exist_ok=True)
    conn = None
    try:
        conn = sqlite3.connect(_DB_PATH, check_same_thread=False, factory=SQLiteConnectionWithStatus)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_CREATE_TABLE_SQL)
        conn.commit()
        return conn
    except Exception:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        raise


def _domain_from_url(url: str) -> str:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or url).lower().lstrip("www.")
    except Exception:
        return url.lower()


def save_scan(
    url: str,
    score: float,
    severity: str,
    confidence: float,
    evidence: List[str],
    full_result: Dict[str, Any],
) -> int:
    domain   = _domain_from_url(url)
    ts       = datetime.now().isoformat(sep=" ", timespec="seconds")
    findings = json.dumps(evidence[:10])
    report   = json.dumps(full_result, default=str)

    import time
    max_retries = 3
    for attempt in range(max_retries):
        conn = _connect()
        try:
            cur = conn.execute(
                _INSERT_SQL,
                (domain, url, ts, float(score), severity, float(confidence), findings, report),
            )
            conn.commit()
            return int(cur.lastrowid)
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                time.sleep(0.1 * (2 ** attempt))
                continue
            raise
        finally:
            conn.close()
    return -1


def get_last_scan(domain: str) -> Optional[Dict[str, Any]]:
    bare = domain.lower().lstrip("www.")
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE domain = ? ORDER BY scanned_at DESC LIMIT 1",
            (bare,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_history(limit: int = 100) -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, domain, url, scanned_at, score, severity, confidence, findings "
            "FROM scans ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["findings"] = json.loads(d["findings"])
            except Exception:
                d["findings"] = []
            result.append(d)
        return result
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["findings"]    = json.loads(d["findings"])
            d["report_json"] = json.loads(d["report_json"])
        except Exception:
            pass
        return d
    finally:
        conn.close()


def get_domain_history(domain: str) -> List[Dict[str, Any]]:
    bare = domain.lower().lstrip("www.")
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, scanned_at, score, severity, confidence FROM scans "
            "WHERE domain = ? ORDER BY scanned_at ASC",
            (bare,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()