"""
AERIS Database Access Layer
===========================
Implements the DB access layer using SQLite (backed by aeris.db)
with full backward compatibility for all public functions and signatures.
"""
import os
import logging
import sqlite3
from datetime import datetime
from records.db_manager import get_db_connection

logger = logging.getLogger(__name__)

# Fallback path if SQLite fails
FALLBACK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "records", "data")
os.makedirs(FALLBACK_DIR, exist_ok=True)
FALLBACK_CSV = os.path.join(FALLBACK_DIR, "offline_scans_fallback.csv")


def _get_connection():
    """Establish connection to the unified SQLite database."""
    try:
        return get_db_connection()
    except Exception as e:
        logger.error(f"[Database] Error connecting to SQLite Database: {e}")
        return None


def save_scan(url: str, score: float, severity: str, confidence: float, evidence: list, full_result: dict = None, ip: str = "", asn: str = ""):
    """Saves a scan result to the SQLite database."""
    try:
        from urllib.parse import urlparse
        raw_host = urlparse(url if "://" in url else f"http://{url}").hostname or url
        domain = raw_host.lower().lstrip("www.")
    except Exception:
        domain = url

    reasoning = "\n".join(evidence) if evidence else ""
    gsb_res = "FLAGGED" if any("GOOGLE SAFE BROWSING" in e for e in evidence) else None
    vt_res = "FLAGGED" if any("VIRUSTOTAL" in e for e in evidence) else None

    # Try to extract IP/ASN from full_result if not explicitly passed
    if not ip and full_result:
        ip = full_result.get("ip", "")
    if not asn and full_result:
        asn = full_result.get("asn", "")

    conn = _get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (domain, risk_score, risk_level, confidence, reasoning, ip, asn) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (domain, float(score), severity, float(confidence), reasoning, ip, asn)
            )

            if gsb_res or vt_res:
                cursor.execute(
                    "INSERT INTO reputation_results (domain, gsb_result, virustotal_result) VALUES (?, ?, ?)",
                    (domain, gsb_res, vt_res)
                )

            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[Database] Failed to insert record into SQLite: {e}")
            _save_to_fallback(domain, url, score, severity, confidence, reasoning)
            return False
        finally:
            conn.close()
    else:
        _save_to_fallback(domain, url, score, severity, confidence, reasoning)
        return False


def _map_db_row_to_expected(row):
    """Maps SQLite Row dictionary keys to the expected history format."""
    ts_str = row["timestamp"]
    if isinstance(ts_str, str):
        try:
            # Parse from standard SQLite format
            ts_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            ts_formatted = ts_dt.strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            ts_formatted = ts_str
    elif isinstance(ts_str, datetime):
        ts_formatted = ts_str.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        ts_formatted = str(ts_str)

    return {
        "id": row["id"],
        "domain": row["domain"],
        "url": row["domain"],
        "score": row["risk_score"],
        "severity": row["risk_level"],
        "confidence": row["confidence"],
        "scanned_at": ts_formatted,
        "findings": row["reasoning"].split("\n") if row["reasoning"] else []
    }


def get_history(limit=50):
    """Retrieve the recent scan history from SQLite."""
    conn = _get_connection()
    history = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            history = [_map_db_row_to_expected(r) for r in rows]
        except Exception as e:
            logger.error(f"[Database] Failed to fetch history from SQLite: {e}")
        finally:
            conn.close()
    return history


def get_scan_by_id(scan_id):
    """Retrieve a specific scan by ID."""
    conn = _get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row:
                return _map_db_row_to_expected(row)
        except Exception as e:
            logger.error(f"[Database] Failed to fetch scan by ID from SQLite: {e}")
        finally:
            conn.close()
    return None


def get_last_scan(domain):
    """Retrieve the most recent scan for a specific domain."""
    conn = _get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE domain = ? ORDER BY timestamp DESC LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                return _map_db_row_to_expected(row)
        except Exception as e:
            logger.error(f"[Database] Failed to fetch last scan from SQLite: {e}")
        finally:
            conn.close()
    return None


def get_domain_history(domain):
    """Retrieve all history for a specific domain."""
    conn = _get_connection()
    history = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE domain = ? ORDER BY timestamp DESC", (domain,))
            rows = cursor.fetchall()
            history = [_map_db_row_to_expected(r) for r in rows]
        except Exception as e:
            logger.error(f"[Database] Failed to fetch domain history from SQLite: {e}")
        finally:
            conn.close()
    return history


def log_feedback(domain: str, predicted_risk: float, predicted_severity: str, user_report_type: str, evidence_snapshot: list, reputation_snapshot: dict, user_comment: str, client_ip: str):
    """Log user feedback into SQLite."""
    conn = _get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO feedback_reports (domain, reported_issue, user_comment) VALUES (?, ?, ?)",
                (domain, user_report_type, str(user_comment) if user_comment else None)
            )
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[Database] Failed to insert feedback into SQLite: {e}")
            return False
        finally:
            conn.close()
    return False


def get_community_warnings(domain):
    """Return count of feedback reports that say site is more dangerous."""
    conn = _get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM feedback_reports WHERE domain = ? AND reported_issue LIKE ?", (domain, "%more dangerous%"))
            row = cursor.fetchone()
            return row[0] if row else 0
        except Exception as e:
            logger.error(f"[Database] Failed to fetch community warnings from SQLite: {e}")
            return 0
        finally:
            conn.close()
    return 0


def get_scan_timeline(domain: str) -> list:
    """Retrieve chronological scan history for a specific domain with timestamps, scores, and severity."""
    conn = _get_connection()
    history = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT timestamp, risk_score, risk_level FROM scans WHERE domain = ? ORDER BY timestamp ASC",
                (domain,)
            )
            rows = cursor.fetchall()
            for r in rows:
                ts_str = r["timestamp"]
                if isinstance(ts_str, str):
                    try:
                        ts_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                        ts_formatted = ts_dt.strftime("%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        ts_formatted = ts_str
                elif isinstance(ts_str, datetime):
                    ts_formatted = ts_str.strftime("%Y-%m-%dT%H:%M:%S")
                else:
                    ts_formatted = str(ts_str)

                history.append({
                    "timestamp": ts_formatted,
                    "risk_score": r["risk_score"],
                    "severity": r["risk_level"]
                })
        except Exception as e:
            logger.error(f"[Database] Failed to fetch scan timeline from SQLite: {e}")
        finally:
            conn.close()
    return history


def _save_to_fallback(domain, url, risk_score, risk_level, confidence, reasoning):
    import csv
    file_exists = os.path.isfile(FALLBACK_CSV)
    try:
        with open(FALLBACK_CSV, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["scanned_at", "domain", "url", "score", "severity", "confidence", "findings"])
            writer.writerow([
                datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                domain,
                url,
                risk_score,
                risk_level,
                confidence,
                reasoning
            ])
    except Exception as e:
        logger.error(f"[Database] CRITICAL: Fallback CSV write failed: {e}")
