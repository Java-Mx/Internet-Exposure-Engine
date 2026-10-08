"""
AERIS SQLite Transaction Integrity Tests
==========================================
Verifies that database operations conform to ACID properties:
- Transactions rollback correctly on exceptions.
- Data persists on successful commit.
- WAL (Write-Ahead Logging) mode is enabled for concurrency.
"""
import os
import sqlite3
import pytest
import threading
from pathlib import Path
import records.db_manager
from records.db_manager import get_db_connection


@pytest.fixture(autouse=True)
def temp_db_isolation(tmp_path):
    """Isolate the database path to a temporary directory for tests."""
    original_path = records.db_manager.DB_PATH
    temp_file = tmp_path / "test_aeris.db"
    records.db_manager.DB_PATH = str(temp_file)
    yield temp_file
    # Cleanup and restore
    if temp_file.exists():
        try:
            temp_file.unlink()
        except OSError:
            pass
    records.db_manager.DB_PATH = original_path


def test_wal_mode_enabled():
    """Ensure WAL mode is enabled on connection initialization."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        assert mode.lower() == "wal"


def test_transaction_rollback_on_exception():
    """Ensure transaction rolls back completely when an exception occurs before commit."""
    with get_db_connection() as conn:
        # Verify starting state is empty
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        assert cursor.fetchone()[0] == 0

    try:
        # Perform some database operations inside a manual transaction
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            
            cursor.execute(
                "INSERT INTO scans (domain, risk_score, risk_level, confidence, reasoning) VALUES (?, ?, ?, ?, ?)",
                ("rollback-test.com", 75.0, "HIGH", 0.85, "First insert")
            )
            
            # Trigger an intentional unique constraint violation or exception
            # audit_trail requires unique entry_id
            cursor.execute(
                "INSERT INTO audit_trail (entry_id, target) VALUES (?, ?)",
                ("DUPLICATE-ID", "target1.com")
            )
            cursor.execute(
                "INSERT INTO audit_trail (entry_id, target) VALUES (?, ?)",
                ("DUPLICATE-ID", "target2.com")  # Unique constraint violation
            )
            
            conn.commit()
    except sqlite3.IntegrityError:
        # Catch expected integrity constraint error and rollback
        pass

    # Re-verify that NO scans or audit logs were persisted
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        assert cursor.fetchone()[0] == 0
        
        cursor.execute("SELECT COUNT(*) FROM audit_trail")
        assert cursor.fetchone()[0] == 0


def test_transaction_commit_success():
    """Ensure standard commits persist data successfully."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Start transaction
        cursor.execute("BEGIN TRANSACTION")
        cursor.execute(
            "INSERT INTO scans (domain, risk_score, risk_level, confidence, reasoning) VALUES (?, ?, ?, ?, ?)",
            ("commit-test.com", 12.0, "LOW", 0.95, "Should succeed")
        )
        conn.commit()
        
    # Re-verify persistence from a separate connection
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans WHERE domain = ?", ("commit-test.com",))
        assert cursor.fetchone()[0] == 1


def test_concurrent_readers_writers():
    """
    Ensure multiple threads can read and write concurrently under WAL mode
    without throwing sqlite3.OperationalError: database is locked.
    """
    # Initialize schema once before spawning threads
    with get_db_connection() as conn:
        pass

    errors = []
    
    def run_writer(thread_id):
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                for i in range(10):
                    cursor.execute("BEGIN IMMEDIATE TRANSACTION")
                    cursor.execute(
                        "INSERT INTO scans (domain, risk_score, risk_level, confidence, reasoning) VALUES (?, ?, ?, ?, ?)",
                        (f"thread-{thread_id}-domain-{i}.com", 50.0, "MEDIUM", 0.7, "Thread write")
                    )
                    conn.commit()
        except Exception as e:
            errors.append(e)

    def run_reader():
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                for _ in range(50):
                    cursor.execute("SELECT COUNT(*) FROM scans")
                    cursor.fetchone()
        except Exception as e:
            errors.append(e)

    threads = []
    # Create 3 writers and 3 readers running concurrently
    for t_id in range(3):
        threads.append(threading.Thread(target=run_writer, args=(t_id,)))
        threads.append(threading.Thread(target=run_reader))

    # Start and join
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Ensure no operational errors were raised
    assert len(errors) == 0, f"Concurrent database operations raised errors: {errors}"
