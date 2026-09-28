"""
operator/db.py
SQLite storage layer for Ghostless Operator.
Guarantees atomic slot allocation, window tracking, and receipt persistence.
"""

import sqlite3
import os
from typing import Optional, Dict, Any, List

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "operator.db")

def get_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH):
    with get_db(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS windows (
            window_id INTEGER PRIMARY KEY,
            start_seq INTEGER NOT NULL,
            size INTEGER NOT NULL,
            opened_at INTEGER NOT NULL,
            seal_deadline INTEGER NOT NULL,
            sealed_at INTEGER DEFAULT 0,
            root TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN'
        );

        CREATE TABLE IF NOT EXISTS slots (
            window_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            leaf TEXT NOT NULL,
            record_p_hex TEXT NOT NULL,
            priv_commit_hex TEXT NOT NULL,
            salt_hex TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ALLOCATED',
            PRIMARY KEY (window_id, seq),
            FOREIGN KEY (window_id) REFERENCES windows(window_id)
        );

        CREATE TABLE IF NOT EXISTS receipts (
            window_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            leaf TEXT NOT NULL,
            sig_hex TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (window_id, seq)
        );
        """)
