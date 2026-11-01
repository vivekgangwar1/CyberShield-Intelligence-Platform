import sqlite3
from pathlib import Path

# Database file location
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "outputs" / "cybershield.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            details TEXT,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_scan(scan_type, target, prediction, confidence=None, details=None):
    connection = get_connection()

    connection.execute("""
        INSERT INTO scan_history
        (scan_type, target, prediction, confidence, details)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_type, target, prediction, confidence, details))

    connection.commit()
    connection.close()