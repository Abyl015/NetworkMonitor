import sqlite3
from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parent
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = STORAGE_DIR / "traffic_data.db"


def get_connection():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(DB_PATH))


def init_db():
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                description TEXT
            )
        """)

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)"
        )

        conn.commit()


def add_alert(alert_type, description):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (alert_type, description) VALUES (?, ?)",
            (alert_type, description)
        )
        conn.commit()


def get_recent_alerts(limit=50):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, alert_type, description FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()