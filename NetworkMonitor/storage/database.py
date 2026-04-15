import sqlite3
from contextlib import contextmanager
from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parent
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = STORAGE_DIR / "traffic_data.db"


@contextmanager
def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                description TEXT
            )
        """)

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)"
        )

        conn.commit()


def add_alert(alert_type, description):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alerts (alert_type, description) VALUES (?, ?)",
            (alert_type, description)
        )
        conn.commit()


def get_recent_alerts(limit=50):
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT id, timestamp, alert_type, description "
            "FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()