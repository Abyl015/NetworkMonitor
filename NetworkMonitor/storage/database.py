import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = STORAGE_DIR / "traffic_data.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                description TEXT
            )
        """)
        conn.commit()


def add_alert(alert_type, description):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (alert_type, description) VALUES (?, ?)",
            (alert_type, description)
        )
        conn.commit()