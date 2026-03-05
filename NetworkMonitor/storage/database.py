import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "traffic_data.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
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
    conn.close()


def add_alert(alert_type, description):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (alert_type, description) VALUES (?, ?)",
        (alert_type, description)
    )
    conn.commit()
    conn.close()
