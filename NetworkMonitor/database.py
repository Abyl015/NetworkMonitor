import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "traffic_data.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT,
            description TEXT
        )
    '''
    )
    conn.commit()
    conn.close()


def add_alert(alert_type, description):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO alerts (alert_type, description) VALUES (?, ?)',
        (alert_type, description),
    )
    conn.commit()
    conn.close()
