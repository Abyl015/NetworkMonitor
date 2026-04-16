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

        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT,
                stopped_at TEXT,
                duration_sec INTEGER,
                profile_name TEXT,
                interface_name TEXT,
                total_packets INTEGER,
                total_anomalies INTEGER,
                total_incidents INTEGER,
                final_ib_score INTEGER,
                summary_text TEXT,
                report_path TEXT
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
            "SELECT id, timestamp, alert_type, description FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()


def save_session(session: dict):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO monitoring_sessions (
                started_at, stopped_at, duration_sec,
                profile_name, interface_name,
                total_packets, total_anomalies, total_incidents,
                final_ib_score, summary_text, report_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.get("started_at"),
            session.get("stopped_at"),
            session.get("duration_sec"),
            session.get("profile_name"),
            session.get("interface_name"),
            session.get("total_packets"),
            session.get("total_anomalies"),
            session.get("total_incidents"),
            session.get("final_ib_score"),
            session.get("summary_text"),
            session.get("report_path"),
        ))
        conn.commit()


def get_sessions(limit=50):
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT id, started_at, duration_sec, profile_name,
                   interface_name, final_ib_score
            FROM monitoring_sessions
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()


def get_session_by_id(session_id):
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT * FROM monitoring_sessions WHERE id=?
        """, (session_id,))
        return cursor.fetchone()