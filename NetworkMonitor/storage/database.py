import sqlite3
from contextlib import contextmanager

from NetworkMonitor.core.paths import database_path, user_data_dir

STORAGE_DIR = user_data_dir()
DB_PATH = database_path()

ALERT_COLUMNS = {
    "session_id": "INTEGER",
}

SESSION_COLUMNS = {
    "total_ioc_matches": "INTEGER",
    "final_ib_level": "TEXT",
    "threat_level": "TEXT",
    "incident_probability": "TEXT",
    "confidence": "TEXT",
    "total_risk": "REAL",
    "risk_components_json": "TEXT",
    "findings_json": "TEXT",
}


@contextmanager
def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    try:
        yield conn
    finally:
        conn.close()


def _table_columns(conn, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def _add_missing_columns(conn, table_name: str, columns: dict[str, str]) -> None:
    existing = _table_columns(conn, table_name)
    for name, column_type in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {name} {column_type}")


def init_db():
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_id INTEGER,
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
                report_path TEXT,
                total_ioc_matches INTEGER,
                final_ib_level TEXT,
                threat_level TEXT,
                incident_probability TEXT,
                confidence TEXT,
                total_risk REAL,
                risk_components_json TEXT,
                findings_json TEXT
            )
        """)

        _add_missing_columns(conn, "alerts", ALERT_COLUMNS)
        _add_missing_columns(conn, "monitoring_sessions", SESSION_COLUMNS)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session_id ON alerts(session_id)")

        conn.commit()


def add_alert(alert_type, description, session_id=None):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alerts (session_id, alert_type, description) VALUES (?, ?, ?)",
            (session_id, alert_type, description),
        )
        conn.commit()


def get_recent_alerts(limit=50):
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT id, timestamp, alert_type, description FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cursor.fetchall()


def get_alerts_for_session(session_id, limit=200):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT id, timestamp, alert_type, description
            FROM alerts
            WHERE session_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (session_id, limit),
        )
        return cursor.fetchall()


def get_session_alerts(session_id, limit=500):
    return get_alerts_for_session(session_id, limit=limit)


def get_top_alert_types_for_session(session_id, limit=10):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT alert_type, COUNT(*) AS count
            FROM alerts
            WHERE session_id = ?
            GROUP BY alert_type
            ORDER BY count DESC, alert_type ASC
            LIMIT ?
            """,
            (session_id, limit),
        )
        return cursor.fetchall()


def get_alert_types():
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT DISTINCT alert_type
            FROM alerts
            WHERE alert_type IS NOT NULL AND alert_type != ''
            ORDER BY alert_type
        """)
        return [row[0] for row in cursor.fetchall()]


def query_alerts(
    *,
    session_id=None,
    started_from=None,
    started_to=None,
    alert_type=None,
    verdict=None,
    search_text=None,
    limit=500,
):
    where = []
    params = []

    if session_id is not None:
        where.append("session_id = ?")
        params.append(session_id)
    if started_from:
        where.append("timestamp >= ?")
        params.append(started_from)
    if started_to:
        where.append("timestamp <= ?")
        params.append(started_to)
    if alert_type:
        where.append("alert_type = ?")
        params.append(alert_type)
    if verdict:
        verdict_text = str(verdict).lower()
        where.append("(LOWER(description) LIKE ? OR LOWER(description) LIKE ?)")
        params.extend([f"%verdict={verdict_text}%", f"%[verdict] {verdict_text}%"])
    if search_text:
        like = f"%{str(search_text).lower()}%"
        where.append("(LOWER(description) LIKE ? OR LOWER(alert_type) LIKE ?)")
        params.extend([like, like])

    query = """
        SELECT id, timestamp, session_id, alert_type, description
        FROM alerts
    """
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        cursor = conn.execute(query, params)
        return cursor.fetchall()


def _session_values(session: dict) -> tuple:
    return (
        session.get("started_at"),
        session.get("stopped_at"),
        session.get("duration_sec"),
        session.get("profile_name"),
        session.get("interface_name"),
        session.get("total_packets"),
        session.get("total_anomalies"),
        session.get("total_ioc_matches"),
        session.get("total_incidents"),
        session.get("final_ib_score"),
        session.get("final_ib_level"),
        session.get("threat_level"),
        session.get("incident_probability"),
        session.get("confidence"),
        session.get("total_risk"),
        session.get("risk_components_json"),
        session.get("findings_json"),
        session.get("summary_text"),
        session.get("report_path"),
    )


def save_session(session: dict):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO monitoring_sessions (
                started_at, stopped_at, duration_sec,
                profile_name, interface_name,
                total_packets, total_anomalies, total_ioc_matches,
                total_incidents, final_ib_score, final_ib_level,
                threat_level, incident_probability, confidence,
                total_risk, risk_components_json, findings_json,
                summary_text, report_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, _session_values(session))
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


def update_session_report_path(session_id, report_path):
    with get_connection() as conn:
        conn.execute("""
            UPDATE monitoring_sessions
            SET report_path = ?
            WHERE id = ?
        """, (report_path, session_id))
        conn.commit()


def get_last_session_id():
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT id FROM monitoring_sessions
            ORDER BY id DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        return row[0] if row else None


def get_session_by_id(session_id):
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM monitoring_sessions WHERE id=?", (session_id,))
        return cursor.fetchone()


def get_session_record(session_id):
    row = get_session_by_id(session_id)
    return session_row_to_dict(row) if row else None


def get_previous_session_record(session_id):
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT * FROM monitoring_sessions
            WHERE id < ?
            ORDER BY id DESC
            LIMIT 1
        """, (session_id,))
        row = cursor.fetchone()
    return session_row_to_dict(row) if row else None


def session_row_to_dict(row):
    if not row:
        return None
    columns = [
        "id",
        "started_at",
        "stopped_at",
        "duration_sec",
        "profile_name",
        "interface_name",
        "total_packets",
        "total_anomalies",
        "total_incidents",
        "final_ib_score",
        "summary_text",
        "report_path",
        "total_ioc_matches",
        "final_ib_level",
        "threat_level",
        "incident_probability",
        "confidence",
        "total_risk",
        "risk_components_json",
        "findings_json",
    ]
    return {name: row[idx] if idx < len(row) else None for idx, name in enumerate(columns)}
