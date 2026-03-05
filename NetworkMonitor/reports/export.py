from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from NetworkMonitor.core.profile_manager import ProfileManager
from NetworkMonitor.database import DB_PATH, init_db


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def export_reports(profile_manager: ProfileManager, engine: Any | None = None) -> tuple[str, str]:
    init_db()

    exports_dir = _project_root() / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = exports_dir / f"alerts_{timestamp}.csv"
    summary_path = exports_dir / f"summary_{timestamp}.md"

    import sqlite3

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, alert_type, description
        FROM alerts
        ORDER BY timestamp ASC
        """
    )
    rows = cursor.fetchall()
    conn.close()

    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["id", "timestamp", "alert_type", "description"])
        writer.writerows(rows)

    total_alerts = len(rows)
    by_type = Counter(str(row[2] or "unknown") for row in rows)

    min_ts = rows[0][1] if rows else "N/A"
    max_ts = rows[-1][1] if rows else "N/A"

    active_profile = profile_manager.get_active_profile()
    sample_factor = active_profile.data.get("sample_factor", "N/A")
    thresholds = active_profile.data.get("thresholds", {})
    ml_cfg = active_profile.data.get("ml", {})

    ib_score = getattr(engine, "ib_score", "N/A") if engine is not None else "N/A"
    ib_level = getattr(engine, "ib_level", "N/A") if engine is not None else "N/A"

    by_type_lines = "\n".join(f"- {k}: {v}" for k, v in sorted(by_type.items())) or "- N/A"

    summary = f"""# NetworkMonitor report summary

## Period
- from: {min_ts}
- to: {max_ts}

## Alerts
- total: {total_alerts}
- by type:
{by_type_lines}

## Active profile
- name: {active_profile.name}
- sample_factor: {sample_factor}
- thresholds: {thresholds}
- ml: {ml_cfg}

## IB
- score: {ib_score}
- level: {ib_level}
"""

    summary_path.write_text(summary, encoding="utf-8")
    return str(csv_path), str(summary_path)
