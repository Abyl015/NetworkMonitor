# NetworkMonitor/reports/export.py
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from datetime import datetime

import pandas as pd


def export_reports(
    db_path: Path | None = None,
    out_dir: Path | None = None,
    context: dict | None = None,
):
    """
    Экспортирует alerts в CSV + summary.txt
    Возвращает (csv_path, summary_path)
    """
    # db по умолчанию: NetworkMonitor/storage/traffic_data.db (или как у тебя)
    pkg_dir = Path(__file__).resolve().parents[1]  # .../NetworkMonitor
    if db_path is None:
        db_path = pkg_dir / "storage" / "traffic_data.db"

    if out_dir is None:
        # exports рядом с проектом (в корне репо)
        out_dir = pkg_dir.parent / "exports"

    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"alerts_{ts}.csv"
    summary_path = out_dir / f"summary_{ts}.txt"

    if not db_path.exists():
        raise FileNotFoundError(f"DB not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    try:
        df = pd.read_sql_query(
            "SELECT id, timestamp, alert_type, description FROM alerts ORDER BY id DESC",
            conn
        )
    finally:
        conn.close()

    df.to_csv(csv_path, index=False, encoding="utf-8-sig")

    # простая сводка
    total = len(df)
    by_type = df["alert_type"].value_counts().to_dict() if total else {}
    top_lines = "\n".join([f"- {k}: {v}" for k, v in by_type.items()])

    summary = (
        f"Report time: {datetime.now().isoformat()}\n"
        f"DB: {db_path}\n"
        f"Total alerts: {total}\n\n"
        f"By type:\n{top_lines}\n"
    )
    if context:
        summary += "\nContext:\n"
        summary += json.dumps(context, ensure_ascii=False, indent=2)
        summary += "\n"
    summary_path.write_text(summary, encoding="utf-8")

    return str(csv_path), str(summary_path)
