from pathlib import Path
import csv
import sqlite3
from datetime import datetime

# Берём путь к БД из storage/database.py (чтобы всегда один и тот же)
try:
    from NetworkMonitor.storage.database import DB_PATH
except Exception:
    DB_PATH = Path("traffic_data.db")

def export_reports(out_dir: str = "exports") -> tuple[str, str]:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = out_path / f"alerts_{ts}.csv"
    summary_file = out_path / f"summary_{ts}.txt"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT id, timestamp, alert_type, description FROM alerts ORDER BY id DESC")
    rows = cur.fetchall()

    # CSV
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "timestamp", "alert_type", "description"])
        w.writerows(rows)

    # Summary
    total = len(rows)
    by_type = {}
    for _, _, t, _ in rows:
        by_type[t] = by_type.get(t, 0) + 1

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"Report time: {datetime.now()}\n")
        f.write(f"DB: {DB_PATH}\n")
        f.write(f"Total alerts: {total}\n\n")
        f.write("By type:\n")
        for k in sorted(by_type, key=lambda x: by_type[x], reverse=True):
            f.write(f"- {k}: {by_type[k]}\n")

    conn.close()
    return str(csv_file), str(summary_file)

if __name__ == "__main__":
    c, s = export_reports()
    print("Saved:", c)
    print("Saved:", s)
