from __future__ import annotations

import html
import json
import re
from collections import Counter
from datetime import datetime
from typing import Any

from NetworkMonitor.storage.database import (
    get_previous_session_record,
    get_session_alerts,
    get_session_record,
    get_top_alert_types_for_session,
    init_db,
)


def format_duration(seconds: int | None) -> str:
    seconds = int(seconds or 0)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _safe(value: Any, default: str = "N/A") -> str:
    if value is None or value == "":
        return default
    return html.escape(str(value))


def _parse_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed is not None else fallback


def _alert_dicts(rows: list[tuple]) -> list[dict[str, Any]]:
    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "alert_type": row[2],
            "description": row[3],
        }
        for row in rows
    ]


def _top_suspicious_values(alerts: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    values: Counter[str] = Counter()
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    token_patterns = [
        ("dport", re.compile(r"\bdport=([0-9]+)\b", re.IGNORECASE)),
        ("host", re.compile(r"\bhost=([^|\s]+)", re.IGNORECASE)),
        ("src", re.compile(r"\bsrc=([^|\s]+)", re.IGNORECASE)),
        ("dst", re.compile(r"\bdst=([^|\s]+)", re.IGNORECASE)),
    ]

    for alert in alerts:
        desc = alert.get("description") or ""
        for ip in ip_re.findall(desc):
            values[f"IP: {ip}"] += 1
        for label, pattern in token_patterns:
            for match in pattern.findall(desc):
                values[f"{label}: {match.strip()}"] += 1

    return values.most_common(limit)


def _recommendations(score: Any, findings: list[str], summary: str | None, top_alert_types: list[tuple]) -> list[str]:
    recommendations: list[str] = []
    text = " ".join(
        [summary or "", " ".join(findings or []), " ".join(t or "" for t, _ in top_alert_types)]
    ).lower()

    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        numeric_score = None

    if numeric_score is not None and numeric_score < 60:
        recommendations.append("Провести углубленную проверку сегмента сети из-за сниженного IB Score.")
    if "ioc" in text:
        recommendations.append("Проверить узлы и соединения, связанные с IOC-срабатываниями.")
    if "scan" in text or "скан" in text:
        recommendations.append("Проверить источники сканирования портов и ограничить ненужные входящие соединения.")
    if "dos" in text or "flood" in text:
        recommendations.append("Проверить всплески трафика и настроить фильтрацию для flood-паттернов.")
    if "ml" in text or "anomal" in text or "аномал" in text:
        recommendations.append("Просмотреть аномальные соединения и при необходимости обновить профиль ML.")
    if not recommendations:
        recommendations.append("Критичных действий по данным отчета не требуется; продолжайте наблюдение.")

    return recommendations[:5]


def _format_delta(value: Any) -> str:
    if value is None:
        return "N/A"
    sign = "+" if value > 0 else ""
    return f"{sign}{value}"


def _comparison(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any] | None:
    if not previous:
        return None

    def delta(field: str) -> Any:
        cur = current.get(field)
        prev = previous.get(field)
        if cur is None or prev is None:
            return None
        return cur - prev

    return {
        "previous_id": previous.get("id"),
        "ib_score_delta": delta("final_ib_score"),
        "incidents_delta": delta("total_incidents"),
        "anomalies_delta": delta("total_anomalies"),
        "ioc_delta": delta("total_ioc_matches"),
    }


def _session_data_from_db(session_id: int) -> dict[str, Any]:
    init_db()
    session = get_session_record(session_id)
    if not session:
        raise ValueError(f"Session not found: {session_id}")

    alerts = _alert_dicts(get_session_alerts(session_id, limit=1000))
    top_types = get_top_alert_types_for_session(session_id, limit=10)
    findings = _parse_json(session.get("findings_json"), [])
    components = _parse_json(session.get("risk_components_json"), {})
    if not isinstance(findings, list):
        findings = []
    if not isinstance(components, dict):
        components = {}

    return {
        "session_id": session.get("id"),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "N/A",
        "source": session.get("interface_name") or "N/A",
        "profile": session.get("profile_name"),
        "started_at": session.get("started_at"),
        "stopped_at": session.get("stopped_at"),
        "duration": format_duration(session.get("duration_sec")),
        "stats": {
            "packets": session.get("total_packets"),
            "anomalies": session.get("total_anomalies"),
            "incidents": session.get("total_incidents"),
            "ioc_matches": session.get("total_ioc_matches"),
        },
        "assessment": {
            "score": session.get("final_ib_score"),
            "level": session.get("final_ib_level"),
            "threat_level": session.get("threat_level"),
            "incident_probability": session.get("incident_probability"),
            "confidence": session.get("confidence"),
            "summary": session.get("summary_text"),
            "total_risk": session.get("total_risk"),
            "components": components,
            "findings": findings,
        },
        "alerts": alerts,
        "top_alert_types": top_types,
        "top_suspicious_values": _top_suspicious_values(alerts),
        "comparison": _comparison(session, get_previous_session_record(session_id)),
    }


def _session_data_from_runtime(session: Any, engine: Any) -> dict[str, Any]:
    session_id = getattr(engine, "current_session_db_id", None)
    if session_id:
        try:
            data = _session_data_from_db(int(session_id))
            data["mode"] = getattr(session, "mode", None) or data["mode"]
            data["source"] = (
                getattr(session, "pcap_path", None)
                or getattr(session, "interface_name", None)
                or data["source"]
            )
            return data
        except Exception:
            pass

    assessment = getattr(engine, "last_assessment", None) or {}
    return {
        "session_id": session_id,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": getattr(session, "mode", None) or "N/A",
        "source": getattr(session, "pcap_path", None) or getattr(session, "interface_name", None) or "N/A",
        "profile": getattr(session, "profile_name", None),
        "started_at": session.started_at.strftime("%Y-%m-%d %H:%M:%S")
        if getattr(session, "started_at", None)
        else None,
        "stopped_at": session.stopped_at.strftime("%Y-%m-%d %H:%M:%S")
        if getattr(session, "stopped_at", None)
        else None,
        "duration": format_duration(session.duration_seconds()),
        "stats": {
            "packets": getattr(session, "total_packets", None),
            "anomalies": getattr(session, "total_anomalies", None),
            "incidents": getattr(session, "total_incidents", None),
            "ioc_matches": getattr(session, "total_ioc_matches", None),
        },
        "assessment": {
            "score": getattr(session, "final_ib_score", None),
            "level": getattr(session, "final_ib_level", None),
            "threat_level": getattr(session, "threat_level", None),
            "incident_probability": getattr(session, "incident_probability", None),
            "confidence": getattr(session, "confidence", None),
            "summary": assessment.get("summary") if isinstance(assessment, dict) else None,
            "total_risk": assessment.get("total_risk") if isinstance(assessment, dict) else None,
            "components": assessment.get("components", {}) if isinstance(assessment, dict) else {},
            "findings": assessment.get("findings", []) if isinstance(assessment, dict) else [],
        },
        "alerts": [],
        "top_alert_types": [],
        "top_suspicious_values": [],
        "comparison": None,
    }


def _render_list(items: list[Any], empty: str) -> str:
    if not items:
        return f'<p class="muted">{_safe(empty)}</p>'
    return "<ul>" + "".join(f"<li>{_safe(item)}</li>" for item in items) + "</ul>"


def _render_kv(rows: list[tuple[str, Any]]) -> str:
    return (
        "<table>"
        + "".join(f"<tr><th>{_safe(key)}</th><td>{_safe(value)}</td></tr>" for key, value in rows)
        + "</table>"
    )


def _render_report(data: dict[str, Any]) -> str:
    assessment = data["assessment"]
    stats = data["stats"]
    alerts = data["alerts"]
    top_types = data["top_alert_types"]
    suspicious = data["top_suspicious_values"]
    recommendations = _recommendations(
        assessment.get("score"),
        assessment.get("findings", []),
        assessment.get("summary"),
        top_types,
    )

    component_rows = list((assessment.get("components") or {}).items())
    alert_rows = "".join(
        "<tr>"
        f"<td>{_safe(alert.get('id'))}</td>"
        f"<td>{_safe(alert.get('timestamp'))}</td>"
        f"<td>{_safe(alert.get('alert_type'))}</td>"
        f"<td>{_safe(alert.get('description'))}</td>"
        "</tr>"
        for alert in alerts
    ) or '<tr><td colspan="4" class="muted">Для этой сессии связанные alerts не найдены.</td></tr>'

    comparison = data.get("comparison")
    comparison_html = ""
    if comparison:
        comparison_html = f"""
        <section>
            <h2>Сравнение с предыдущей сессией #{_safe(comparison.get("previous_id"))}</h2>
            {_render_kv([
                ("IB Score delta", _format_delta(comparison.get("ib_score_delta"))),
                ("Incidents delta", _format_delta(comparison.get("incidents_delta"))),
                ("Anomalies delta", _format_delta(comparison.get("anomalies_delta"))),
                ("IOC delta", _format_delta(comparison.get("ioc_delta"))),
            ])}
        </section>
        """

    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>NetworkMonitor Session Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; color: #172033; background: #f4f7fb; }}
        .page {{ max-width: 1120px; margin: 0 auto; padding: 28px; }}
        header, section {{ background: white; border: 1px solid #dbe3ea; border-radius: 10px; padding: 18px; margin-top: 16px; }}
        header {{ background: #0f172a; color: white; }}
        h1, h2 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; font-size: 14px; }}
        th {{ background: #f8fafc; color: #334155; }}
        .summary {{ border-left: 4px solid #2563eb; background: #eff6ff; padding: 12px; border-radius: 6px; }}
        .muted {{ color: #64748b; }}
    </style>
</head>
<body>
<div class="page">
    <header>
        <h1>Аналитический отчет NetworkMonitor</h1>
        <div>Сформирован: {_safe(data.get("generated_at"))}</div>
    </header>
    <section>
        <h2>Общая информация о сессии</h2>
        {_render_kv([
            ("Session ID", data.get("session_id")),
            ("Время запуска", data.get("started_at")),
            ("Время завершения", data.get("stopped_at")),
            ("Длительность", data.get("duration")),
            ("Режим", data.get("mode")),
            ("Источник", data.get("source")),
            ("Профиль", data.get("profile")),
        ])}
    </section>
    <section>
        <h2>Итоговая оценка ИБ</h2>
        {_render_kv([
            ("IB Score", assessment.get("score")),
            ("Уровень ИБ", assessment.get("level")),
            ("Уровень угрозы", assessment.get("threat_level")),
            ("Вероятность инцидента", assessment.get("incident_probability")),
            ("Достоверность", assessment.get("confidence")),
            ("Total risk", assessment.get("total_risk")),
        ])}
        <div class="summary"><b>Вывод:</b> {_safe(assessment.get("summary"))}</div>
    </section>
    <section>
        <h2>Breakdown оценки</h2>
        {_render_kv(component_rows) if component_rows else '<p class="muted">Компоненты риска для этой сессии не сохранены.</p>'}
        <h3>Findings</h3>
        {_render_list(assessment.get("findings", []), "Findings для этой сессии не сохранены.")}
    </section>
    <section>
        <h2>Статистика</h2>
        {_render_kv([
            ("Packets", stats.get("packets")),
            ("Anomalies", stats.get("anomalies")),
            ("Incidents", stats.get("incidents")),
            ("IOC matches", stats.get("ioc_matches")),
        ])}
    </section>
    <section>
        <h2>Alerts, связанные с сессией</h2>
        <table><tr><th>ID</th><th>Time</th><th>Type</th><th>Description</th></tr>{alert_rows}</table>
    </section>
    <section>
        <h2>Агрегации и рекомендации</h2>
        <h3>Top alert types</h3>
        {_render_list([f"{alert_type or 'N/A'}: {count}" for alert_type, count in top_types], "Нет связанных alerts.")}
        <h3>Top suspicious values</h3>
        {_render_list([f"{value}: {count}" for value, count in suspicious], "Подозрительные значения не извлечены из descriptions.")}
        <h3>Рекомендации</h3>
        {_render_list(recommendations, "Рекомендации не сформированы.")}
    </section>
    {comparison_html}
</div>
</body>
</html>
"""


def build_html_report_for_session(session_id: int) -> str:
    return _render_report(_session_data_from_db(int(session_id)))


def build_html_report(session: Any, engine: Any) -> str:
    return _render_report(_session_data_from_runtime(session, engine))
