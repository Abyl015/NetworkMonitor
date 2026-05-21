from __future__ import annotations

import html
import ipaddress
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


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or str(value).strip().upper() == "N/A"


def _safe(value: Any, default: str = "Нет данных") -> str:
    if _is_empty(value):
        return html.escape(default)
    return html.escape(str(value))


def _plain(value: Any, default: str = "Нет данных") -> str:
    if _is_empty(value):
        return default
    return str(value)


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
        return "Не рассчитано"
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
        '<table class="kv-table">'
        + "".join(f"<tr><th>{_safe(key)}</th><td>{_safe(value)}</td></tr>" for key, value in rows)
        + "</table>"
    )


def _render_summary_card(label: str, value: Any, default: str = "Не рассчитано", primary: bool = False) -> str:
    card_class = "summary-card summary-card-primary" if primary else "summary-card"
    return f"""
        <div class="{card_class}">
            <div class="summary-label">{_safe(label)}</div>
            <div class="summary-value">{_safe(value, default)}</div>
        </div>
    """


def _has_activity_without_linked_alerts(stats: dict[str, Any], alerts: list[dict[str, Any]]) -> bool:
    if alerts:
        return False
    try:
        incidents = int(stats.get("incidents") or 0)
        anomalies = int(stats.get("anomalies") or 0)
    except (TypeError, ValueError):
        return False
    return incidents > 0 or anomalies > 0


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _alert_text_blob(
    alerts: list[dict[str, Any]],
    top_types: list[tuple],
    findings: list[Any],
    summary: str | None,
) -> str:
    parts = [summary or ""]
    parts.extend(str(item) for item in findings or [])
    parts.extend(str(alert.get("alert_type") or "") for alert in alerts)
    parts.extend(str(alert.get("description") or "") for alert in alerts)
    parts.extend(str(alert_type or "") for alert_type, _count in top_types or [])
    return " ".join(parts).lower()


def _build_analyst_assessment(data: dict[str, Any]) -> list[tuple[str, str]]:
    assessment = data.get("assessment") or {}
    stats = data.get("stats") or {}
    alerts = data.get("alerts") or []
    top_types = data.get("top_alert_types") or []
    findings = assessment.get("findings") or []
    blob = _alert_text_blob(alerts, top_types, findings, assessment.get("summary"))

    score = _to_float(assessment.get("score"))
    total_risk = _to_float(assessment.get("total_risk"))
    ioc_count = _to_int(stats.get("ioc_matches"))
    anomaly_count = _to_int(stats.get("anomalies"))
    incident_count = _to_int(stats.get("incidents"))
    has_ioc = ioc_count > 0 or "ioc" in blob
    has_malicious = "malicious" in blob or "ioc_match" in blob or "ioc_domain_match" in blob
    has_scan = "scan" in blob or "unique_ports" in blob
    has_dos = "dos" in blob or "flood" in blob or "pps=" in blob
    has_ml = "ml" in blob or "anomal" in blob or "аномал" in blob
    has_suspicious = "suspicious" in blob or has_scan or has_dos

    high_priority = (
        has_ioc
        or incident_count > 0
        or has_malicious
        or (score is not None and score < 60)
        or (total_risk is not None and total_risk >= 0.7)
    )
    medium_priority = (
        anomaly_count > 0
        or has_suspicious
        or has_ml
        or (score is not None and score < 80)
        or (total_risk is not None and total_risk >= 0.35)
    )

    if high_priority:
        priority = "Высокий"
        overall = (
            "Отчёт содержит значимые индикаторы риска. Данные следует рассматривать как основание "
            "для приоритетной аналитической проверки, а не как самостоятельное доказательство компрометации."
        )
    elif medium_priority:
        priority = "Средний"
        overall = (
            "Отчёт содержит события, требующие сопоставления с сетевым контекстом, журналами и ожидаемой "
            "активностью узлов."
        )
    else:
        priority = "Низкий"
        overall = (
            "По текущим данным сильные признаки инцидента не выделены. Рекомендуется продолжить наблюдение "
            "и проверять новые срабатывания в контексте среды."
        )

    if has_ioc:
        next_step = "Рекомендуется проверить узлы и соединения, связанные с IOC-срабатываниями."
        note = "IOC-срабатывания требуют проверки актуальности индикатора и контекста соединения."
    elif anomaly_count > 0 or has_ml:
        next_step = "Рекомендуется сопоставить ML-аномалии с сетевыми событиями и IOC-контекстом."
        note = "ML-аномалии могут отражать как подозрительную, так и редкую легитимную активность."
    elif has_scan:
        next_step = "Рекомендуется проверить источники сканирования и назначение затронутых портов."
        note = "Сканирование может быть связано с администрированием, инвентаризацией или проверками безопасности."
    elif has_dos:
        next_step = "Рекомендуется проверить всплески трафика, целевые сервисы и распределение источников."
        note = "Высокая интенсивность трафика требует подтверждения по журналам сервисов и сетевой инфраструктуры."
    else:
        next_step = "Рекомендуется проверить ключевые алерты и связанную оценку сессии."
        note = (
            "События требуют дополнительной проверки, так как текущие данные не являются достаточным "
            "доказательством компрометации."
        )

    return [
        ("Общая оценка", overall),
        ("Приоритет", priority),
        ("Рекомендуемое действие", next_step),
        ("Примечание аналитика", note),
    ]


def _render_analyst_assessment(data: dict[str, Any]) -> str:
    return f"""
    <section class="report-section">
        <h2>Аналитическая оценка</h2>
        {_render_kv(_build_analyst_assessment(data))}
    </section>
    """


def _is_public_ip_for_report(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _threat_intel_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    source = (
        data.get("threat_intel")
        or data.get("enrichment")
        or data.get("enrichment_results")
        or []
    )
    items: list[tuple[Any, Any]]
    if isinstance(source, dict):
        items = list(source.items())
    elif isinstance(source, list):
        items = [(None, item) for item in source]
    else:
        return []

    rows: list[dict[str, Any]] = []
    for key, item in items:
        if not isinstance(item, dict):
            continue
        ip_value = item.get("ip") or key
        if not ip_value or not _is_public_ip_for_report(ip_value):
            continue
        isp_usage = " / ".join(
            str(part)
            for part in (item.get("isp"), item.get("usageType"))
            if not _is_empty(part)
        )
        rows.append({
            "ip": ip_value,
            "status": item.get("status"),
            "abuse_score": item.get("abuseConfidenceScore"),
            "total_reports": item.get("totalReports"),
            "country": item.get("countryCode"),
            "isp_usage": isp_usage or None,
            "last_reported": item.get("lastReportedAt"),
            "analyst_note": (
                "External reputation data is contextual and requires manual validation. "
                "Shared hosting, CDN, VPN, or cloud infrastructure may cause false positives."
            ),
        })
    return rows


def _render_threat_intelligence(data: dict[str, Any]) -> str:
    rows = _threat_intel_rows(data)
    if not rows:
        body = (
            '<p class="muted">'
            + _safe("Данные Threat Intelligence enrichment недоступны. Отчёт не выполняет внешние API-запросы автоматически.")
            + "</p>"
        )
    else:
        table_rows = "".join(
            "<tr>"
            f"<td>{_safe(row.get('ip'))}</td>"
            f"<td>{_safe(row.get('status'))}</td>"
            f"<td>{_safe(row.get('abuse_score'))}</td>"
            f"<td>{_safe(row.get('total_reports'))}</td>"
            f"<td>{_safe(row.get('country'))}</td>"
            f"<td>{_safe(row.get('isp_usage'))}</td>"
            f"<td>{_safe(row.get('last_reported'))}</td>"
            f"<td>{_safe(row.get('analyst_note'))}</td>"
            "</tr>"
            for row in rows
        )
        body = (
            '<table class="data-table"><tr><th>IP address</th><th>Lookup status</th>'
            "<th>Abuse confidence score</th><th>Total reports</th><th>Country</th>"
            "<th>ISP / usage type</th><th>Last reported</th><th>Analyst note</th></tr>"
            f"{table_rows}</table>"
        )

    return f"""
    <section class="report-section">
        <h2>Threat Intelligence Enrichment</h2>
        {body}
    </section>
    """


def _render_privacy_note() -> str:
    return f"""
    <section class="report-section">
        <h2>Примечание о конфиденциальности</h2>
        <p>{_safe("Внешнее обогащение выполняется только для публичных IP-адресов и используется как дополнительный аналитический контекст. Внутренние/private IP-адреса, API-ключи, локальные имена хостов и чувствительные параметры не должны включаться в отчёт или отправляться во внешние сервисы.")}</p>
        <p class="muted">{_safe("Отчёт формируется из локальных результатов анализа и сохранённых данных сессии. Внешняя репутационная информация, если она присутствует, не является доказательством сама по себе.")}</p>
    </section>
    """


def _render_detection_limitations() -> str:
    return f"""
    <section class="report-section">
        <h2>Ограничения обнаружения</h2>
        <p>{_safe("Результаты анализа следует рассматривать как индикаторы риска. ML-аномалии, IOC-срабатывания и внешняя репутационная информация требуют дополнительной проверки аналитиком. Система не выполняет автоматическую блокировку и не должна использоваться как единственный источник решения об инциденте.")}</p>
        {_render_list([
            "IB Score является индикатором оценки риска, а не финальным forensic-заключением.",
            "ML-аномалии могут включать ложные срабатывания и редкое легитимное поведение.",
            "IOC-срабатывания могут быть устаревшими или относиться к shared/CDN/cloud инфраструктуре.",
            "Threat Intelligence enrichment не доказывает вредоносность само по себе.",
            "Перед containment/blocking требуется ручная аналитическая проверка.",
            "Текущая система является локальным IDS/monitoring prototype, а не полноценной SIEM/SOAR/IPS платформой.",
        ], "Нет данных")}
    </section>
    """


def _risk_component_label(name: Any) -> str:
    labels = {
        "network_risk": "Сетевой риск",
        "ml_risk": "ML-риск",
        "ioc_risk": "IOC-риск",
        "host_compromise_risk": "Риск компрометации хоста",
    }
    return labels.get(str(name), str(name))


def _render_pdf_kv(rows: list[tuple[str, Any]]) -> str:
    return (
        '<table class="kv-table">'
        + "".join(f"<tr><th>{_safe(key)}</th><td>{_safe(value)}</td></tr>" for key, value in rows)
        + "</table>"
    )


def _render_pdf_list(items: list[Any], empty: str) -> str:
    if not items:
        return f"<p>{_safe(empty)}</p>"
    return "<ul>" + "".join(f"<li>{_safe(item)}</li>" for item in items) + "</ul>"


def _render_pdf_section(title: str, body: str) -> str:
    return f"""
    <h2>{_safe(title)}</h2>
    {body}
    """


def _render_pdf_threat_intelligence(data: dict[str, Any]) -> str:
    rows = _threat_intel_rows(data)
    if not rows:
        return _render_pdf_section(
            "Threat Intelligence Enrichment",
            "<p>"
            + _safe("Данные Threat Intelligence enrichment недоступны. Отчёт не выполняет внешние API-запросы автоматически.")
            + "</p>",
        )

    table_rows = "".join(
        "<tr>"
        f"<td>{_safe(row.get('ip'))}</td>"
        f"<td>{_safe(row.get('status'))}</td>"
        f"<td>{_safe(row.get('abuse_score'))}</td>"
        f"<td>{_safe(row.get('total_reports'))}</td>"
        f"<td>{_safe(row.get('country'))}</td>"
        f"<td>{_safe(row.get('isp_usage'))}</td>"
        f"<td>{_safe(row.get('last_reported'))}</td>"
        "</tr>"
        for row in rows
    )
    return _render_pdf_section(
        "Threat Intelligence Enrichment",
        "<table><tr><th>IP</th><th>Status</th><th>Abuse score</th><th>Total reports</th>"
        "<th>Country</th><th>ISP / usage</th><th>Last reported</th></tr>"
        f"{table_rows}</table>",
    )


def _render_pdf_privacy_note() -> str:
    return _render_pdf_section(
        "Примечание о конфиденциальности",
        "<p>"
        + _safe("Внешнее обогащение выполняется только для публичных IP-адресов и используется как дополнительный аналитический контекст. Внутренние/private IP-адреса, API-ключи, локальные имена хостов и чувствительные параметры не должны включаться в отчёт или отправляться во внешние сервисы.")
        + "</p><p>"
        + _safe("Отчёт формируется из локальных результатов анализа и сохранённых данных сессии. Внешняя репутационная информация, если она присутствует, не является доказательством сама по себе.")
        + "</p>",
    )


def _render_pdf_detection_limitations() -> str:
    return _render_pdf_section(
        "Ограничения обнаружения",
        "<p>"
        + _safe("Результаты анализа следует рассматривать как индикаторы риска. ML-аномалии, IOC-срабатывания и внешняя репутационная информация требуют дополнительной проверки аналитиком. Система не выполняет автоматическую блокировку и не должна использоваться как единственный источник решения об инциденте.")
        + "</p>"
        + _render_pdf_list([
            "IB Score является индикатором оценки риска, а не финальным forensic-заключением.",
            "ML-аномалии могут включать ложные срабатывания и редкое легитимное поведение.",
            "IOC-срабатывания могут быть устаревшими или относиться к shared/CDN/cloud инфраструктуре.",
            "Threat Intelligence enrichment не доказывает вредоносность само по себе.",
            "Перед containment/blocking требуется ручная аналитическая проверка.",
        ], "Нет данных"),
    )


def build_pdf_report_html_from_data(data: dict[str, Any]) -> str:
    assessment = data["assessment"]
    stats = data["stats"]
    alerts = data["alerts"]
    top_types = data["top_alert_types"]
    recommendations = _recommendations(
        assessment.get("score"),
        assessment.get("findings", []),
        assessment.get("summary"),
        top_types,
    )
    component_rows = [
        (_risk_component_label(name), value)
        for name, value in (assessment.get("components") or {}).items()
    ]
    alert_rows = "".join(
        "<tr>"
        f"<td>{_safe(alert.get('id'))}</td>"
        f"<td>{_safe(alert.get('timestamp'))}</td>"
        f"<td>{_safe(alert.get('alert_type'))}</td>"
        f"<td>{_safe(alert.get('description'))}</td>"
        "</tr>"
        for alert in alerts
    )
    if not alert_rows:
        empty_alerts = "Для этой сессии отдельные записи alerts не найдены."
        if _has_activity_without_linked_alerts(stats, alerts):
            empty_alerts = (
                "Для этой сессии отдельные записи alerts не найдены. Возможная причина: события были "
                "учтены в агрегированной статистике, но не были связаны с session_id."
            )
        alert_rows = f'<tr><td colspan="4">{_safe(empty_alerts)}</td></tr>'

    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: sans-serif;
            font-size: 10.5pt;
            color: #172033;
            line-height: 1.35;
        }}
        h1 {{
            font-size: 20pt;
            color: #0f172a;
            margin: 0 0 8pt;
        }}
        h2 {{
            font-size: 14pt;
            color: #1d4ed8;
            margin: 16pt 0 7pt;
            border-bottom: 1px solid #cbd5e1;
            padding-bottom: 3pt;
        }}
        h3 {{
            font-size: 11.5pt;
            color: #334155;
            margin: 10pt 0 5pt;
        }}
        p {{ margin: 4pt 0 8pt; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 4pt 0 10pt;
        }}
        th, td {{
            border: 1px solid #dbe3ea;
            padding: 5pt 6pt;
            vertical-align: top;
        }}
        th {{
            background: #f1f5f9;
            font-weight: bold;
            text-align: left;
        }}
        .kv-table th {{ width: 34%; }}
        .score {{
            font-size: 24pt;
            font-weight: bold;
            color: #1d4ed8;
        }}
        .muted {{ color: #64748b; }}
        ul {{ margin-top: 4pt; }}
    </style>
</head>
<body>
    <h1>Отчёт по оценке кибербезопасности</h1>
    <p class="muted">Сформирован: {_safe(data.get("generated_at"))}</p>

    {_render_pdf_section("Информация о сессии", _render_pdf_kv([
        ("Session ID", data.get("session_id")),
        ("Время запуска", data.get("started_at")),
        ("Время завершения", data.get("stopped_at")),
        ("Длительность", data.get("duration")),
        ("Режим", data.get("mode")),
        ("Источник", data.get("source")),
        ("Профиль", data.get("profile")),
    ]))}

    {_render_pdf_section("IB Score", f'''
        <p class="score">{_safe(assessment.get("score"), "Не рассчитано")}</p>
        {_render_pdf_kv([
            ("Уровень ИБ", assessment.get("level")),
            ("Уровень угрозы", assessment.get("threat_level")),
            ("Вероятность инцидента", assessment.get("incident_probability")),
            ("Достоверность", assessment.get("confidence")),
            ("Итоговый риск", assessment.get("total_risk")),
            ("Вывод", assessment.get("summary")),
        ])}
    ''')}

    {_render_pdf_section("Аналитическая оценка", _render_pdf_kv(_build_analyst_assessment(data)))}

    {_render_pdf_section("Статистика", _render_pdf_kv([
        ("Пакеты", stats.get("packets")),
        ("Аномалии", stats.get("anomalies")),
        ("Инциденты", stats.get("incidents")),
        ("IOC совпадения", stats.get("ioc_matches")),
    ]))}

    {_render_pdf_section("Алерты", (
        "<table><tr><th>ID</th><th>Время</th><th>Тип</th><th>Описание</th></tr>"
        f"{alert_rows}</table>"
    ))}

    {_render_pdf_section("Состав оценки / risk breakdown", (
        _render_pdf_kv(component_rows) if component_rows else "<p>Не сохранено</p>"
    ))}

    {_render_pdf_section("Ключевые выводы", _render_pdf_list(assessment.get("findings", []), "Не сохранено"))}

    {_render_pdf_threat_intelligence(data)}
    {_render_pdf_privacy_note()}
    {_render_pdf_detection_limitations()}

    {_render_pdf_section("Рекомендации", _render_pdf_list(recommendations, "Не рассчитано"))}
</body>
</html>
"""


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

    component_rows = [
        (_risk_component_label(name), value)
        for name, value in (assessment.get("components") or {}).items()
    ]
    alert_rows = "".join(
        "<tr>"
        f"<td>{_safe(alert.get('id'))}</td>"
        f"<td>{_safe(alert.get('timestamp'))}</td>"
        f"<td><span class=\"pill\">{_safe(alert.get('alert_type'))}</span></td>"
        f"<td>{_safe(alert.get('description'))}</td>"
        "</tr>"
        for alert in alerts
    )
    if not alert_rows:
        empty_alerts = "Для этой сессии отдельные записи alerts не найдены."
        if _has_activity_without_linked_alerts(stats, alerts):
            empty_alerts = (
                "Для этой сессии отдельные записи alerts не найдены. Возможная причина: события были "
                "учтены в агрегированной статистике, но не были связаны с session_id."
            )
        alert_rows = f'<tr><td colspan="4" class="empty-cell">{_safe(empty_alerts)}</td></tr>'

    comparison = data.get("comparison")
    comparison_html = ""
    if comparison:
        comparison_html = f"""
        <section class="report-section">
            <h2>Сравнение с предыдущей сессией #{_safe(comparison.get("previous_id"))}</h2>
            {_render_kv([
                ("Динамика IB Score", _format_delta(comparison.get("ib_score_delta"))),
                ("Динамика инцидентов", _format_delta(comparison.get("incidents_delta"))),
                ("Динамика аномалий", _format_delta(comparison.get("anomalies_delta"))),
                ("Динамика IOC", _format_delta(comparison.get("ioc_delta"))),
            ])}
        </section>
        """

    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>HTML-отчёт NetworkMonitor</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: "Segoe UI", Arial, sans-serif;
            margin: 0;
            color: #172033;
            background: #f4f7fb;
            line-height: 1.45;
        }}
        .page {{ max-width: 1160px; margin: 0 auto; padding: 30px; }}
        .report-header {{
            background: #0f172a;
            color: #ffffff;
            border-radius: 12px;
            padding: 28px 30px;
            border: 1px solid #1e293b;
        }}
        .eyebrow {{
            color: #93c5fd;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        h1 {{ margin: 0; font-size: 28px; font-weight: 750; }}
        h2 {{ margin: 0 0 14px; font-size: 19px; color: #0f172a; }}
        h3 {{ margin: 18px 0 8px; font-size: 15px; color: #334155; }}
        .header-meta {{ margin-top: 12px; color: #cbd5e1; font-size: 14px; }}
        .report-section {{
            background: #ffffff;
            border: 1px solid #dbe3ea;
            border-radius: 10px;
            padding: 18px;
            margin-top: 16px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: 1.3fr repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }}
        .summary-card {{
            background: #f8fafc;
            border: 1px solid #dbe3ea;
            border-radius: 10px;
            padding: 14px;
            min-height: 92px;
        }}
        .summary-card-primary {{
            background: #eff6ff;
            border-color: #93c5fd;
        }}
        .summary-label {{
            color: #64748b;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}
        .summary-value {{
            margin-top: 8px;
            color: #0f172a;
            font-size: 24px;
            font-weight: 800;
        }}
        .summary-card-primary .summary-value {{ color: #1d4ed8; font-size: 34px; }}
        .summary-note {{
            border-left: 4px solid #2563eb;
            background: #eff6ff;
            padding: 12px 14px;
            border-radius: 8px;
        }}
        table {{ width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 8px; }}
        th, td {{
            border-bottom: 1px solid #e5e7eb;
            padding: 10px 12px;
            text-align: left;
            vertical-align: top;
            font-size: 14px;
        }}
        th {{ background: #f8fafc; color: #334155; font-weight: 700; }}
        tr:last-child td {{ border-bottom: 0; }}
        .kv-table th {{ width: 28%; }}
        .data-table {{
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
        }}
        .pill {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 999px;
            background: #e0f2fe;
            color: #075985;
            font-size: 12px;
            font-weight: 700;
        }}
        .muted, .empty-cell {{ color: #64748b; }}
        .empty-cell {{ padding: 16px; background: #f8fafc; }}
        ul {{ margin: 8px 0 0; padding-left: 20px; }}
        li {{ margin: 5px 0; }}
        @media print {{
            body {{ background: #ffffff; }}
            .page {{ max-width: none; padding: 0; }}
            .report-header, .report-section {{ break-inside: avoid; box-shadow: none; }}
            .report-header {{ border-radius: 0; }}
            a {{ color: #172033; text-decoration: none; }}
        }}
        @media (max-width: 780px) {{
            .page {{ padding: 16px; }}
            .summary-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
<div class="page">
    <header class="report-header">
        <div class="eyebrow">AI Network Guardian / NetworkMonitor</div>
        <h1>Отчёт по оценке кибербезопасности</h1>
        <div class="header-meta">Сформирован: {_safe(data.get("generated_at"))} · Формат: HTML</div>
    </header>
    <section class="report-section">
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
    <section class="report-section">
        <h2>Итоговая оценка ИБ</h2>
        <div class="summary-grid">
            {_render_summary_card("IB Score", assessment.get("score"), "Не рассчитано", primary=True)}
            {_render_summary_card("Уровень угрозы", assessment.get("threat_level"))}
            {_render_summary_card("Вероятность инцидента", assessment.get("incident_probability"))}
            {_render_summary_card("Достоверность", assessment.get("confidence"))}
        </div>
        {_render_kv([
            ("Уровень ИБ", assessment.get("level")),
            ("Итоговый риск", _safe(assessment.get("total_risk"), "Не рассчитано")),
        ])}
        <div class="summary-note"><b>Вывод:</b> {_safe(assessment.get("summary"), "Не сохранено")}</div>
    </section>
    {_render_analyst_assessment(data)}
    {_render_threat_intelligence(data)}
    {_render_privacy_note()}
    {_render_detection_limitations()}
    <section class="report-section">
        <h2>Состав оценки</h2>
        {_render_kv(component_rows) if component_rows else '<p class="muted">Не сохранено</p>'}
        <h3>Ключевые выводы</h3>
        {_render_list(assessment.get("findings", []), "Не сохранено")}
    </section>
    <section class="report-section">
        <h2>Статистика</h2>
        {_render_kv([
            ("Пакеты", stats.get("packets")),
            ("Аномалии", stats.get("anomalies")),
            ("Инциденты", stats.get("incidents")),
            ("IOC совпадения", stats.get("ioc_matches")),
        ])}
    </section>
    <section class="report-section">
        <h2>Алерты, связанные с сессией</h2>
        <table class="data-table"><tr><th>ID</th><th>Время</th><th>Тип</th><th>Описание</th></tr>{alert_rows}</table>
    </section>
    <section class="report-section">
        <h2>Агрегации и рекомендации</h2>
        <h3>Топ типов алертов</h3>
        {_render_list([f"{_plain(alert_type)}: {count}" for alert_type, count in top_types], "Нет данных")}
        <h3>Топ подозрительных значений</h3>
        {_render_list([f"{value}: {count}" for value, count in suspicious], "Нет данных")}
        <h3>Рекомендации</h3>
        {_render_list(recommendations, "Не рассчитано")}
    </section>
    {comparison_html}
</div>
</body>
</html>
"""


def build_report_data_for_session(session_id: int) -> dict[str, Any]:
    return _session_data_from_db(int(session_id))


def build_report_data(session: Any, engine: Any) -> dict[str, Any]:
    return _session_data_from_runtime(session, engine)


def build_html_report_for_session(session_id: int) -> str:
    return _render_report(build_report_data_for_session(int(session_id)))


def build_html_report(session: Any, engine: Any) -> str:
    return _render_report(build_report_data(session, engine))
