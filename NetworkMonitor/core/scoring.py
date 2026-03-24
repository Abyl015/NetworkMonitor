# NetworkMonitor/core/scoring.py
from __future__ import annotations

from typing import Any


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _norm(value: float, low: float, high: float) -> float:
    """
    Нормализация в диапазон 0..1
    """
    if high <= low:
        return 0.0
    if value <= low:
        return 0.0
    if value >= high:
        return 1.0
    return (value - low) / (high - low)


def _bool_to_risk(flag: bool, true_value: float) -> float:
    return float(true_value if flag else 0.0)


def _security_level(score: int) -> str:
    if score >= 81:
        return "Высокий уровень ИБ"
    if score >= 61:
        return "Приемлемый уровень ИБ"
    if score >= 41:
        return "Средний уровень ИБ"
    if score >= 21:
        return "Низкий уровень ИБ"
    return "Критическое состояние ИБ"


def _threat_level(total_risk: float) -> str:
    if total_risk >= 80:
        return "Критический"
    if total_risk >= 60:
        return "Высокий"
    if total_risk >= 35:
        return "Средний"
    if total_risk >= 15:
        return "Повышенный"
    return "Низкий"


def _incident_probability(total_risk: float, ioc_matches: int, infected_hosts: int) -> str:
    if infected_hosts > 0 or ioc_matches >= 3:
        return "Высокая"
    if total_risk >= 55 or ioc_matches >= 1:
        return "Средняя"
    if total_risk >= 25:
        return "Умеренная"
    return "Низкая"


def _confidence_level(observed_packets: int) -> str:
    if observed_packets >= 1000:
        return "Высокая"
    if observed_packets >= 300:
        return "Средняя"
    return "Низкая"


def calc_security_assessment(metrics: dict[str, Any], flags: dict[str, Any]) -> dict[str, Any]:
    """
    Подробная оценка состояния ИБ.

    metrics может содержать:
    - unique_ports_max
    - pps
    - pps_eff
    - anom_rate
    - ioc_matches
    - infected_hosts
    - observed_packets

    flags может содержать:
    - scan_rule
    - dos_rule
    - ioc_match
    - infected_host_candidate
    """
    unique_ports_max = float(metrics.get("unique_ports_max", 0))
    pps = float(metrics.get("pps", 0.0))
    pps_eff = float(metrics.get("pps_eff", pps))
    anom_rate = float(metrics.get("anom_rate", 0.0))
    ioc_matches = int(metrics.get("ioc_matches", 0))
    infected_hosts = int(metrics.get("infected_hosts", 0))
    observed_packets = int(metrics.get("observed_packets", 0))

    scan_rule = bool(flags.get("scan_rule", False))
    dos_rule = bool(flags.get("dos_rule", False))
    ioc_match = bool(flags.get("ioc_match", False)) or (ioc_matches > 0)
    infected_host_candidate = bool(flags.get("infected_host_candidate", False)) or (infected_hosts > 0)

    # --- Компонент 1: сетевое поведение ---
    port_scan_risk = _clamp(
        (_norm(unique_ports_max, 10, 80) * 70.0) +
        _bool_to_risk(scan_rule, 30.0)
    )

    dos_flood_risk = _clamp(
        (_norm(pps_eff, 20, 250) * 70.0) +
        _bool_to_risk(dos_rule, 30.0)
    )

    network_risk = _clamp((port_scan_risk * 0.55) + (dos_flood_risk * 0.45))

    # --- Компонент 2: аномальность трафика ---
    # anom_rate ожидается в диапазоне 0..1
    ml_risk = _clamp(_norm(anom_rate, 0.01, 0.50) * 100.0)

    # --- Компонент 3: IOC ---
    # 1 совпадение уже существенно, 3+ почти максимум
    ioc_base = _norm(ioc_matches, 0, 3) * 80.0
    ioc_bonus = 20.0 if ioc_match else 0.0
    ioc_risk = _clamp(ioc_base + ioc_bonus)

    # --- Компонент 4: риск компрометации хостов ---
    infected_base = _norm(infected_hosts, 0, 2) * 80.0
    infected_bonus = 20.0 if infected_host_candidate else 0.0
    host_compromise_risk = _clamp(infected_base + infected_bonus)

    # --- Итоговый риск ---
    total_risk = _clamp(
        (network_risk * 0.30) +
        (ml_risk * 0.30) +
        (ioc_risk * 0.25) +
        (host_compromise_risk * 0.15)
    )

    overall_score = int(round(100.0 - total_risk))
    security_level = _security_level(overall_score)
    threat_level = _threat_level(total_risk)
    incident_probability = _incident_probability(total_risk, ioc_matches, infected_hosts)
    confidence = _confidence_level(observed_packets)

    findings: list[str] = []

    if ioc_matches > 0:
        findings.append(f"Обнаружены совпадения с IOC: {ioc_matches}")
    if infected_hosts > 0:
        findings.append(f"Выявлены вероятно скомпрометированные хосты: {infected_hosts}")
    if scan_rule or unique_ports_max >= 20:
        findings.append("Обнаружены признаки сканирования портов")
    if dos_rule or pps_eff >= 100:
        findings.append("Обнаружены признаки интенсивного трафика / flood-поведения")
    if anom_rate >= 0.15:
        findings.append(f"Высокая доля аномалий ML: {anom_rate:.2f}")
    elif anom_rate >= 0.05:
        findings.append(f"Обнаружена заметная доля аномалий ML: {anom_rate:.2f}")

    if not findings:
        findings.append("Критичных признаков компрометации не обнаружено")

    if ioc_matches > 0 and infected_hosts > 0:
        summary = (
            "Зафиксированы совпадения с индикаторами компрометации и признаки "
            "возможной компрометации внутреннего хоста."
        )
    elif ioc_matches > 0:
        summary = (
            "Обнаружены совпадения с индикаторами компрометации. Требуется "
            "дополнительная проверка затронутых соединений."
        )
    elif anom_rate >= 0.15 or scan_rule or dos_rule:
        summary = (
            "Выявлено подозрительное сетевое поведение и аномалии трафика. "
            "Рекомендуется углублённый анализ."
        )
    else:
        summary = (
            "На текущем этапе наблюдения состояние сети выглядит относительно стабильным."
        )

    return {
        "overall_score": overall_score,
        "total_risk": round(total_risk, 2),
        "security_level": security_level,
        "threat_level": threat_level,
        "incident_probability": incident_probability,
        "confidence": confidence,
        "components": {
            "network_risk": round(network_risk, 2),
            "ml_risk": round(ml_risk, 2),
            "ioc_risk": round(ioc_risk, 2),
            "host_compromise_risk": round(host_compromise_risk, 2),
        },
        "risks": {
            "Port Scan": round(port_scan_risk, 2),
            "DoS/Flood": round(dos_flood_risk, 2),
            "ML Anomaly": round(ml_risk, 2),
            "IOC Match": round(ioc_risk, 2),
            "Host Compromise": round(host_compromise_risk, 2),
        },
        "findings": findings,
        "summary": summary,
    }


def calc_ib_score(metrics: dict[str, Any], flags: dict[str, Any]):
    """
    Совместимость со старым engine.py.
    Возвращает:
    ib_score, total_risk, risks, level
    """
    assessment = calc_security_assessment(metrics, flags)
    return (
        assessment["overall_score"],
        assessment["total_risk"],
        assessment["risks"],
        assessment["security_level"],
    )


def format_assessment_line(assessment: dict[str, Any]) -> str:
    """
    Красивый однострочный вывод для логов/GUI.
    """
    return (
        f"[ОЦЕНКА ИБ] Индекс={assessment['overall_score']}/100 | "
        f"Статус={assessment['security_level']} | "
        f"Угроза={assessment['threat_level']} | "
        f"Инцидент={assessment['incident_probability']}"
    )