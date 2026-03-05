# NetworkMonitor/core/scoring.py
from dataclasses import dataclass
from typing import Dict, Tuple


def norm(x: float, a: float, b: float) -> float:
    if x <= a:
        return 0.0
    if x >= b:
        return 1.0
    return (x - a) / (b - a)


@dataclass
class ThreatScore:
    name: str
    risk: float


def calc_ib_score(metrics: Dict[str, float], flags: Dict[str, bool]) -> Tuple[int, float, Dict[str, float], str]:
    """
    Возвращает:
    - ib_score 0..100
    - total_risk 0..1
    - risks_by_threat
    - level (строка)
    """

    unique_ports_max = metrics.get("unique_ports_max", 0.0)

    # ВАЖНО:
    # pps = "как измерили" (после sampling)
    # pps_eff = "оценка реального PPS" (pps * sample_factor)
    pps_eff = metrics.get("pps_eff", metrics.get("pps", 0.0))

    anom_rate = metrics.get("anom_rate", 0.0)

    # вероятности (пороги можно калибровать под среду)
    p_scan = norm(unique_ports_max, 20, 100)

    # Для домашней сети: 80 PPS уже подозрительно, 800 PPS - очень плохо
    p_dos = norm(pps_eff, 80, 800)

    p_ml = norm(anom_rate, 0.01, 0.10)

    # уверенность
    c_scan = 0.9 if flags.get("scan_rule", False) else 0.7
    c_dos = 0.9 if flags.get("dos_rule", False) else 0.7
    c_ml = 0.6

    # impact: scan=3, dos=5, ml=4
    r_scan = p_scan * (3/5) * c_scan
    r_dos  = p_dos  * (5/5) * c_dos
    r_ml   = p_ml   * (4/5) * c_ml

    # агрегируем нелинейно
    total_risk = 1.0 - ((1.0 - r_scan) * (1.0 - r_dos) * (1.0 - r_ml))
    ib_score = int(round(100 * (1.0 - total_risk)))

    if ib_score >= 80:
        level = "Высокий уровень ИБ"
    elif ib_score >= 50:
        level = "Средний уровень ИБ"
    else:
        level = "Низкий уровень ИБ"

    return ib_score, total_risk, {"Port Scan": r_scan, "DoS/Flood": r_dos, "ML Anomaly": r_ml}, level
