from collections import defaultdict, deque
from typing import Dict


class RuleEngine:
    """
    Правила:
    - Port scan: много уникальных портов от одного src_ip
    - Flood: высокий PPS по окну (с учетом sampling)
    """

    def __init__(
        self,
        sample_factor: int = 20,
        pps_window_sec: int = 10,
        scan_ports_threshold: int = 50,
        dos_pps_eff_threshold: int = 100
    ):
        self.sample_factor = int(sample_factor)
        self.pps_window_sec = int(pps_window_sec)
        self.scan_ports_threshold = int(scan_ports_threshold)
        self.dos_pps_eff_threshold = int(dos_pps_eff_threshold)

        # ✅ ВОТ ЭТО ОБЯЗАТЕЛЬНО (иначе AttributeError)
        self.ports_by_src = defaultdict(set)
        self.packets_window = deque()  # timestamps

        # статистика
        self.last_pps = 0.0
        self.last_pps_eff = 0.0

    def update(self, feat) -> Dict[str, object]:
        now = feat.ts

        # окно PPS
        self.packets_window.append(now)
        while self.packets_window and (now - self.packets_window[0]) > self.pps_window_sec:
            self.packets_window.popleft()

        self.last_pps = len(self.packets_window) / float(self.pps_window_sec)
        self.last_pps_eff = self.last_pps * self.sample_factor

        # порт-скан (накопительный)
        if feat.dport:
            self.ports_by_src[feat.src_ip].add(feat.dport)

        unique_ports = len(self.ports_by_src[feat.src_ip])
        unique_ports_max = max((len(s) for s in self.ports_by_src.values()), default=0)

        scan_rule = unique_ports >= self.scan_ports_threshold
        dos_rule = self.last_pps_eff >= self.dos_pps_eff_threshold

        return {
            "pps": self.last_pps,
            "pps_eff": self.last_pps_eff,
            "unique_ports_src": unique_ports,
            "unique_ports_max": unique_ports_max,
            "scan_rule": scan_rule,
            "dos_rule": dos_rule,
        }
