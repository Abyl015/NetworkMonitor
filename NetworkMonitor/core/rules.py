from collections import defaultdict, deque
from typing import Dict


class RuleEngine:
    """
    Правила:
    - Port scan: много уникальных портов от одного src_ip к одному dst_ip за окно времени
    - Flood: высокий PPS по одному src_ip в окне
    """

    def __init__(
        self,
        sample_factor: int = 20,
        pps_window_sec: int = 10,
        scan_ports_threshold: int = 20,
        dos_pps_eff_threshold: int = 100,
        scan_window_sec: int = 15,
    ):
        self.sample_factor = int(sample_factor)
        self.pps_window_sec = int(pps_window_sec)
        self.scan_ports_threshold = int(scan_ports_threshold)
        self.dos_pps_eff_threshold = int(dos_pps_eff_threshold)
        self.scan_window_sec = int(scan_window_sec)

        # DoS/Flood state: PPS считаем по src_ip
        self.packets_window_by_src = defaultdict(deque)

        # Scan state: считаем уникальные dport по паре src_ip -> dst_ip за окно времени
        self.scan_ports_by_pair = defaultdict(deque)

        # статистика последнего обработанного события
        self.last_pps = 0.0
        self.last_pps_eff = 0.0

    def update(self, feat) -> Dict[str, object]:
        now = feat.ts
        src = feat.src_ip
        pair = (feat.src_ip, feat.dst_ip)

        # -------------------------
        # DoS/Flood: PPS по src_ip
        # -------------------------
        q = self.packets_window_by_src[src]
        q.append(now)

        while q and (now - q[0]) > self.pps_window_sec:
            q.popleft()

        pps = len(q) / float(self.pps_window_sec)
        pps_eff = pps * self.sample_factor

        self.last_pps = pps
        self.last_pps_eff = pps_eff

        # -------------------------
        # Scan: порты по src->dst за scan_window_sec
        # -------------------------
        scan_q = self.scan_ports_by_pair[pair]

        # Для TCP считаем scan только по SYN без ACK
        is_new_tcp_probe = bool(
            getattr(feat, "is_tcp", 0)
            and getattr(feat, "tcp_syn", 0)
            and not getattr(feat, "tcp_ack", 0)
        )

        # Для UDP допустим учёт по dport
        is_udp_probe = bool(getattr(feat, "is_udp", 0))

        if feat.dport and (is_new_tcp_probe or is_udp_probe):
            scan_q.append((now, feat.dport))

        while scan_q and (now - scan_q[0][0]) > self.scan_window_sec:
            scan_q.popleft()

        unique_ports_pair = len({p for _, p in scan_q})

        unique_ports_max = max(
            (len({p for _, p in dq}) for dq in self.scan_ports_by_pair.values()),
            default=0,
        )

        scan_rule = unique_ports_pair >= self.scan_ports_threshold
        dos_rule = pps_eff >= self.dos_pps_eff_threshold

        return {
            "pps": pps,
            "pps_eff": pps_eff,
            "unique_ports_src": unique_ports_pair,
            "unique_ports_max": unique_ports_max,
            "scan_rule": scan_rule,
            "dos_rule": dos_rule,
        }

    def evict_stale(self, now: float | None = None) -> None:
        """
        Опциональная очистка старого состояния, чтобы словари не росли бесконечно.
        Можно вызывать периодически из engine.py.
        """
        if now is None:
            return

        # чистим stale src windows
        stale_src = []
        for src, q in self.packets_window_by_src.items():
            while q and (now - q[0]) > self.pps_window_sec:
                q.popleft()
            if not q:
                stale_src.append(src)

        for src in stale_src:
            self.packets_window_by_src.pop(src, None)

        # чистим stale scan windows
        stale_pairs = []
        for pair, dq in self.scan_ports_by_pair.items():
            while dq and (now - dq[0][0]) > self.scan_window_sec:
                dq.popleft()
            if not dq:
                stale_pairs.append(pair)

        for pair in stale_pairs:
            self.scan_ports_by_pair.pop(pair, None)