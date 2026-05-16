from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.core.enrichment import enrich_ip_abuseipdb


class CaptureWorker(QThread):
    message = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, engine: NetworkEngine, mode: str = "live", pcap_path: str | None = None):
        super().__init__()
        self.engine = engine
        self.mode = mode
        self.pcap_path = pcap_path
        self.engine.callback = self.message.emit

    def run(self):
        try:
            if self.mode == "pcap" and self.pcap_path:
                self.engine.analyze_pcap(self.pcap_path)
            else:
                self.engine.start_capture()
        finally:
            self.finished_signal.emit()


class EnrichmentWorker(QThread):
    progress = pyqtSignal(str, dict)
    finished_signal = pyqtSignal(dict)

    def __init__(self, ips: list[str], max_requests: int = 25):
        super().__init__()
        self.ips = list(ips or [])
        self.max_requests = int(max_requests)

    def run(self):
        results = {}
        network_calls = 0

        try:
            for ip in self.ips:
                cached_before = False
                if network_calls >= self.max_requests:
                    result = {
                        "ip": ip,
                        "provider": "AbuseIPDB",
                        "status": "limit_reached",
                        "max_requests": self.max_requests,
                    }
                else:
                    result = enrich_ip_abuseipdb(ip)
                    cached_before = result.get("status") in {"cached", "disabled", "skipped"}
                    if not cached_before:
                        network_calls += 1

                results[ip] = result
                self.progress.emit(ip, result)
        finally:
            self.finished_signal.emit(results)
