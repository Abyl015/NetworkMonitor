from __future__ import annotations

import time

from PyQt6.QtCore import QThread, pyqtSignal
from NetworkMonitor.core.engine import NetworkEngine
from NetworkMonitor.core.enrichment import enrich_ip_abuseipdb


class CaptureWorker(QThread):
    message = pyqtSignal(str)
    messages = pyqtSignal(list)
    finished_signal = pyqtSignal()

    PCAP_BATCH_INTERVAL_SEC = 0.25
    PCAP_BATCH_SIZE = 100
    PCAP_LOW_LEVEL_INTERVAL_SEC = 1.0

    def __init__(self, engine: NetworkEngine, mode: str = "live", pcap_path: str | None = None):
        super().__init__()
        self.engine = engine
        self.mode = mode
        self.pcap_path = pcap_path
        self._pending_pcap_messages: list[str] = []
        self._last_pcap_batch_emit = time.monotonic()
        self._pcap_low_level_latest: dict[str, str] = {}
        self._pcap_low_level_last_emit: dict[str, float] = {}
        self._pcap_low_level_last_value: dict[str, str] = {}
        self.engine.callback = self._handle_engine_message

    def run(self):
        try:
            if self.mode == "pcap" and self.pcap_path:
                self.engine.analyze_pcap(self.pcap_path)
            else:
                self.engine.start_capture()
        finally:
            self._flush_pcap_messages(force=True)
            self.finished_signal.emit()

    def _handle_engine_message(self, msg: str) -> None:
        if self.mode != "pcap":
            self.message.emit(msg)
            return

        self._queue_pcap_message(msg)

    def _pcap_low_level_category(self, msg: str) -> str | None:
        if "[DEBUG] raw packets:" in msg:
            return "debug_raw"
        if "[DEBUG] feature packets:" in msg:
            return "debug_feature"
        if "[DEBUG] sampled packets:" in msg:
            return "debug_sampled"
        if "[TRAIN DEBUG]" in msg:
            return "train_debug"
        if "<i>[PCAP]" in msg:
            return "pcap_progress"
        if msg.startswith("<i>") and "[" not in msg:
            return "training_progress"
        return None

    def _append_pending_pcap_low_level(self, now: float, force: bool = False) -> None:
        for category, msg in list(self._pcap_low_level_latest.items()):
            if msg == self._pcap_low_level_last_value.get(category):
                continue
            last_emit = self._pcap_low_level_last_emit.get(category, 0.0)
            if not force and now - last_emit < self.PCAP_LOW_LEVEL_INTERVAL_SEC:
                continue
            self._pending_pcap_messages.append(msg)
            self._pcap_low_level_last_emit[category] = now
            self._pcap_low_level_last_value[category] = msg

    def _queue_pcap_message(self, msg: str) -> None:
        now = time.monotonic()
        category = self._pcap_low_level_category(msg)
        if category:
            self._pcap_low_level_latest[category] = msg
            self._append_pending_pcap_low_level(now)
        else:
            self._append_pending_pcap_low_level(now, force=True)
            self._pending_pcap_messages.append(msg)

        self._flush_pcap_messages(force=False)

    def _flush_pcap_messages(self, force: bool = False) -> None:
        if self.mode != "pcap":
            return

        now = time.monotonic()
        if force:
            self._append_pending_pcap_low_level(now, force=True)

        if not self._pending_pcap_messages:
            return

        enough_messages = len(self._pending_pcap_messages) >= self.PCAP_BATCH_SIZE
        enough_time = now - self._last_pcap_batch_emit >= self.PCAP_BATCH_INTERVAL_SEC
        if not force and not enough_messages and not enough_time:
            return

        batch = self._pending_pcap_messages
        self._pending_pcap_messages = []
        self._last_pcap_batch_emit = now
        self.messages.emit(batch)


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
