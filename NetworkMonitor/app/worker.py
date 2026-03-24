from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal
from NetworkMonitor.core.engine import NetworkEngine


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