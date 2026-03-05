# NetworkMonitor/app/worker.py
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal
from NetworkMonitor.core.engine import NetworkEngine


class CaptureWorker(QThread):
    message = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, engine: NetworkEngine):
        super().__init__()
        self.engine = engine
        self.engine.callback = self.message.emit

    def run(self):
        try:
            self.engine.start_capture()
        finally:
            self.finished_signal.emit()
