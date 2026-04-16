from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class MonitoringSession:
    mode: str = "live"  # live | pcap
    profile_name: str = "default"
    interface_name: str = ""
    pcap_path: str = ""

    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None

    total_packets: int = 0
    total_anomalies: int = 0
    total_ioc_matches: int = 0
    total_incidents: int = 0

    final_ib_score: Optional[int] = None
    final_ib_level: str = "Оценка не рассчитана"

    notes: list[str] = field(default_factory=list)

    def duration_seconds(self) -> int:
        if not self.started_at or not self.stopped_at:
            return 0
        return int((self.stopped_at - self.started_at).total_seconds())