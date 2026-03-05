# NetworkMonitor/core/features.py
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import IP

@dataclass
class PacketFeatures:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    length: int
    dport: int


def extract_features(pkt, ts: float) -> Optional[PacketFeatures]:
    """Достаём признаки из scapy пакета. Возвращает None если пакет не IP."""

    if not pkt.haslayer(IP):
        return None

    src_ip = pkt["IP"].src
    dst_ip = pkt["IP"].dst
    proto = int(pkt["IP"].proto)
    length = int(len(pkt))

    dport = 0
    if hasattr(pkt, "dport"):
        try:
            dport = int(pkt.dport)
        except:
            dport = 0

    return PacketFeatures(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        length=length,
        dport=dport
    )
