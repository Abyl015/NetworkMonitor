# NetworkMonitor/core/features.py
from dataclasses import dataclass
from typing import Optional
import ipaddress
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP, ICMP

@dataclass
class PacketFeatures:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    length: int
    sport: int
    dport: int
    is_tcp: int
    is_udp: int
    is_icmp: int
    is_multicast: int
    ttl: int
    tcp_syn: int
    tcp_ack: int


def extract_features(pkt, ts: float) -> Optional[PacketFeatures]:
    """Достаём признаки из scapy пакета. Возвращает None если пакет не IP."""

    if not pkt.haslayer(IP):
        return None

    src_ip = pkt["IP"].src
    dst_ip = pkt["IP"].dst
    proto = int(pkt["IP"].proto)
    length = int(len(pkt))
    ttl = int(getattr(pkt["IP"], "ttl", 0) or 0)
    try:
        is_multicast = 1 if ipaddress.ip_address(dst_ip).is_multicast else 0
    except ValueError:
        is_multicast = 0

    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        try:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        except Exception:
            sport, dport = 0, 0
    elif pkt.haslayer(UDP):
        try:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        except Exception:
            sport, dport = 0, 0

    is_tcp = 1 if pkt.haslayer(TCP) else 0
    is_udp = 1 if pkt.haslayer(UDP) else 0
    is_icmp = 1 if pkt.haslayer(ICMP) else 0

    tcp_syn = 0
    tcp_ack = 0
    if pkt.haslayer(TCP):
        flags = int(getattr(pkt[TCP], "flags", 0))
        tcp_syn = 1 if (flags & 0x02) else 0
        tcp_ack = 1 if (flags & 0x10) else 0

    return PacketFeatures(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        length=length,
        sport=sport,
        dport=dport,
        is_tcp=is_tcp,
        is_udp=is_udp,
        is_icmp=is_icmp,
        is_multicast=is_multicast,
        ttl=ttl,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
    )
