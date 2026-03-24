# NetworkMonitor/core/iocs.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
from urllib.parse import urlparse


def _safe_read_lines(file_path: Path) -> set[str]:
    if not file_path.exists():
        return set()

    items = set()
    with file_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # пропускаем пустые строки и комментарии
            if not line or line.startswith("#"):
                continue

            items.add(line)

    return items


def normalize_ip(value: str) -> str | None:
    if not value:
        return None

    value = str(value).strip()

    # если вдруг пришел формат ip:port
    if ":" in value and value.count(":") == 1:
        left, right = value.split(":", 1)
        if left.replace(".", "").isdigit() and right.isdigit():
            value = left

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_domain(value: str) -> str | None:
    if not value:
        return None

    value = str(value).strip().lower()

    if not value:
        return None

    # если пришел URL
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    # убираем путь
    if "/" in value:
        value = value.split("/", 1)[0]

    # убираем порт у domain:port
    if ":" in value:
        value = value.split(":", 1)[0]

    value = value.strip(".").lower()

    if not value:
        return None

    return value


@dataclass
class IOCMatch:
    matched: bool
    ioc_type: str | None = None
    value: str | None = None
    reason: str | None = None


@dataclass
class IOCStore:
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "data" / "iocs")
    malicious_ips: set[str] = field(default_factory=set)
    malicious_domains: set[str] = field(default_factory=set)

    def __post_init__(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ip_file = self.base_dir / "malicious_ips.txt"
        self.domain_file = self.base_dir / "malicious_domains.txt"
        self.reload()

    def reload(self):
        raw_ips = _safe_read_lines(self.ip_file)
        raw_domains = _safe_read_lines(self.domain_file)

        self.malicious_ips = {
            ip for ip in (normalize_ip(x) for x in raw_ips) if ip
        }
        self.malicious_domains = {
            d for d in (normalize_domain(x) for x in raw_domains) if d
        }

    def stats(self) -> dict:
        return {
            "ips": len(self.malicious_ips),
            "domains": len(self.malicious_domains),
            "base_dir": str(self.base_dir),
        }

    def check_ip(self, ip_value: str) -> IOCMatch:
        ip_norm = normalize_ip(ip_value)
        if not ip_norm:
            return IOCMatch(False)

        if ip_norm in self.malicious_ips:
            return IOCMatch(
                matched=True,
                ioc_type="malicious_ip",
                value=ip_norm,
                reason="IP найден в локальной IOC-базе",
            )

        return IOCMatch(False)

    def check_domain(self, domain_value: str) -> IOCMatch:
        domain_norm = normalize_domain(domain_value)
        if not domain_norm:
            return IOCMatch(False)

        # exact match
        if domain_norm in self.malicious_domains:
            return IOCMatch(
                matched=True,
                ioc_type="malicious_domain",
                value=domain_norm,
                reason="Домен найден в локальной IOC-базе",
            )

        # subdomain match: sub.bad.com -> bad.com
        for bad_domain in self.malicious_domains:
            if domain_norm.endswith("." + bad_domain):
                return IOCMatch(
                    matched=True,
                    ioc_type="malicious_domain",
                    value=bad_domain,
                    reason=f"Домен {domain_norm} относится к IOC-домену {bad_domain}",
                )

        return IOCMatch(False)

    def check_ip_pair(self, src_ip: str, dst_ip: str) -> IOCMatch:
        src_match = self.check_ip(src_ip)
        if src_match.matched:
            return src_match

        dst_match = self.check_ip(dst_ip)
        if dst_match.matched:
            return dst_match

        return IOCMatch(False)