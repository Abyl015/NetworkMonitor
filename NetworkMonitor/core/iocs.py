# NetworkMonitor/core/iocs.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
from urllib.parse import urlparse

from NetworkMonitor.core.paths import bundled_iocs_dir


def _strip_safe_inline_comment(line: str) -> str:
    for index, char in enumerate(line):
        if char == "#" and index > 0 and line[index - 1].isspace():
            return line[:index].strip()
    return line


def _safe_read_lines(file_path: Path) -> set[str]:
    if not file_path.exists():
        return set()

    items = set()
    with file_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            line = _strip_safe_inline_comment(line)
            if not line:
                continue

            items.add(line)

    return items


def normalize_ip(value: str) -> str | None:
    if not value:
        return None

    value = str(value).strip()

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

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or parsed.netloc or parsed.path

    if "/" in value:
        value = value.split("/", 1)[0]

    if ":" in value and value.count(":") == 1:
        left, right = value.rsplit(":", 1)
        if left and right.isdigit():
            value = left

    value = value.strip().rstrip(".").lower()

    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    if not value:
        return None

    return value


@dataclass
class IOCMatch:
    matched: bool
    ioc_type: str | None = None
    value: str | None = None
    reason: str | None = None


def load_ip_iocs(file_path: Path) -> set[str]:
    return {
        ip
        for ip in (normalize_ip(item) for item in _safe_read_lines(file_path))
        if ip
    }


def load_domain_iocs(file_path: Path) -> set[str]:
    return {
        domain
        for domain in (normalize_domain(item) for item in _safe_read_lines(file_path))
        if domain
    }


def match_domain_ioc(domain_value: str, malicious_domains: set[str]) -> IOCMatch:
    domain_norm = normalize_domain(domain_value)
    if not domain_norm:
        return IOCMatch(False)

    if domain_norm in malicious_domains:
        return IOCMatch(
            matched=True,
            ioc_type="malicious_domain",
            value=domain_norm,
            reason="Domain IOC match",
        )

    for bad_domain in malicious_domains:
        if domain_norm.endswith("." + bad_domain):
            return IOCMatch(
                matched=True,
                ioc_type="malicious_domain",
                value=bad_domain,
                reason=f"Domain IOC subdomain match: {domain_norm} -> {bad_domain}",
            )

    return IOCMatch(False)


@dataclass
class IOCStore:
    base_dir: Path = field(default_factory=bundled_iocs_dir)
    malicious_ips: set[str] = field(default_factory=set)
    malicious_domains: set[str] = field(default_factory=set)

    def __post_init__(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ip_file = self.base_dir / "malicious_ips.txt"
        self.domain_file = self.base_dir / "malicious_domains.txt"
        self.reload()

    def reload(self):
        self.malicious_ips = load_ip_iocs(self.ip_file)
        self.malicious_domains = load_domain_iocs(self.domain_file)

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
                reason="IP IOC match",
            )

        return IOCMatch(False)

    def check_domain(self, domain_value: str) -> IOCMatch:
        return match_domain_ioc(domain_value, self.malicious_domains)

    def check_ip_pair(self, src_ip: str, dst_ip: str) -> IOCMatch:
        src_match = self.check_ip(src_ip)
        if src_match.matched:
            return src_match

        dst_match = self.check_ip(dst_ip)
        if dst_match.matched:
            return dst_match

        return IOCMatch(False)
