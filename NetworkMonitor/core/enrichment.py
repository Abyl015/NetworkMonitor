from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from NetworkMonitor.config.secrets import get_secret


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"
DEFAULT_TIMEOUT_SECONDS = 4

_cache = {}
_cache_lock = threading.Lock()


def _result(ip: str, status: str, **extra) -> dict:
    data = {
        "ip": str(ip or ""),
        "provider": "AbuseIPDB",
        "status": status,
        "checked_at": int(time.time()),
    }
    data.update(extra)
    return data


def _normalize_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except (TypeError, ValueError):
        return None


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (TypeError, ValueError):
        return False

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or getattr(addr, "is_site_local", False)
    ):
        return False

    return bool(addr.is_global)


def _cache_key(ip: str, max_age_days: int) -> str:
    return f"{ip}|{int(max_age_days)}"


def _cached_result(ip: str, max_age_days: int) -> dict | None:
    key = _cache_key(ip, max_age_days)
    with _cache_lock:
        cached = _cache.get(key)
    if not cached:
        return None

    result = dict(cached)
    result["status"] = "cached"
    result["cached_status"] = cached.get("status")
    result["checked_at"] = int(time.time())
    return result


def _store_cache(ip: str, max_age_days: int, result: dict) -> None:
    key = _cache_key(ip, max_age_days)
    with _cache_lock:
        _cache[key] = dict(result)


def enrich_ip_abuseipdb(ip: str, max_age_days: int = 90) -> dict:
    normalized_ip = _normalize_ip(ip)
    if not normalized_ip:
        return _result(ip, "skipped", reason="invalid_ip")

    if not is_public_ip(normalized_ip):
        return _result(normalized_ip, "skipped", reason="non_public_ip")

    api_key = (get_secret(ABUSEIPDB_API_KEY_ENV) or "").strip()
    if not api_key:
        return _result(normalized_ip, "disabled", reason="missing_api_key")

    cached = _cached_result(normalized_ip, max_age_days)
    if cached:
        return cached

    if not is_public_ip(normalized_ip):
        return _result(normalized_ip, "skipped", reason="non_public_ip")

    query = urllib.parse.urlencode(
        {
            "ipAddress": normalized_ip,
            "maxAgeInDays": int(max_age_days),
        }
    )
    request = urllib.request.Request(
        f"{ABUSEIPDB_CHECK_URL}?{query}",
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return _result(
                normalized_ip,
                "rate_limited",
                http_status=exc.code,
                retry_after=exc.headers.get("Retry-After"),
                rate_limit_remaining=exc.headers.get("X-RateLimit-Remaining"),
            )
        return _result(normalized_ip, "error", error=f"HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return _result(normalized_ip, "error", error=str(getattr(exc, "reason", exc)))
    except TimeoutError:
        return _result(normalized_ip, "error", error="timeout")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _result(normalized_ip, "error", error=f"{type(exc).__name__}: {exc}")

    abuse_data = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(abuse_data, dict):
        return _result(normalized_ip, "error", error="invalid_response")

    result = _result(
        normalized_ip,
        "ok",
        abuseConfidenceScore=abuse_data.get("abuseConfidenceScore"),
        totalReports=abuse_data.get("totalReports"),
        countryCode=abuse_data.get("countryCode"),
        usageType=abuse_data.get("usageType"),
        isp=abuse_data.get("isp"),
        domain=abuse_data.get("domain"),
        lastReportedAt=abuse_data.get("lastReportedAt"),
    )
    _store_cache(normalized_ip, max_age_days, result)
    return result


def enrich_public_ips(ips: list[str], max_requests: int = 25) -> dict[str, dict]:
    results = {}
    network_calls = 0

    for raw_ip in ips or []:
        normalized_ip = _normalize_ip(raw_ip)
        result_key = normalized_ip or str(raw_ip or "")

        if not normalized_ip:
            results[result_key] = _result(raw_ip, "skipped", reason="invalid_ip")
            continue

        if result_key in results:
            continue

        if not is_public_ip(normalized_ip):
            results[normalized_ip] = _result(normalized_ip, "skipped", reason="non_public_ip")
            continue

        if not get_secret(ABUSEIPDB_API_KEY_ENV):
            results[normalized_ip] = _result(normalized_ip, "disabled", reason="missing_api_key")
            continue

        cached = _cached_result(normalized_ip, 90)
        if cached:
            results[normalized_ip] = cached
            continue

        if network_calls >= int(max_requests):
            results[normalized_ip] = _result(normalized_ip, "limit_reached", max_requests=int(max_requests))
            continue

        network_calls += 1
        results[normalized_ip] = enrich_ip_abuseipdb(normalized_ip)

    return results
