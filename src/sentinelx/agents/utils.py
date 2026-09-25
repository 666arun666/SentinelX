import ipaddress
import re

from sentinelx.models.db_models import Event


def extract_ipv4(event: Event) -> list[str]:
    """Extract valid IPv4 addresses from an event."""
    ips = set()
    for ip_cand in [event.source_ip, event.destination_ip]:
        if ip_cand:
            try:
                # Basic validation
                ip_obj = ipaddress.IPv4Address(ip_cand)
                # Exclude private/loopback
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    ips.add(str(ip_obj))
            except Exception:  # noqa: BLE001, S110
                pass
    return list(ips)


def extract_hashes(event: Event) -> list[str]:
    """Extract valid MD5, SHA1, SHA256 hashes from an event."""
    hashes = set()
    # Check indicators JSON
    if event.indicators and isinstance(event.indicators, dict):
        for v in event.indicators.values():
            if isinstance(v, str):
                v_clean = v.strip().lower()
                # SHA256 (64 hex chars), SHA1 (40), MD5 (32)
                if re.fullmatch(
                    r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", v_clean
                ):
                    hashes.add(v_clean)
    return list(hashes)


def extract_domains(event: Event) -> list[str]:
    """Extract valid domains from an event."""
    domains = set()
    if event.indicators and isinstance(event.indicators, dict):
        for k, v in event.indicators.items():
            if k == "domain" and isinstance(v, str):
                v_clean = v.strip().lower()
                if re.fullmatch(
                    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$",
                    v_clean,
                ):
                    domains.add(v_clean)
    return list(domains)
