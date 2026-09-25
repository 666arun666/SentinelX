import json
import logging
from typing import Any

import httpx
from redis.asyncio import Redis

from sentinelx.agents.models import ProviderStatus
from sentinelx.core.config import settings

logger = logging.getLogger(__name__)


async def get_redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


class ThreatIntelClient:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.vt_key = settings.VIRUSTOTAL_API_KEY
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.ttl = 30 * 24 * 3600

    async def _fetch_from_cache(self, key: str) -> dict[str, Any] | None:
        try:
            cached = await self.redis.get(key)
            if cached:
                return json.loads(cached)
        except Exception as e:  # noqa: BLE001
            logger.warning("Redis cache read failure: %s", e)
        return None

    async def _save_to_cache(self, key: str, data: dict[str, Any]) -> None:
        try:
            await self.redis.set(key, json.dumps(data), ex=self.ttl)
        except Exception as e:  # noqa: BLE001
            logger.warning("Redis cache write failure: %s", e)

    async def check_abuseipdb(self, ip: str) -> ProviderStatus:
        if not self.abuseipdb_key:
            return ProviderStatus(status="not_attempted", error_type="missing_api_key")

        cache_key = f"abuseipdb:ipv4:{ip}"
        cached = await self._fetch_from_cache(cache_key)
        if cached is not None:
            return ProviderStatus(status="success", data=cached)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                )

                if resp.status_code == 429:
                    return ProviderStatus(status="failed", error_type="rate_limit")

                resp.raise_for_status()
                data = resp.json().get("data", {})

                result = {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                }

                await self._save_to_cache(cache_key, result)
                return ProviderStatus(status="success", data=result)

        except httpx.TimeoutException:
            return ProviderStatus(status="failed", error_type="timeout")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return ProviderStatus(status="failed", error_type="auth_failure")
            return ProviderStatus(
                status="failed", error_type=f"http_{e.response.status_code}"
            )
        except Exception as e:  # noqa: BLE001
            logger.error("AbuseIPDB unexpected error: %s", e)
            return ProviderStatus(status="failed", error_type="unexpected_error")

    async def check_virustotal_hash(self, file_hash: str) -> ProviderStatus:
        if not self.vt_key:
            return ProviderStatus(status="not_attempted", error_type="missing_api_key")

        cache_key = f"virustotal:hash:{file_hash}"
        cached = await self._fetch_from_cache(cache_key)
        if cached is not None:
            return ProviderStatus(status="success", data=cached)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self.vt_key, "Accept": "application/json"},
                )

                if resp.status_code == 429:
                    return ProviderStatus(status="failed", error_type="rate_limit")
                elif resp.status_code == 404:
                    result = {"malicious": 0, "total": 0, "not_found": True}
                    await self._save_to_cache(cache_key, result)
                    return ProviderStatus(status="success", data=result)

                resp.raise_for_status()
                data = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                result = {
                    "malicious": data.get("malicious", 0),
                    "suspicious": data.get("suspicious", 0),
                    "undetected": data.get("undetected", 0),
                }

                await self._save_to_cache(cache_key, result)
                return ProviderStatus(status="success", data=result)

        except httpx.TimeoutException:
            return ProviderStatus(status="failed", error_type="timeout")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return ProviderStatus(status="failed", error_type="auth_failure")
            return ProviderStatus(
                status="failed", error_type=f"http_{e.response.status_code}"
            )
        except Exception as e:  # noqa: BLE001
            logger.error("VirusTotal unexpected error: %s", e)
            return ProviderStatus(status="failed", error_type="unexpected_error")

    async def check_virustotal_domain(self, domain: str) -> ProviderStatus:
        if not self.vt_key:
            return ProviderStatus(status="not_attempted", error_type="missing_api_key")

        cache_key = f"virustotal:domain:{domain}"
        cached = await self._fetch_from_cache(cache_key)
        if cached is not None:
            return ProviderStatus(status="success", data=cached)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": self.vt_key, "Accept": "application/json"},
                )

                if resp.status_code == 429:
                    return ProviderStatus(status="failed", error_type="rate_limit")
                elif resp.status_code == 404:
                    result = {"malicious": 0, "not_found": True}
                    await self._save_to_cache(cache_key, result)
                    return ProviderStatus(status="success", data=result)

                resp.raise_for_status()
                data = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                result = {
                    "malicious": data.get("malicious", 0),
                    "suspicious": data.get("suspicious", 0),
                }

                await self._save_to_cache(cache_key, result)
                return ProviderStatus(status="success", data=result)

        except httpx.TimeoutException:
            return ProviderStatus(status="failed", error_type="timeout")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return ProviderStatus(status="failed", error_type="auth_failure")
            return ProviderStatus(
                status="failed", error_type=f"http_{e.response.status_code}"
            )
        except Exception as e:  # noqa: BLE001
            logger.error("VirusTotal domain unexpected error: %s", e)
            return ProviderStatus(status="failed", error_type="unexpected_error")
