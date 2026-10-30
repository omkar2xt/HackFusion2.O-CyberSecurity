"""
SignalSafe Campus - URLhaus Threat Intelligence Adapter
Module: backend/app/services/detection/threat_intel/urlhaus.py
"""

import asyncio
import os
import time
import httpx
from backend.app.services.detection.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
    ThreatIntelStatus,
    is_ssrf_risk_or_internal,
)


class URLhausProvider(BaseThreatIntelProvider):
    """Queries abuse.ch URLhaus threat database."""

    def __init__(self, api_key: str | None = None, timeout: float = 3.0):
        self.api_key = api_key or os.environ.get("URLHAUS_API_KEY", "")
        self.timeout = timeout
        self.endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

    @property
    def provider_name(self) -> str:
        return "URLhaus"

    async def check_url(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

        if os.environ.get("DISABLE_EXTERNAL_TI", "false").lower() == "true" or os.environ.get("OFFLINE_MODE", "false").lower() == "true":
            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.UNAVAILABLE,
                is_malicious=False,
                confidence=0.0,
                details="External threat intelligence disabled in offline/sandbox mode.",
                query_latency_ms=0.0,
            )

        if is_ssrf_risk_or_internal(url):
            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.SKIPPED_INTERNAL_IP,
                is_malicious=False,
                confidence=0.0,
                details="Skipped internal/private network destination to prevent SSRF.",
                query_latency_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.endpoint,
                    data={"url": url},
                    headers=headers,
                )

            latency = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.RATE_LIMITED,
                    is_malicious=False,
                    confidence=0.0,
                    details="URLhaus query rate limit reached.",
                    query_latency_ms=latency,
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.ERROR,
                    is_malicious=False,
                    confidence=0.0,
                    details=f"URLhaus API returned HTTP {resp.status_code}",
                    query_latency_ms=latency,
                )

            data = resp.json()
            query_status = data.get("query_status")

            if query_status == "ok":
                threat = data.get("threat", "malware_download")
                urlhaus_reference = data.get("urlhaus_reference")
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.MATCH,
                    is_malicious=True,
                    confidence=0.98,
                    threat_category=threat,
                    permalink=urlhaus_reference,
                    details=f"Listed on URLhaus threat registry (status: {data.get('url_status', 'unknown')}, threat: {threat}).",
                    query_latency_ms=latency,
                )

            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.NO_MATCH,
                is_malicious=False,
                confidence=0.0,
                details="URL is not listed in URLhaus malware database.",
                query_latency_ms=latency,
            )

        except (httpx.TimeoutException, asyncio.TimeoutError):
            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.TIMEOUT,
                is_malicious=False,
                confidence=0.0,
                details=f"Request timed out after {self.timeout}s.",
                query_latency_ms=(time.perf_counter() - start_time) * 1000.0,
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.ERROR,
                is_malicious=False,
                confidence=0.0,
                details=f"Communication error: {str(exc)}",
                query_latency_ms=(time.perf_counter() - start_time) * 1000.0,
            )
