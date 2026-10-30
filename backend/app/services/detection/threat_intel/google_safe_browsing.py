"""
SignalSafe Campus - Google Safe Browsing Adapter
Module: backend/app/services/detection/threat_intel/google_safe_browsing.py
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


class GoogleSafeBrowsingProvider(BaseThreatIntelProvider):
    """Queries Google Safe Browsing Lookup API v4."""

    def __init__(self, api_key: str | None = None, timeout: float = 3.0):
        self.api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
        self.timeout = timeout
        self.endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    @property
    def provider_name(self) -> str:
        return "Google Safe Browsing"

    async def check_url(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

        # SSRF Check
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

        if not self.api_key:
            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.UNAVAILABLE,
                is_malicious=False,
                confidence=0.0,
                details="API key not configured in environment.",
                query_latency_ms=0.0,
            )

        payload = {
            "client": {"clientId": "signalsafe-campus", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.endpoint}?key={self.api_key}",
                    json=payload,
                )

            latency = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.RATE_LIMITED,
                    is_malicious=False,
                    confidence=0.0,
                    details="Google Safe Browsing rate limit exceeded.",
                    query_latency_ms=latency,
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.ERROR,
                    is_malicious=False,
                    confidence=0.0,
                    details=f"Provider returned HTTP {resp.status_code}",
                    query_latency_ms=latency,
                )

            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                top_match = matches[0]
                threat_type = top_match.get("threatType", "SOCIAL_ENGINEERING")
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.MATCH,
                    is_malicious=True,
                    confidence=0.98,
                    threat_category=threat_type,
                    details=f"Identified as malicious ({threat_type}) by Google Safe Browsing.",
                    query_latency_ms=latency,
                )

            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.NO_MATCH,
                is_malicious=False,
                confidence=0.0,
                details="No malicious record found in Google Safe Browsing database.",
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
