"""
SignalSafe Campus - VirusTotal Threat Intelligence Adapter
Module: backend/app/services/detection/threat_intel/virustotal.py
"""

import asyncio
import base64
import os
import time
import httpx
from backend.app.services.detection.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
    ThreatIntelStatus,
    is_ssrf_risk_or_internal,
)


class VirusTotalProvider(BaseThreatIntelProvider):
    """Queries VirusTotal API v3 URL lookup endpoint."""

    def __init__(self, api_key: str | None = None, timeout: float = 3.0):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.timeout = timeout
        self.endpoint = "https://www.virustotal.com/api/v3/urls"

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    async def check_url(self, url: str) -> ThreatIntelResult:
        start_time = time.perf_counter()

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

        # In VirusTotal v3, the URL identifier is base64url encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.endpoint}/{url_id}",
                    headers=headers,
                )

            latency = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 404:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.NO_MATCH,
                    is_malicious=False,
                    confidence=0.0,
                    details="URL not previously indexed in VirusTotal corpus.",
                    query_latency_ms=latency,
                )

            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.RATE_LIMITED,
                    is_malicious=False,
                    confidence=0.0,
                    details="VirusTotal rate limit exceeded.",
                    query_latency_ms=latency,
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.ERROR,
                    is_malicious=False,
                    confidence=0.0,
                    details=f"VirusTotal API returned HTTP {resp.status_code}",
                    query_latency_ms=latency,
                )

            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            # High-confidence malicious threshold: >= 2 engines flag malicious
            if malicious_count >= 2:
                permalink = f"https://www.virustotal.com/gui/url/{url_id}"
                confidence = min(0.70 + (malicious_count * 0.05), 0.99)
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    target_url=url,
                    status=ThreatIntelStatus.MATCH,
                    is_malicious=True,
                    confidence=round(confidence, 2),
                    threat_category="PHISHING_OR_MALWARE",
                    permalink=permalink,
                    details=f"{malicious_count} security engines flagged this URL as malicious.",
                    query_latency_ms=latency,
                )

            return ThreatIntelResult(
                provider_name=self.provider_name,
                target_url=url,
                status=ThreatIntelStatus.NO_MATCH,
                is_malicious=False,
                confidence=0.0,
                details=f"No engine consensus ({malicious_count} malicious, {suspicious_count} suspicious).",
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
