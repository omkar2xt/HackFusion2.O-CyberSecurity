"""
SignalSafe Campus - Aggregated Threat Intelligence Service
Module: backend/app/services/detection/threat_intel/service.py

Coordinates asynchronous, parallel queries across Google Safe Browsing,
VirusTotal, and URLhaus with connection timeouts, circuit breaking, and TTL caching.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Tuple

from backend.app.services.detection.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
    ThreatIntelStatus,
)
from backend.app.services.detection.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from backend.app.services.detection.threat_intel.virustotal import VirusTotalProvider
from backend.app.services.detection.threat_intel.urlhaus import URLhausProvider


@dataclass(frozen=True)
class AggregatedThreatIntelResult:
    """Aggregated threat intelligence query outcome across all providers."""
    target_url: str
    has_malicious_match: bool
    top_match: Optional[ThreatIntelResult]
    results: List[ThreatIntelResult]
    responding_providers: List[str]
    failed_providers: List[str]
    total_query_time_ms: float
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatIntelCache:
    """Lightweight in-memory TTL cache for threat intelligence lookups."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[AggregatedThreatIntelResult, float]] = {}

    def get(self, url: str) -> Optional[AggregatedThreatIntelResult]:
        entry = self._cache.get(url)
        if not entry:
            return None
        result, timestamp = entry
        if time.time() - timestamp > self.ttl:
            del self._cache[url]
            return None
        return result

    def set(self, url: str, result: AggregatedThreatIntelResult):
        self._cache[url] = (result, time.time())

    def clear(self):
        self._cache.clear()


class ThreatIntelService:
    """Coordinates external threat intelligence evaluation."""

    def __init__(
        self,
        providers: Optional[List[BaseThreatIntelProvider]] = None,
        cache_ttl: int = 300,
    ):
        self.providers = providers or [
            GoogleSafeBrowsingProvider(),
            VirusTotalProvider(),
            URLhausProvider(),
        ]
        self.cache = ThreatIntelCache(ttl_seconds=cache_ttl)

    async def query_all(self, url: str) -> AggregatedThreatIntelResult:
        """
        Queries all configured providers in parallel.
        Handles provider timeouts and outages gracefully without crashing.
        Never marks a URL safe solely because a provider returns no match.
        """
        cached = self.cache.get(url)
        if cached:
            return cached

        start_time = time.perf_counter()
        tasks = [provider.check_url(url) for provider in self.providers]
        raw_responses = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[ThreatIntelResult] = []
        responding_providers: List[str] = []
        failed_providers: List[str] = []
        malicious_matches: List[ThreatIntelResult] = []

        for provider, resp in zip(self.providers, raw_responses):
            if isinstance(resp, Exception):
                failed_providers.append(provider.provider_name)
                results.append(
                    ThreatIntelResult(
                        provider_name=provider.provider_name,
                        target_url=url,
                        status=ThreatIntelStatus.ERROR,
                        is_malicious=False,
                        confidence=0.0,
                        details=f"Uncaught task error: {str(resp)}",
                    )
                )
            elif isinstance(resp, ThreatIntelResult):
                results.append(resp)
                if resp.status in (
                    ThreatIntelStatus.ERROR,
                    ThreatIntelStatus.TIMEOUT,
                    ThreatIntelStatus.RATE_LIMITED,
                    ThreatIntelStatus.UNAVAILABLE,
                ):
                    failed_providers.append(provider.provider_name)
                else:
                    responding_providers.append(provider.provider_name)

                if resp.is_malicious and resp.status == ThreatIntelStatus.MATCH:
                    malicious_matches.append(resp)

        has_malicious = len(malicious_matches) > 0
        top_match = max(malicious_matches, key=lambda x: x.confidence) if malicious_matches else None
        total_time_ms = (time.perf_counter() - start_time) * 1000.0

        aggregated = AggregatedThreatIntelResult(
            target_url=url,
            has_malicious_match=has_malicious,
            top_match=top_match,
            results=results,
            responding_providers=responding_providers,
            failed_providers=failed_providers,
            total_query_time_ms=round(total_time_ms, 2),
        )

        self.cache.set(url, aggregated)
        return aggregated


# Default service instance
threat_intel_service = ThreatIntelService()
