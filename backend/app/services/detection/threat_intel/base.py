"""
SignalSafe Campus - Threat Intelligence Provider Interfaces
Module: backend/app/services/detection/threat_intel/base.py
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Optional
from urllib.parse import urlparse


class ThreatIntelStatus(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNAVAILABLE = "UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    SKIPPED_INTERNAL_IP = "SKIPPED_INTERNAL_IP"


@dataclass(frozen=True)
class ThreatIntelResult:
    """Standardized result returned by external threat intelligence providers."""
    provider_name: str
    target_url: str
    status: ThreatIntelStatus
    is_malicious: bool
    confidence: float  # 0.0 to 1.0
    threat_category: Optional[str] = None
    permalink: Optional[str] = None
    details: str = ""
    query_latency_ms: float = 0.0
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def is_ssrf_risk_or_internal(url: str) -> bool:
    """
    Checks if a target URL resolves to an internal/private/loopback address.
    Prevents Server-Side Request Forgery (SSRF) and private reconnaissance.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return True

        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True

        # Check IP ranges
        clean_host = host.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )
        except ValueError:
            pass

        # Check pure 32-bit integer IP representation (e.g. 2130706433 = 127.0.0.1)
        if clean_host.isdigit():
            try:
                val = int(clean_host)
                if 0 <= val <= 4294967295:
                    ip = ipaddress.IPv4Address(val)
                    return (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_reserved
                        or ip.is_multicast
                    )
            except (ValueError, OverflowError):
                pass

        # Check hex representation (e.g. 0x7f000001)
        if clean_host.lower().startswith("0x"):
            try:
                val = int(clean_host, 16)
                if 0 <= val <= 4294967295:
                    ip = ipaddress.IPv4Address(val)
                    return (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_reserved
                        or ip.is_multicast
                    )
            except (ValueError, OverflowError):
                pass

        # Disallow internal metadata hostnames (cloud metadata endpoints)
        if host in ("169.254.169.254", "metadata.google.internal", "instance-data"):
            return True

        return False
    except Exception:
        return True


class BaseThreatIntelProvider(ABC):
    """Abstract base class for external threat intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def check_url(self, url: str) -> ThreatIntelResult:
        """Asynchronously queries provider for threat records matching the URL."""
        pass
