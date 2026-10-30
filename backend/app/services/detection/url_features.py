"""
SignalSafe Campus - Centralized URL Feature Engineering Pipeline
Module: backend/app/services/detection/url_features.py
Version: 1.0.0

Provides a centralized, deterministic, static URL feature extraction pipeline shared by:
1. Offline dataset harmonization and ML model training.
2. Live production inference in SignalSafe detection endpoints.

Guarantee:
The same input URL string produces the identical feature vector in both training and live inference.
No arbitrary HTTP requests or external network queries are performed.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

# -----------------------------------------------------------------------------
# 1. Feature Schema Definition & Ordering (Version 1.0.0)
# -----------------------------------------------------------------------------

URL_FEATURE_SCHEMA_VERSION = "1.0.0"

# Fixed, immutable ordering of feature names for model matrix alignment.
URL_FEATURE_NAMES: Tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "dot_count_domain",
    "hyphen_count",
    "hyphen_count_domain",
    "has_hyphen_in_domain",
    "underscore_count",
    "slash_count",
    "double_slash_in_path",
    "at_symbol_count",
    "question_mark_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "is_https",
    "is_ip_address",
    "has_non_standard_port",
    "subdomain_count",
    "subdomain_length",
    "tld_length",
    "is_punycode",
    "digit_count",
    "digit_count_domain",
    "percentage_numeric_chars",
    "percentage_numeric_chars_domain",
    "url_entropy",
    "domain_entropy",
    "suspicious_file_extension",
    "suspicious_keyword_count",
    "suspicious_keyword_in_domain",
    "suspicious_keyword_in_path",
)

URL_FEATURE_SCHEMA: Dict[str, Dict[str, Any]] = {
    "url_length": {
        "type": "int",
        "description": "Total character length of the normalized URL string.",
        "logic": "len(normalized_url)",
        "missing_value": 0,
    },
    "hostname_length": {
        "type": "int",
        "description": "Total character length of the normalized hostname.",
        "logic": "len(hostname)",
        "missing_value": 0,
    },
    "path_length": {
        "type": "int",
        "description": "Total character length of the URL path.",
        "logic": "len(path)",
        "missing_value": 0,
    },
    "query_length": {
        "type": "int",
        "description": "Total character length of the URL query component.",
        "logic": "len(query)",
        "missing_value": 0,
    },
    "dot_count": {
        "type": "int",
        "description": "Count of dot characters ('.') in the full URL.",
        "logic": "url.count('.')",
        "missing_value": 0,
    },
    "dot_count_domain": {
        "type": "int",
        "description": "Count of dot characters ('.') in the hostname.",
        "logic": "hostname.count('.')",
        "missing_value": 0,
    },
    "hyphen_count": {
        "type": "int",
        "description": "Total count of hyphen characters ('-') in the full URL.",
        "logic": "url.count('-')",
        "missing_value": 0,
    },
    "hyphen_count_domain": {
        "type": "int",
        "description": "Count of hyphen characters ('-') in the hostname.",
        "logic": "hostname.count('-')",
        "missing_value": 0,
    },
    "has_hyphen_in_domain": {
        "type": "int",
        "description": "Binary flag (1/0) indicating if the hostname contains any hyphen.",
        "logic": "1 if '-' in hostname else 0",
        "missing_value": 0,
    },
    "underscore_count": {
        "type": "int",
        "description": "Count of underscore characters ('_') in the full URL.",
        "logic": "url.count('_')",
        "missing_value": 0,
    },
    "slash_count": {
        "type": "int",
        "description": "Total count of forward slash characters ('/') in the full URL.",
        "logic": "url.count('/')",
        "missing_value": 0,
    },
    "double_slash_in_path": {
        "type": "int",
        "description": "Binary flag (1/0) indicating '//' in path (redirect evasion).",
        "logic": "1 if '//' in path else 0",
        "missing_value": 0,
    },
    "at_symbol_count": {
        "type": "int",
        "description": "Count of '@' symbols in URL (userinfo credential obfuscation).",
        "logic": "url.count('@')",
        "missing_value": 0,
    },
    "question_mark_count": {
        "type": "int",
        "description": "Count of question mark characters ('?') in the full URL.",
        "logic": "url.count('?')",
        "missing_value": 0,
    },
    "equal_count": {
        "type": "int",
        "description": "Count of equal sign characters ('=') in the full URL.",
        "logic": "url.count('=')",
        "missing_value": 0,
    },
    "ampersand_count": {
        "type": "int",
        "description": "Count of ampersand characters ('&') in the full URL.",
        "logic": "url.count('&')",
        "missing_value": 0,
    },
    "percent_count": {
        "type": "int",
        "description": "Count of percent characters ('%') in URL (percent-encoding).",
        "logic": "raw_url.count('%')",
        "missing_value": 0,
    },
    "is_https": {
        "type": "int",
        "description": "Binary flag (1/0) indicating HTTPS scheme. NOT proof of legitimacy.",
        "logic": "1 if scheme == 'https' else 0",
        "missing_value": 0,
    },
    "is_ip_address": {
        "type": "int",
        "description": "Binary flag (1/0) indicating whether the host is a raw IPv4/IPv6 address.",
        "logic": "1 if host parses as IP or octal/hex IP else 0",
        "missing_value": 0,
    },
    "has_non_standard_port": {
        "type": "int",
        "description": "Binary flag (1/0) indicating explicit port other than 80 or 443.",
        "logic": "1 if port and port not in (80, 443) else 0",
        "missing_value": 0,
    },
    "subdomain_count": {
        "type": "int",
        "description": "Number of subdomain labels preceding the registrable domain.",
        "logic": "count of subdomain parts separated by dot",
        "missing_value": 0,
    },
    "subdomain_length": {
        "type": "int",
        "description": "Character length of the subdomain string.",
        "logic": "len(subdomain_string)",
        "missing_value": 0,
    },
    "tld_length": {
        "type": "int",
        "description": "Character length of the Top-Level Domain suffix.",
        "logic": "len(tld_suffix)",
        "missing_value": 0,
    },
    "is_punycode": {
        "type": "int",
        "description": "Binary flag (1/0) indicating 'xn--' IDN homograph representation.",
        "logic": "1 if 'xn--' in hostname else 0",
        "missing_value": 0,
    },
    "digit_count": {
        "type": "int",
        "description": "Total count of numeric digits ('0'-'9') in the URL.",
        "logic": "sum(c.isdigit() for c in url)",
        "missing_value": 0,
    },
    "digit_count_domain": {
        "type": "int",
        "description": "Total count of numeric digits in the hostname.",
        "logic": "sum(c.isdigit() for c in hostname)",
        "missing_value": 0,
    },
    "percentage_numeric_chars": {
        "type": "float",
        "description": "Percentage of digits in the full URL string (0.0 to 100.0).",
        "logic": "(digit_count / len(url)) * 100.0",
        "missing_value": 0.0,
    },
    "percentage_numeric_chars_domain": {
        "type": "float",
        "description": "Percentage of digits in the hostname string (0.0 to 100.0).",
        "logic": "(digit_count_domain / len(hostname)) * 100.0",
        "missing_value": 0.0,
    },
    "url_entropy": {
        "type": "float",
        "description": "Shannon entropy of characters in the full URL string.",
        "logic": "-sum(p * log2(p)) for char frequencies in url",
        "missing_value": 0.0,
    },
    "domain_entropy": {
        "type": "float",
        "description": "Shannon entropy of characters in the hostname string.",
        "logic": "-sum(p * log2(p)) for char frequencies in hostname",
        "missing_value": 0.0,
    },
    "suspicious_file_extension": {
        "type": "int",
        "description": "Binary flag (1/0) indicating high-risk executable or archive extension.",
        "logic": "1 if path ends with high-risk extension else 0",
        "missing_value": 0,
    },
    "suspicious_keyword_count": {
        "type": "int",
        "description": "Total count of credential/phishing target keywords across URL components.",
        "logic": "count of occurrences of sensitive keyword list",
        "missing_value": 0,
    },
    "suspicious_keyword_in_domain": {
        "type": "int",
        "description": "Binary flag (1/0) indicating suspicious keyword present in hostname.",
        "logic": "1 if any keyword in hostname else 0",
        "missing_value": 0,
    },
    "suspicious_keyword_in_path": {
        "type": "int",
        "description": "Binary flag (1/0) indicating suspicious keyword in path or query.",
        "logic": "1 if any keyword in path or query else 0",
        "missing_value": 0,
    },
}

# -----------------------------------------------------------------------------
# 2. Domain & Lexical Constants
# -----------------------------------------------------------------------------

# High-risk executable/payload extensions frequently observed in malware/phishing.
SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".zip", ".scr", ".bat", ".apk", ".iso", ".dmg",
    ".vbs", ".ps1", ".rar", ".7z", ".tar", ".gz", ".bin",
    ".sh", ".cmd", ".msi", ".jar", ".vbe", ".jse", ".wsf",
})

# Phishing target keywords commonly exploited for credential harvesting & spoofing.
SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "banking", "update", "confirm",
    "password", "credential", "wallet", "support", "auth", "authenticate",
    "service", "portal", "payment", "recover", "validation", "checkpoint",
    "billing", "oauth", "sso", "session", "webscr", "appleid", "office365",
)

# Common two-part multi-suffix ccTLDs to ensure precise registrable-domain splitting
# without requiring an external online Public Suffix List query.
COMMON_TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.tr", "edu.tr", "gov.tr", "org.tr",
    "com.pe", "edu.pe", "gob.pe", "org.pe",
    "com.ro", "org.ro", "tm.ro",
    "org.ng", "com.ng", "gov.ng", "edu.ng",
    "com.pk", "org.pk", "edu.pk", "gov.pk",
    "com.ar", "org.ar", "gov.ar", "edu.ar",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "org.tw", "gov.tw", "edu.tw",
    "co.za", "org.za", "gov.za", "ac.za",
})

# -----------------------------------------------------------------------------
# 3. Data Structures
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class URLNormalizationResult:
    """Structured result of deterministic URL normalization and parsing."""
    raw_url: str
    normalized_url: str
    is_valid: bool
    error_reason: Optional[str]
    scheme: str
    hostname: str
    port: Optional[int]
    registrable_domain: str
    subdomain: str
    tld: str
    path: str
    query: str
    fragment: str
    is_ip: bool
    is_punycode: bool


@dataclass(frozen=True)
class URLFeatures:
    """Type-safe container for the 34-feature URL feature vector."""
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    dot_count: int
    dot_count_domain: int
    hyphen_count: int
    hyphen_count_domain: int
    has_hyphen_in_domain: int
    underscore_count: int
    slash_count: int
    double_slash_in_path: int
    at_symbol_count: int
    question_mark_count: int
    equal_count: int
    ampersand_count: int
    percent_count: int
    is_https: int
    is_ip_address: int
    has_non_standard_port: int
    subdomain_count: int
    subdomain_length: int
    tld_length: int
    is_punycode: int
    digit_count: int
    digit_count_domain: int
    percentage_numeric_chars: float
    percentage_numeric_chars_domain: float
    url_entropy: float
    domain_entropy: float
    suspicious_file_extension: int
    suspicious_keyword_count: int
    suspicious_keyword_in_domain: int
    suspicious_keyword_in_path: int

    def to_dict(self) -> Dict[str, float | int]:
        """Convert features to a dictionary keyed by official feature names."""
        return asdict(self)

    def to_vector(self) -> List[float]:
        """Convert features to a flat, ordered float list matching URL_FEATURE_NAMES."""
        d = self.to_dict()
        return [float(d[name]) for name in URL_FEATURE_NAMES]

# -----------------------------------------------------------------------------
# 4. Helper & Extraction Algorithms
# -----------------------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy: H(X) = -sum(p(x) * log2(p(x)))
    Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    length = len(text)
    freqs: Dict[str, int] = {}
    for char in text:
        freqs[char] = freqs.get(char, 0) + 1
    
    entropy = 0.0
    for count in freqs.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 6)


def is_ip_host(host_string: str) -> bool:
    """
    Detects standard IPv4, IPv6, and obfuscated octal/hex/decimal IP representations.
    """
    if not host_string:
        return False
    
    # Strip brackets if IPv6
    clean_host = host_string.strip("[]")
    
    # Direct standard IPv4/IPv6 parse
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Check for pure 32-bit integer IP representation (e.g. 2130706433 = 127.0.0.1)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 4294967295:
                ipaddress.IPv4Address(val)
                return True
        except (ValueError, OverflowError):
            pass

    # Check for hex representation (e.g. 0x7f000001)
    if clean_host.lower().startswith("0x"):
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 4294967295:
                ipaddress.IPv4Address(val)
                return True
        except (ValueError, OverflowError):
            pass

    return False


def extract_domain_parts(hostname: str) -> Tuple[str, str, str]:
    """
    Splits hostname into (subdomain, registrable_domain, tld).
    Uses a standard multi-part suffix table to reliably parse ccTLDs (e.g. .co.uk).
    Returns (subdomain, registrable_domain, tld).
    """
    if not hostname or is_ip_host(hostname):
        return ("", hostname, "")

    labels = hostname.lower().strip(".").split(".")
    if not labels or len(labels) == 1:
        return ("", hostname, "")

    # Check two-part TLD match
    if len(labels) >= 3:
        two_part = f"{labels[-2]}.{labels[-1]}"
        if two_part in COMMON_TWO_PART_TLDS:
            tld = two_part
            registrable_domain = f"{labels[-3]}.{two_part}"
            subdomain = ".".join(labels[:-3])
            return (subdomain, registrable_domain, tld)

    # Standard single-part TLD match
    tld = labels[-1]
    registrable_domain = f"{labels[-2]}.{tld}"
    subdomain = ".".join(labels[:-2])
    return (subdomain, registrable_domain, tld)


# -----------------------------------------------------------------------------
# 5. Core Normalization & Parsing
# -----------------------------------------------------------------------------

def normalize_url(url: Any) -> URLNormalizationResult:
    """
    Deterministically validates and normalizes an input URL string.
    
    Handles:
    - Non-string / null / whitespace input
    - Maximum character length limits (4096 chars)
    - Missing scheme prefixing (prepends 'http://' for parsing)
    - Hostname case normalization (lowercase)
    - IDN / Punycode decoding
    - Port and path extraction
    """
    if url is None or not isinstance(url, str):
        return URLNormalizationResult(
            raw_url="" if url is None else str(url),
            normalized_url="",
            is_valid=False,
            error_reason="Input must be a non-empty string",
            scheme="",
            hostname="",
            port=None,
            registrable_domain="",
            subdomain="",
            tld="",
            path="",
            query="",
            fragment="",
            is_ip=False,
            is_punycode=False,
        )

    raw_url = url.strip()
    if not raw_url:
        return URLNormalizationResult(
            raw_url="",
            normalized_url="",
            is_valid=False,
            error_reason="URL string is empty or contains only whitespace",
            scheme="",
            hostname="",
            port=None,
            registrable_domain="",
            subdomain="",
            tld="",
            path="",
            query="",
            fragment="",
            is_ip=False,
            is_punycode=False,
        )

    if len(raw_url) > 4096:
        return URLNormalizationResult(
            raw_url=raw_url,
            normalized_url="",
            is_valid=False,
            error_reason="URL exceeds maximum permitted length of 4096 characters",
            scheme="",
            hostname="",
            port=None,
            registrable_domain="",
            subdomain="",
            tld="",
            path="",
            query="",
            fragment="",
            is_ip=False,
            is_punycode=False,
        )

    # Reject null bytes and non-printable control characters
    if "\x00" in raw_url or any(ord(c) < 32 for c in raw_url):
        return URLNormalizationResult(
            raw_url=raw_url,
            normalized_url="",
            is_valid=False,
            error_reason="URL contains null bytes or illegal control characters",
            scheme="",
            hostname="",
            port=None,
            registrable_domain="",
            subdomain="",
            tld="",
            path="",
            query="",
            fragment="",
            is_ip=False,
            is_punycode=False,
        )

    # Infer scheme if missing
    working_url = raw_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", working_url):
        working_url = "http://" + working_url

    try:
        parsed = urlparse(working_url)
    except Exception as exc:
        return URLNormalizationResult(
            raw_url=raw_url,
            normalized_url="",
            is_valid=False,
            error_reason=f"URL parsing failed: {str(exc)}",
            scheme="",
            hostname="",
            port=None,
            registrable_domain="",
            subdomain="",
            tld="",
            path="",
            query="",
            fragment="",
            is_ip=False,
            is_punycode=False,
        )

    scheme = parsed.scheme.lower()
    try:
        raw_hostname = parsed.hostname or ""
    except ValueError:
        raw_hostname = ""
    hostname = raw_hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None

    is_ip = is_ip_host(hostname)
    is_puny = "xn--" in hostname

    # Handle Punycode normalization for IDN homograph representation
    if is_puny:
        try:
            # Decode punycode to verify, but keep ascii hostname canonical for feature extraction
            _ = hostname.encode("ascii").decode("idna")
        except Exception:
            pass

    subdomain, registrable_domain, tld = extract_domain_parts(hostname)

    path = parsed.path or "/"
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Reconstruct normalized URL
    netloc_part = hostname
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc_part = f"{hostname}:{port}"

    normalized_url = f"{scheme}://{netloc_part}{path}"
    if query:
        normalized_url = f"{normalized_url}?{query}"
    if fragment:
        normalized_url = f"{normalized_url}#{fragment}"

    return URLNormalizationResult(
        raw_url=raw_url,
        normalized_url=normalized_url,
        is_valid=bool(hostname),
        error_reason=None if hostname else "Missing valid hostname",
        scheme=scheme,
        hostname=hostname,
        port=port,
        registrable_domain=registrable_domain,
        subdomain=subdomain,
        tld=tld,
        path=path,
        query=query,
        fragment=fragment,
        is_ip=is_ip,
        is_punycode=is_puny,
    )

# -----------------------------------------------------------------------------
# 6. Feature Extraction Engine
# -----------------------------------------------------------------------------

def extract_url_features(url: Any) -> URLFeatures:
    """
    Extracts the full, standardized 34-dimensional feature vector from a URL.
    
    Guarantees:
    - Never throws an uncaught exception on malformed or adversarial inputs.
    - Missing/invalid input defaults gracefully to schema-compliant zero values.
    - Pure, deterministic static string analysis without network calls.
    """
    norm = normalize_url(url)
    
    if not norm.is_valid:
        # Graceful schema fallback for unparseable input
        return URLFeatures(
            url_length=len(norm.raw_url),
            hostname_length=0,
            path_length=0,
            query_length=0,
            dot_count=norm.raw_url.count("."),
            dot_count_domain=0,
            hyphen_count=norm.raw_url.count("-"),
            hyphen_count_domain=0,
            has_hyphen_in_domain=0,
            underscore_count=norm.raw_url.count("_"),
            slash_count=norm.raw_url.count("/"),
            double_slash_in_path=0,
            at_symbol_count=norm.raw_url.count("@"),
            question_mark_count=norm.raw_url.count("?"),
            equal_count=norm.raw_url.count("="),
            ampersand_count=norm.raw_url.count("&"),
            percent_count=norm.raw_url.count("%"),
            is_https=0,
            is_ip_address=0,
            has_non_standard_port=0,
            subdomain_count=0,
            subdomain_length=0,
            tld_length=0,
            is_punycode=0,
            digit_count=sum(c.isdigit() for c in norm.raw_url),
            digit_count_domain=0,
            percentage_numeric_chars=round(
                (sum(c.isdigit() for c in norm.raw_url) / max(len(norm.raw_url), 1)) * 100.0, 4
            ),
            percentage_numeric_chars_domain=0.0,
            url_entropy=calculate_shannon_entropy(norm.raw_url),
            domain_entropy=0.0,
            suspicious_file_extension=0,
            suspicious_keyword_count=0,
            suspicious_keyword_in_domain=0,
            suspicious_keyword_in_path=0,
        )

    # Working components
    full_url = norm.normalized_url
    hostname = norm.hostname
    path = norm.path
    query = norm.query
    raw_url = norm.raw_url

    # Structural lengths
    url_length = len(full_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Delimiters and character counts
    dot_count = full_url.count(".")
    dot_count_domain = hostname.count(".")
    hyphen_count = full_url.count("-")
    hyphen_count_domain = hostname.count("-")
    has_hyphen_in_domain = 1 if hyphen_count_domain > 0 else 0
    underscore_count = full_url.count("_")
    slash_count = full_url.count("/")
    
    # Path redirection evasion (double slash inside path)
    double_slash_in_path = 1 if "//" in path else 0
    
    at_symbol_count = raw_url.count("@")
    question_mark_count = full_url.count("?")
    equal_count = full_url.count("=")
    ampersand_count = full_url.count("&")
    percent_count = raw_url.count("%")

    # Scheme and network properties
    # NOTE: is_https is only transport layer encryption; NEVER treat as proof of legitimacy!
    is_https = 1 if norm.scheme == "https" else 0
    is_ip_address = 1 if norm.is_ip else 0
    has_non_standard_port = (
        1 if (norm.port and norm.port not in (80, 443)) else 0
    )

    # Subdomain and TLD metrics
    subdomain_parts = [p for p in norm.subdomain.split(".") if p]
    subdomain_count = len(subdomain_parts)
    subdomain_length = len(norm.subdomain)
    tld_length = len(norm.tld)
    is_punycode = 1 if norm.is_punycode else 0

    # Numeric density
    digit_count = sum(c.isdigit() for c in full_url)
    digit_count_domain = sum(c.isdigit() for c in hostname)
    percentage_numeric_chars = round((digit_count / max(url_length, 1)) * 100.0, 4)
    percentage_numeric_chars_domain = round(
        (digit_count_domain / max(hostname_length, 1)) * 100.0, 4
    )

    # Information entropy
    url_entropy = calculate_shannon_entropy(full_url)
    domain_entropy = calculate_shannon_entropy(hostname)

    # File extension check (lowercased path suffix)
    path_lower = path.lower()
    has_suspicious_ext = 0
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}/" in path_lower:
            has_suspicious_ext = 1
            break

    # Sensitive phishing / credential keyword heuristics
    search_space = f"{hostname}/{path}?{query}".lower()
    keyword_count = 0
    keyword_in_domain = 0
    keyword_in_path = 0

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in search_space:
            keyword_count += search_space.count(kw)
        if kw in hostname:
            keyword_in_domain = 1
        if kw in path_lower or (query and kw in query.lower()):
            keyword_in_path = 1

    return URLFeatures(
        url_length=url_length,
        hostname_length=hostname_length,
        path_length=path_length,
        query_length=query_length,
        dot_count=dot_count,
        dot_count_domain=dot_count_domain,
        hyphen_count=hyphen_count,
        hyphen_count_domain=hyphen_count_domain,
        has_hyphen_in_domain=has_hyphen_in_domain,
        underscore_count=underscore_count,
        slash_count=slash_count,
        double_slash_in_path=double_slash_in_path,
        at_symbol_count=at_symbol_count,
        question_mark_count=question_mark_count,
        equal_count=equal_count,
        ampersand_count=ampersand_count,
        percent_count=percent_count,
        is_https=is_https,
        is_ip_address=is_ip_address,
        has_non_standard_port=has_non_standard_port,
        subdomain_count=subdomain_count,
        subdomain_length=subdomain_length,
        tld_length=tld_length,
        is_punycode=is_punycode,
        digit_count=digit_count,
        digit_count_domain=digit_count_domain,
        percentage_numeric_chars=percentage_numeric_chars,
        percentage_numeric_chars_domain=percentage_numeric_chars_domain,
        url_entropy=url_entropy,
        domain_entropy=domain_entropy,
        suspicious_file_extension=has_suspicious_ext,
        suspicious_keyword_count=keyword_count,
        suspicious_keyword_in_domain=keyword_in_domain,
        suspicious_keyword_in_path=keyword_in_path,
    )


def extract_url_feature_dict(url: Any) -> Dict[str, float | int]:
    """Extracts features as a dictionary matching official schema names."""
    return extract_url_features(url).to_dict()


def extract_url_feature_vector(url: Any) -> List[float]:
    """Extracts features as a flat, ordered float list matching URL_FEATURE_NAMES."""
    return extract_url_features(url).to_vector()


def batch_extract_url_feature_vectors(urls: List[Any]) -> List[List[float]]:
    """Batch-extracts feature vectors for offline preprocessing or bulk scanning."""
    return [extract_url_feature_vector(u) for u in urls]
