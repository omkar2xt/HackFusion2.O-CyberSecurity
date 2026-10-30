"""
SignalSafe Campus - Centralized URL Feature Extraction Service (URL_FEATURE_SCHEMA_V1)

Extracts exactly 34 deterministic lexical, structural, protocol, and keyword features
from user-submitted URLs for machine learning classification and heuristic scoring.
"""

import math
import re
import urllib.parse
from collections import Counter
from typing import Dict, List, Union, Tuple
import numpy as np

# Exact feature ordering definition (34 features)
URL_FEATURE_SCHEMA_V1: List[str] = [
    # Length & Structure (0-3)
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    
    # Character Frequencies (4-14)
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_question_marks",
    "count_equals",
    "count_at",
    "count_ampersands",
    "count_percent",
    "count_digits",
    "count_letters",
    
    # Structural Metrics & Entropy (15-19)
    "count_subdomains",
    "digit_ratio_url",
    "digit_ratio_host",
    "letter_ratio_url",
    "char_entropy",
    
    # Host & Protocol Heuristics (20-25)
    "is_ip_address",
    "is_https",
    "has_punycode",
    "is_shortened",
    "has_port",
    "is_unusual_port",
    
    # Deceptive / High-Risk Keyword Indicators (26-31)
    "has_login_keyword",
    "has_verify_keyword",
    "has_secure_keyword",
    "has_update_keyword",
    "has_account_keyword",
    "has_banking_keyword",
    
    # TLD & Token Runs (32-33)
    "count_tld_tokens",
    "consecutive_char_run",
]

# Regex patterns
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "qr.ae", "trib.al", "adf.ly", "goo.gl", "bit.do"
}

LOGIN_KEYWORDS = ("login", "signin", "auth", "portal", "sso", "webmail")
VERIFY_KEYWORDS = ("verify", "verification", "confirm", "validate", "kyc", "otp")
SECURE_KEYWORDS = ("secure", "security", "safe", "ssl", "protect")
UPDATE_KEYWORDS = ("update", "upgrade", "renew", "alert", "suspended", "urgent", "unlock")
ACCOUNT_KEYWORDS = ("account", "user", "member", "profile", "wallet", "identity")
BANKING_KEYWORDS = ("bank", "pay", "refund", "fee", "invoice", "scholarship", "deposit", "transfer")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of characters in string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def max_consecutive_run(text: str) -> int:
    """Finds maximum consecutive repeated character run length."""
    if not text:
        return 0
    max_run = 1
    curr_run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            curr_run += 1
            if curr_run > max_run:
                max_run = curr_run
        else:
            curr_run = 1
    return max_run


def extract_url_feature_dict(url: str) -> Dict[str, Union[int, float]]:
    """
    Extracts all 34 features into a structured dictionary matching URL_FEATURE_SCHEMA_V1.
    """
    url = url.strip()
    url_lower = url.lower()
    
    # Safe URL split
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        parsed = urllib.parse.urlsplit("http://malformed.local")

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    netloc = parsed.netloc if parsed.netloc else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    
    # Split host and port safely
    port = None
    host = netloc
    if ":" in netloc and not netloc.endswith("]"):
        parts = netloc.split(":")
        host = parts[0]
        try:
            port = int(parts[1])
        except (ValueError, IndexError):
            port = None

    url_len = len(url)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    # Character counts
    dots = url.count(".")
    hyphens = url.count("-")
    underscores = url.count("_")
    slashes = url.count("/")
    qmarks = url.count("?")
    equals = url.count("=")
    ats = url.count("@")
    ampersands = url.count("&")
    percents = url.count("%")
    digits = sum(1 for c in url if c.isdigit())
    letters = sum(1 for c in url if c.isalpha())

    # Subdomain calculation
    host_labels = [label for label in host.split(".") if label]
    subdomains_count = max(0, len(host_labels) - 2) if len(host_labels) > 2 else 0

    # Ratios
    digit_ratio_url = digits / url_len if url_len > 0 else 0.0
    host_digits = sum(1 for c in host if c.isdigit())
    digit_ratio_host = host_digits / host_len if host_len > 0 else 0.0
    letter_ratio_url = letters / url_len if url_len > 0 else 0.0
    entropy = calculate_entropy(url)

    # Boolean & categorical heuristics
    is_ip = 1 if IPV4_REGEX.match(host) or host.startswith("[") else 0
    is_https = 1 if scheme == "https" else 0
    has_punycode = 1 if "xn--" in host.lower() else 0
    is_short = 1 if host.lower() in SHORTENER_DOMAINS else 0
    has_port = 1 if port is not None else 0
    is_unusual_port = 1 if (port is not None and port not in (80, 443, 8080)) else 0

    # Deceptive keywords
    has_login = 1 if any(k in url_lower for k in LOGIN_KEYWORDS) else 0
    has_verify = 1 if any(k in url_lower for k in VERIFY_KEYWORDS) else 0
    has_secure = 1 if any(k in url_lower for k in SECURE_KEYWORDS) else 0
    has_update = 1 if any(k in url_lower for k in UPDATE_KEYWORDS) else 0
    has_account = 1 if any(k in url_lower for k in ACCOUNT_KEYWORDS) else 0
    has_banking = 1 if any(k in url_lower for k in BANKING_KEYWORDS) else 0

    # TLD token count
    tld_tokens = 1
    if len(host_labels) >= 2:
        last_label = host_labels[-1].lower()
        penultimate_label = host_labels[-2].lower()
        if len(last_label) == 2 and penultimate_label in ("co", "ac", "gov", "org", "net", "edu"):
            tld_tokens = 2

    consec_run = max_consecutive_run(url)

    # Pack in strict schema ordering
    return {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "count_dots": dots,
        "count_hyphens": hyphens,
        "count_underscores": underscores,
        "count_slashes": slashes,
        "count_question_marks": qmarks,
        "count_equals": equals,
        "count_at": ats,
        "count_ampersands": ampersands,
        "count_percent": percents,
        "count_digits": digits,
        "count_letters": letters,
        "count_subdomains": subdomains_count,
        "digit_ratio_url": round(digit_ratio_url, 4),
        "digit_ratio_host": round(digit_ratio_host, 4),
        "letter_ratio_url": round(letter_ratio_url, 4),
        "char_entropy": round(entropy, 4),
        "is_ip_address": is_ip,
        "is_https": is_https,
        "has_punycode": has_punycode,
        "is_shortened": is_short,
        "has_port": has_port,
        "is_unusual_port": is_unusual_port,
        "has_login_keyword": has_login,
        "has_verify_keyword": has_verify,
        "has_secure_keyword": has_secure,
        "has_update_keyword": has_update,
        "has_account_keyword": has_account,
        "has_banking_keyword": has_banking,
        "count_tld_tokens": tld_tokens,
        "consecutive_char_run": consec_run,
    }


def extract_url_feature_vector(url: str) -> np.ndarray:
    """
    Extracts features as a 1D numpy float64 array matching URL_FEATURE_SCHEMA_V1 ordering.
    """
    feat_dict = extract_url_feature_dict(url)
    return np.array([feat_dict[k] for k in URL_FEATURE_SCHEMA_V1], dtype=np.float64)


def extract_domain_group(url: str) -> str:
    """
    Extracts registered domain (or second-level domain) for anti-leakage group splitting.
    """
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        netloc = parsed.netloc.lower()
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        labels = [l for l in netloc.split(".") if l]
        if len(labels) >= 2:
            if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "ac", "gov", "org", "net", "edu"):
                return ".".join(labels[-3:])
            return ".".join(labels[-2:])
        return netloc if netloc else "unknown_domain"
    except Exception:
        return "unknown_domain"
