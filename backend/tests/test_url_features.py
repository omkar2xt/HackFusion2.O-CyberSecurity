"""
SignalSafe Campus - Unit Tests for URL Feature Engineering Pipeline
Module: backend/tests/test_url_features.py
"""

from typing import List
import pytest

from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA,
    URL_FEATURE_SCHEMA_VERSION,
    URLFeatures,
    URLNormalizationResult,
    batch_extract_url_feature_vectors,
    extract_url_feature_dict,
    extract_url_feature_vector,
    extract_url_features,
    normalize_url,
)


class TestURLFeatureSchema:
    """Verifies schema versioning, immutability, and metadata completeness."""

    def test_schema_version_and_dimensions(self):
        assert URL_FEATURE_SCHEMA_VERSION == "1.0.0"
        assert len(URL_FEATURE_NAMES) == 34
        assert len(URL_FEATURE_SCHEMA) == 34

    def test_schema_keys_match_ordering_tuple(self):
        for idx, name in enumerate(URL_FEATURE_NAMES):
            assert name in URL_FEATURE_SCHEMA, f"Feature {name} missing from schema definition"
            meta = URL_FEATURE_SCHEMA[name]
            assert "type" in meta
            assert "description" in meta
            assert "logic" in meta
            assert "missing_value" in meta

    def test_identical_training_and_inference_schema(self):
        test_url = "https://sub.target.org/path/login?query=1"
        dict_features = extract_url_feature_dict(test_url)
        vector_features = extract_url_feature_vector(test_url)

        assert len(dict_features) == len(URL_FEATURE_NAMES)
        assert len(vector_features) == len(URL_FEATURE_NAMES)

        # Ensure vector features match dictionary values in exact index order
        for idx, name in enumerate(URL_FEATURE_NAMES):
            expected_val = float(dict_features[name])
            assert vector_features[idx] == pytest.approx(expected_val)


class TestDeterministicExtraction:
    """Ensures that identical input strings produce strictly identical vectors."""

    def test_repeated_calls_are_bit_identical(self):
        url = "https://portal.bank-verification.com/login?token=abc#section"
        baseline_vec = extract_url_feature_vector(url)

        for _ in range(10):
            current_vec = extract_url_feature_vector(url)
            assert current_vec == baseline_vec


class TestValidURLParsing:
    """Tests feature extraction for legitimate standard HTTP and HTTPS URLs."""

    def test_standard_http_url(self):
        url = "http://example.com/index.html"
        norm = normalize_url(url)
        assert norm.is_valid is True
        assert norm.scheme == "http"
        assert norm.hostname == "example.com"
        assert norm.registrable_domain == "example.com"
        assert norm.tld == "com"
        assert norm.subdomain == ""

        feats = extract_url_features(url)
        assert feats.is_https == 0
        assert feats.is_ip_address == 0
        assert feats.has_non_standard_port == 0
        assert feats.subdomain_count == 0

    def test_standard_https_campus_url(self):
        url = "https://campus.university.edu/student/portal"
        norm = normalize_url(url)
        assert norm.is_valid is True
        assert norm.scheme == "https"
        assert norm.hostname == "campus.university.edu"
        assert norm.registrable_domain == "university.edu"
        assert norm.subdomain == "campus"
        assert norm.tld == "edu"

        feats = extract_url_features(url)
        assert feats.is_https == 1
        assert feats.subdomain_count == 1
        assert feats.tld_length == 3


class TestHTTPSDoesNotDetermineLegitimacy:
    """
    CRITICAL ARCHITECTURAL TEST:
    Demonstrates that HTTPS alone must not be used as proof of legitimacy,
    and HTTP alone must not be treated as proof of maliciousness.
    """

    def test_phishing_url_with_valid_https(self):
        # Modern phishing attack using Let's Encrypt SSL on multi-subdomain target
        phish_url = "https://secure-login-update.account-verification-service.com/login.php?user=victim"
        feats = extract_url_features(phish_url)

        # The URL uses HTTPS, but possesses strong structural phishing signals
        assert feats.is_https == 1  # Uses HTTPS transport encryption
        assert feats.has_hyphen_in_domain == 1  # Hyphenated spoofing domain
        assert feats.hyphen_count_domain >= 2
        assert feats.suspicious_keyword_in_domain == 1
        assert feats.suspicious_keyword_in_path == 1
        assert feats.suspicious_keyword_count >= 3  # 'secure', 'login', 'update', 'account', 'verification'
        assert feats.subdomain_count >= 1

    def test_legitimate_educational_service_with_http(self):
        # Legacy legitimate internal or departmental resource running HTTP
        legit_http_url = "http://math.university.edu/faculty/notes"
        feats = extract_url_features(legit_http_url)

        # Uses HTTP, but lacks malicious structural heuristics
        assert feats.is_https == 0
        assert feats.has_hyphen_in_domain == 0
        assert feats.suspicious_keyword_count == 0
        assert feats.suspicious_keyword_in_domain == 0
        assert feats.suspicious_keyword_in_path == 0
        assert feats.is_ip_address == 0


class TestIPBasedURLs:
    """Tests detection of IPv4, IPv6, ports, and obfuscated decimal/hex IP representations."""

    def test_ipv4_with_standard_port(self):
        url = "http://192.168.1.100/admin.php"
        feats = extract_url_features(url)
        assert feats.is_ip_address == 1
        assert feats.has_non_standard_port == 0

    def test_ipv4_with_non_standard_port(self):
        url = "http://10.0.0.1:8080/setup"
        feats = extract_url_features(url)
        assert feats.is_ip_address == 1
        assert feats.has_non_standard_port == 1

    def test_ipv6_url(self):
        url = "http://[2001:db8::1]/status"
        feats = extract_url_features(url)
        assert feats.is_ip_address == 1

    def test_decimal_integer_ip_representation(self):
        # 2130706433 = 127.0.0.1
        url = "http://2130706433/malware"
        feats = extract_url_features(url)
        assert feats.is_ip_address == 1


class TestInternationalizedDomainsAndPunycode:
    """Tests IDN homograph attack indicators."""

    def test_punycode_domain(self):
        # xn--pple-43d.com is homograph for аpple.com (Cyrillic 'а')
        url = "https://xn--pple-43d.com/login"
        feats = extract_url_features(url)
        assert feats.is_punycode == 1
        assert feats.suspicious_keyword_in_path == 1

    def test_non_punycode_domain(self):
        url = "https://apple.com/login"
        feats = extract_url_features(url)
        assert feats.is_punycode == 0


class TestURLEncodingAndObfuscation:
    """Tests percent-encoding, userinfo credential obfuscation, and path redirection evasion."""

    def test_percent_encoding_count(self):
        # URL with hex-encoded tokens
        url = "https://portal.bank.com/%75%73%65%72%2F%6C%6F%67%69%6E"
        feats = extract_url_features(url)
        assert feats.percent_count >= 5

    def test_at_symbol_credential_obfuscation(self):
        # Attacker crafts URL where browser ignores credentials before @ and navigates to phishingsite.com
        url = "https://legit-brand.com@phishingsite.com/login"
        norm = normalize_url(url)
        assert norm.hostname == "phishingsite.com"
        assert norm.registrable_domain == "phishingsite.com"

        feats = extract_url_features(url)
        assert feats.at_symbol_count == 1
        assert feats.hostname_length == len("phishingsite.com")

    def test_double_slash_in_path(self):
        url = "https://trusted-site.com//redirect?url=http://evil.com"
        feats = extract_url_features(url)
        assert feats.double_slash_in_path == 1


class TestSuspiciousFileExtensionsAndKeywords:
    """Tests executable extension detection and credential keyword heuristics."""

    def test_suspicious_payload_extensions(self):
        payload_urls = [
            "http://malicious.org/update.exe",
            "http://malicious.org/patch.zip",
            "http://malicious.org/installer.apk",
            "http://malicious.org/script.bat",
        ]
        for u in payload_urls:
            feats = extract_url_features(u)
            assert feats.suspicious_file_extension == 1, f"Failed on {u}"

    def test_innocuous_extensions(self):
        innocuous_urls = [
            "http://example.com/index.html",
            "http://example.com/style.css",
            "http://example.com/logo.png",
            "http://example.com/document.pdf",
        ]
        for u in innocuous_urls:
            feats = extract_url_features(u)
            assert feats.suspicious_file_extension == 0, f"False positive on {u}"


class TestMissingAndMalformedInputs:
    """Verifies that the extractor handles missing, malformed, and adversarial inputs gracefully."""

    def test_none_input(self):
        feats = extract_url_features(None)
        assert feats.url_length == 0
        assert feats.hostname_length == 0
        assert feats.is_https == 0
        vec = extract_url_feature_vector(None)
        assert len(vec) == 34
        assert all(isinstance(x, (int, float)) for x in vec)

    def test_empty_string(self):
        feats = extract_url_features("")
        assert feats.url_length == 0
        vec = extract_url_feature_vector("")
        assert len(vec) == 34

    def test_whitespace_string(self):
        feats = extract_url_features("   \t  \n ")
        assert feats.url_length == 0

    def test_non_string_input(self):
        feats = extract_url_features(12345)
        assert isinstance(feats, URLFeatures)

    def test_null_byte_rejection(self):
        url = "http://example.com/\x00malicious"
        norm = normalize_url(url)
        assert norm.is_valid is False
        assert "control characters" in norm.error_reason

    def test_overly_long_url_rejection(self):
        long_url = "http://example.com/" + ("a" * 4100)
        norm = normalize_url(long_url)
        assert norm.is_valid is False
        assert "maximum permitted length" in norm.error_reason


class TestBatchExtraction:
    """Tests batch matrix creation."""

    def test_batch_vectors(self):
        urls = [
            "https://google.com",
            "http://192.168.1.1/admin",
            "https://xn--pple-43d.com",
            None,
        ]
        batch = batch_extract_url_feature_vectors(urls)
        assert len(batch) == 4
        assert all(len(row) == 34 for row in batch)
