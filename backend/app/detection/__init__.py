"""
SignalSafe Campus - Detection Engine Package
Reserved for Milestone 2: URL rules, punycode normalizer, message parser, scoring engine.
"""

from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA_VERSION,
    URL_FEATURE_SCHEMA,
    extract_url_feature_dict,
    extract_url_feature_vector,
    normalize_url,
    URLFeatures,
    URLNormalizationResult,
)

__all__ = [
    "URL_FEATURE_NAMES",
    "URL_FEATURE_SCHEMA_VERSION",
    "URL_FEATURE_SCHEMA",
    "extract_url_feature_dict",
    "extract_url_feature_vector",
    "normalize_url",
    "URLFeatures",
    "URLNormalizationResult",
]
