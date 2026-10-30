# SignalSafe Campus — URL Feature Schema Specification (Version 1.0.0)

**Module Reference**: [`backend/app/services/detection/url_features.py`](file:///d:/work/hack2.0/HackFusion2.O-CyberSecurity/backend/app/services/detection/url_features.py)  
**Schema Version**: `1.0.0`  
**Dimensionality**: Exactly 34 features  
**Execution Type**: Pure static lexical & structural analysis (Zero network requests, zero DNS queries)  
**Environment Consistency Guarantee**: The exact same schema, normalization, and ordering are shared between offline dataset harmonization/training and live API inference (`POST /api/v1/scan/url` & `POST /api/v1/scan/qr`).

---

## 1. Design Principles & Anti-Bias Controls

1. **HTTPS Is Not Proof of Legitimacy**:
   * Modern phishing campaigns routinely provision valid SSL/TLS certificates (e.g. Let's Encrypt).
   * Feature `is_https` represents transport layer encryption status only. It must **never** be used as a standalone indicator of benign classification.
2. **Elimination of Source-Specific Shortcuts**:
   * LegitPhish's pre-computed features possessed a $+0.9292$ correlation between `https_flag` and legitimacy due to URLhaus sampling bias.
   * `URL_FEATURE_SCHEMA_V1` operates strictly on **raw URL strings**, extracting a balanced set of structural, character-density, entropy, and sensitive keyword indicators.
3. **Deterministic Immutability**:
   * Feature names and indices are defined by a frozen tuple (`URL_FEATURE_NAMES`).
   * Extraction output formats:
     * `extract_url_features(url) -> URLFeatures`: Strongly typed dataclass.
     * `extract_url_feature_dict(url) -> Dict[str, float | int]`: Keyed dictionary.
     * `extract_url_feature_vector(url) -> List[float]`: Fixed 34-element array aligned index-by-index with `URL_FEATURE_NAMES`.
4. **Adversarial Resilience**:
   * Safely handles null bytes, ASCII control characters, non-string types, missing schemes, punycode IDN homographs, userinfo `@` credential masking, and double-slash redirection evasion.
   * Unparseable or malformed URLs fall back gracefully to a schema-compliant zero-padded vector without throwing exceptions.

---

## 2. Comprehensive 34-Feature Specification Matrix

| Index | Feature Name | Data Type | Value Range | Missing / Default | Extraction Logic & Security Context |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | `url_length` | `int` | $[0, 4096]$ | `0` | Character length of the normalized URL. Phishing URLs often use excessive length to obscure real destinations. |
| **1** | `hostname_length` | `int` | $[0, 255]$ | `0` | Character length of the fully qualified domain name (FQDN). |
| **2** | `path_length` | `int` | $[0, 4096]$ | `0` | Character length of the path component. |
| **3** | `query_length` | `int` | $[0, 4096]$ | `0` | Character length of the query string following `?`. |
| **4** | `dot_count` | `int` | $[0, 100]$ | `0` | Total `.` characters across the entire URL. |
| **5** | `dot_count_domain` | `int` | $[0, 20]$ | `0` | Dots in the hostname. Abnormally high dots indicate deep nested subdomains. |
| **6** | `hyphen_count` | `int` | $[0, 100]$ | `0` | Total `-` characters across the entire URL. |
| **7** | `hyphen_count_domain` | `int` | $[0, 20]$ | `0` | Count of hyphens in hostname. Attackers frequently use hyphens to stitch brand names (e.g. `login-campus-portal.com`). |
| **8** | `has_hyphen_in_domain` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary indicator for whether the hostname contains at least one hyphen. |
| **9** | `underscore_count` | `int` | $[0, 50]$ | `0` | Total `_` characters in the URL string. |
| **10** | `slash_count` | `int` | $[0, 100]$ | `0` | Total `/` characters in the URL string. |
| **11** | `double_slash_in_path` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag for `//` in URL path. Common open redirect or reverse-proxy evasion vector. |
| **12** | `at_symbol_count` | `int` | $[0, 10]$ | `0` | Count of `@` symbols. Standard HTTP userinfo trick (`https://google.com@evil.com/login`). |
| **13** | `question_mark_count` | `int` | $[0, 20]$ | `0` | Count of `?` in URL. |
| **14** | `equal_count` | `int` | $[0, 50]$ | `0` | Count of `=` characters (parameter assignments). |
| **15** | `ampersand_count` | `int` | $[0, 50]$ | `0` | Count of `&` characters (query parameter chaining). |
| **16** | `percent_count` | `int` | $[0, 100]$ | `0` | Count of `%` characters indicating percent-encoded byte sequences. |
| **17** | `is_https` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if scheme is `https`, `0` otherwise. **Transport security indicator only; NOT legitimacy proof.** |
| **18** | `is_ip_address` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if host is IPv4, IPv6, or decimal/hex integer IP. |
| **19** | `has_non_standard_port` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if an explicit port other than 80 or 443 is declared. |
| **20** | `subdomain_count` | `int` | $[0, 10]$ | `0` | Depth count of subdomain labels preceding the registrable domain. |
| **21** | `subdomain_length` | `int` | $[0, 255]$ | `0` | Total character length of subdomain prefix. |
| **22** | `tld_length` | `int` | $[0, 24]$ | `0` | Character length of extracted TLD / multi-part ccTLD (e.g. `co.uk` = 5). |
| **23** | `is_punycode` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if hostname contains `xn--` (IDN homograph attack indicator). |
| **24** | `digit_count` | `int` | $[0, 200]$ | `0` | Total numeric characters (`0-9`) in entire URL. |
| **25** | `digit_count_domain` | `int` | $[0, 50]$ | `0` | Total numeric characters in hostname. |
| **26** | `percentage_numeric_chars` | `float` | $[0.0, 100.0]$ | `0.0` | `(digit_count / url_length) * 100.0`. |
| **27** | `percentage_numeric_chars_domain` | `float` | $[0.0, 100.0]$ | `0.0` | `(digit_count_domain / hostname_length) * 100.0`. |
| **28** | `url_entropy` | `float` | $[0.0, 8.0]$ | `0.0` | Shannon entropy of full URL character distribution ($H(X) = -\sum p_i \log_2 p_i$). |
| **29** | `domain_entropy` | `float` | $[0.0, 8.0]$ | `0.0` | Shannon entropy of hostname character distribution. Detects DGA domains. |
| **30** | `suspicious_file_extension` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if URL path ends with executable/payload extensions (`.exe`, `.zip`, `.apk`, `.bat`, etc.). |
| **31** | `suspicious_keyword_count` | `int` | $[0, 20]$ | `0` | Frequency of security/credential keywords (`login`, `verify`, `account`, `banking`, etc.). |
| **32** | `suspicious_keyword_in_domain` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if sensitive keyword is embedded within hostname. |
| **33** | `suspicious_keyword_in_path` | `int` (0/1) | $\{0, 1\}$ | `0` | Binary flag: `1` if sensitive keyword appears in path or query. |

---

## 3. Registrable Domain & Multi-Part ccTLD Resolution

To support clean domain-stratified splitting (Group-KFold) without domain leakage, the engine resolves multi-part public suffixes using an internal, standard-library ccTLD lookup table:
* Supported multi-part suffixes include: `.co.uk`, `.org.uk`, `.com.au`, `.edu.pe`, `.org.ng`, `.gov.za`, `.com.ro`, etc.
* Example Resolution:
  * Input: `https://nsdm.cumpar-auto-orice-tip.ro/login`
  * Subdomain: `nsdm`
  * Registrable Domain: `cumpar-auto-orice-tip.ro`
  * TLD: `ro`
  * Group-KFold Partition Key: `cumpar-auto-orice-tip.ro` (All 964 variants stay in the same split).
