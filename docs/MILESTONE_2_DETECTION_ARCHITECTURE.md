# SignalSafe Campus — Milestone 2: Hybrid Detection Engine Architecture & Technical Planning

**Version:** 2.0-DRAFT  
**Status:** Architecture & Planning — Awaiting Approval Before Implementation  
**Date:** 2026-10-30  
**Author:** Backend/Security Architect  
**Prerequisite:** Milestone 1 — Backend Foundation & Database Security Verification (completed)

---

> **STOP — PLANNING DOCUMENT ONLY**
> This document is a planning and design report. No detection engine has been implemented, no models have been trained, no dependencies have been installed, no migrations have been modified, and no live Supabase project has been contacted. Implementation must not begin until this document is reviewed and approved.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Task 1 — Dataset Audit](#2-task-1--dataset-audit)
3. [Task 2 — ML Architecture Selection](#3-task-2--ml-architecture-selection)
4. [Task 3 — Detection Engine Module Design](#4-task-3--detection-engine-module-design)
5. [Task 4 — Risk Scoring Design](#5-task-4--risk-scoring-design)
6. [Task 5 — Threat Intelligence Integration](#6-task-5--threat-intelligence-integration)
7. [Task 6 — Database and API Compatibility](#7-task-6--database-and-api-compatibility)
8. [Task 7 — Testing and Evaluation Strategy](#8-task-7--testing-and-evaluation-strategy)
9. [Proposed Dependencies](#9-proposed-dependencies)
10. [Phased Implementation Plan](#10-phased-implementation-plan)
11. [Technical Risks and Unresolved Decisions](#11-technical-risks-and-unresolved-decisions)
12. [Verified Facts vs. Assumptions](#12-verified-facts-vs-assumptions)

---

## 1. Executive Summary

Milestone 2 introduces a **Hybrid Detection Engine** combining three independent evidence sources:

- **Machine Learning (ML):** URL phishing classification using feature-engineered tabular models. QR and document classification deferred to Milestone 3+.
- **Threat Intelligence (TI):** Adapter-based integration with Google Safe Browsing, VirusTotal, and URLhaus.
- **Rule-Based Detection:** Deterministic heuristics for URL structure, domain impersonation, typosquatting, and credential-harvesting indicators.

Evidence from all three sources is correlated, scored, and explained by the detection engine. The existing FastAPI backend, Supabase schema, OpenAPI 3.1 contract, and authentication architecture are preserved without modification.

The existing mock scan endpoints (`POST /api/v1/scan/url`, `/scan/message`, `/scan/qr`) will be connected to the real detection engine. The response contract remains identical to the OpenAPI contract.

---

## 2. Task 1 — Dataset Audit

### 2.1 Audit Scope

The dataset files have NOT been downloaded locally. This audit is based on the public dataset description pages, accessed on 2026-10-30. Local file inspection is required before model training begins. Unverified claims are explicitly marked.

---

### 2.2 Dataset A — LegitPhish (Mendeley Data, Version 2)

**URL:** https://data.mendeley.com/datasets/hx4m73v2sf/2  
**DOI:** 10.17632/hx4m73v2sf.2  
**Authors:** Potpelwar, Rachana; Kulkarni, Uday; Waghmare, Jaishri (May 2025)  
**License:** CC BY 4.0 (confirmed from Mendeley Data standard licensing)

#### File Format
Tabular CSV (inferred from dataset type; file name and byte count not confirmed — requires local verification).

#### Sample Count and Label Distribution (from dataset description page)

| Label Value | Class | Count |
|---|---|---|
| 0 | Phishing | 63,678 |
| 1 | Legitimate | 37,540 |
| — | **Total** | **~101,219** |

**Class Imbalance Warning:** 63% phishing / 37% legitimate. This is not balanced. Training without addressing this will produce a model biased toward predicting phishing. Class weights, stratified sampling, or cost-sensitive learning must be applied.

#### Feature Schema (18 columns including label)

| Feature Name | Type | Description |
|---|---|---|
| `URL` | string | Full URL string |
| `url_length` | integer | Total character count |
| `has_ip_address` | binary (0/1) | Whether URL contains an IP address |
| `dot_count` | integer | Number of `.` characters |
| `https_flag` | binary (0/1) | Whether scheme is HTTPS |
| `url_entropy` | float | Shannon entropy of URL string |
| `token_count` | integer | Token/word count in URL |
| `subdomain_count` | integer | Number of subdomains |
| `query_param_count` | integer | Number of query string parameters |
| `tld_length` | integer | Length of TLD string |
| `path_length` | integer | Length of path segment |
| `has_hyphen_in_domain` | binary (0/1) | Whether domain contains hyphen |
| `number_of_digits` | integer | Count of numeric characters |
| `tld_popularity` | binary (0/1) | Whether TLD is a popular one |
| `suspicious_file_extension` | binary (0/1) | Whether path ends with suspicious extension |
| `domain_name_length` | integer | Domain name character length |
| `percentage_numeric_chars` | float | Percentage of numeric characters in full URL |
| `ClassLabel` | binary (0/1) | Target: 1=Legitimate, 0=Phishing |

#### Data Sources
- **Phishing:** URLhaus database and scraped repositories. Authors claim manual verification.
- **Legitimate:** Wikipedia and Stack Overflow pages, randomly scraped.

#### Known Quality Issues and Risks

| Issue | Severity | Notes |
|---|---|---|
| Class imbalance (63%/37%) | HIGH | Must apply class weighting during training |
| Legitimate source bias | MEDIUM | Wikipedia/SO may not represent campus phishing targets; may cause FPs on academic URLs |
| URLhaus phishing source | MEDIUM | Known/old threats; may not generalize to novel phishing |
| Duplicate records | UNKNOWN | Must verify with `df.duplicated()` on `URL` column after download |
| Missing values | UNKNOWN | Must verify with `df.isnull().sum()` after download |
| Pre-computed feature leakage | MEDIUM | `tld_popularity` embeds external popularity rankings of unknown date |
| Temporal drift | UNKNOWN | Phishing URLs from URLhaus may be stale/delisted |
| Feature methodology | MEDIUM | Extraction method and any normalization applied by authors is not documented in detail |

---

### 2.3 Dataset B — CIC-Trap4Phish 2025 (UNB/CIC)

**URL:** https://www.unb.ca/cic/datasets/trap4phish2025.html  
**Download:** http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/  
**Paper:** Nejati et al., arXiv:2602.09015, February 2026  
**License:** NOT CONFIRMED — README files in download package must be read before use

#### Sample Count by Format

| Format | Benign | Malicious | Total | Feature Method |
|---|---|---|---|---|
| Word (DOC/DOCX) | 10,000 | 10,000 | 20,000 | Static (43 extracted, 10 selected) |
| Excel (XLS/XLSX) | 10,000 | 10,000 | 20,000 | Static (48 extracted, 10 selected) |
| PDF | 10,000 | 10,000 | 20,000 | Static (40 extracted, 10 selected) |
| HTML | 10,000 | 10,000 | 20,000 | Static (40 extracted, 13 selected) |
| QR Code (images) | 430,000 | 575,000 | ~1,000,000 | Image-based CNN |
| URL Strings | 433,918 | 614,656 | ~1,048,576 | Transformer / lexical |

**Total across all formats: ~1,128,576 samples**

#### Relevance to SignalSafe Campus Milestone 2

| Format | Milestone 2 Relevance |
|---|---|
| Word, Excel, PDF, HTML | Milestone 3+ (document scanning) |
| **QR Code images** | Partially relevant — CNN approach deferred to M3; decoded URL is routed through URL analyzer in M2 |
| **URL Strings** | **Directly relevant** — supplement LegitPhish for URL classifier training |

#### Quality Risks

| Issue | Severity | Notes |
|---|---|---|
| License not confirmed | HIGH | Must read README before any use |
| Download registration required | MEDIUM | Test download access at cicresearch.ca |
| Exact feature column names | UNKNOWN | Named in README; not published on web page |
| URL class imbalance (~59% malicious) | MEDIUM | Requires class weighting |
| Synthetic samples included | MEDIUM | May not reflect real attack distributions |
| Overlap with LegitPhish URLs | UNKNOWN | Both draw from phishing repositories; must deduplicate |
| QR image dataset size | HIGH OPERATIONAL | 1M images requires significant storage; GPU training at 6GB VRAM requires careful memory management |

---

### 2.4 Cross-Dataset Concerns

| Concern | Risk | Action |
|---|---|---|
| URL overlap between LegitPhish phishing and CIC URL Strings | HIGH | Cross-dataset URL fingerprint deduplication before any split |
| Temporal leakage (old URLs in training, newer in test) | MEDIUM | Split by collection date if timestamps available |
| Feature leakage from pre-computed binary flags | MEDIUM | Document feature extraction methodology; re-extract features at inference time |

---

### 2.5 Required Actions Before Training

1. Download LegitPhish CSV; run `df.info()`, `df.isnull().sum()`, `df.duplicated().sum()`, `df['ClassLabel'].value_counts()`.
2. Download CIC-Trap4Phish; read ALL README files for each format.
3. Verify exact feature column names and types in CIC URL Strings CSV.
4. Cross-deduplicate URLs between LegitPhish and CIC URL Strings by normalized URL hash.
5. Confirm CIC license terms; document in `docs/DATA_LICENSES.md`.
6. Assess whether QR image CNN training is feasible within 6GB VRAM given the 1M image scale.
7. Determine if CIC download requires institutional registration.

---

## 3. Task 2 — ML Architecture Selection

### 3.1 Hardware Constraints

| Resource | Specification | Implication |
|---|---|---|
| CPU | Intel i7-14700HX (20 cores) | Excellent for tabular ML; XGBoost CPU is fast |
| GPU | NVIDIA RTX 4050 — 6 GB VRAM | Adequate for small CNN fine-tuning; GPU XGBoost feasible |
| RAM | 16 GB | Constrains in-memory dataset size; chunked loading for >500K samples |
| OS | Windows | Use CUDA 12.x PyTorch builds; XGBoost GPU via CUDA |
| Python | 3.12 | All proposed libraries support Python 3.12 |

### 3.2 Task A — URL Phishing Classification (Primary, Milestone 2)

**Problem:** Binary classification — Phishing vs. Legitimate  
**Features:** 17 numerical/binary features (LegitPhish schema) extracted at inference time  
**Training data:** LegitPhish + CIC URL Strings (after deduplication)

#### Algorithm Comparison

| Algorithm | Advantages | Disadvantages | Decision |
|---|---|---|---|
| **Logistic Regression** | Fastest training and inference; interpretable coefficients; works on scaled features; no GPU | Assumes linearity; poor on complex patterns | Use as **interpretable baseline** |
| **Random Forest** | Handles non-linearities; no scaling needed; built-in feature importance; robust to outliers | Slower than gradient boosting; larger model file | Use as **primary candidate** |
| **XGBoost** | State-of-the-art tabular performance; GPU-accelerated; `scale_pos_weight` for imbalance | More hyperparameters; can overfit | Use as **primary challenger** — likely best F1 |
| **LightGBM** | Fastest training; low memory; GPU support | Less interpretable; can overfit on small data | Use for **production inference speed** |
| CNN (URL) | Character-level pattern learning | Overkill for feature-engineered tabular data; needs more data | **Do not use** for feature-engineered URL data |

**Recommended production model:** XGBoost (GPU) as primary, LightGBM as inference-speed fallback, Logistic Regression as baseline.

**Calibration:** All models must use Platt Scaling (`CalibratedClassifierCV`) so probability outputs are calibrated. Raw XGBoost scores are NOT treated as probabilities.

---

### 3.3 Task B — QR Phishing Detection

**Milestone 2 approach:** Route decoded URL through the URL analysis pipeline. No QR-specific model.

The API contract already defines `POST /api/v1/scan/qr` accepting `decoded_content` (the decoded URL string). The backend routes this through the URL analyzer. No QR image is ever sent to the backend.

**Future Milestone 3 approach (QR image CNN):** If client cannot decode QR, a CNN can classify the raw image.

Recommended CNN for 6GB VRAM:

| Architecture | Parameters | VRAM (est.) | Recommendation |
|---|---|---|---|
| MobileNetV3-Small | ~2.5M | ~1.5 GB | Best fit; fine-tune from ImageNet weights |
| EfficientNet-B0 | ~5.3M | ~2.5 GB | Good accuracy/speed tradeoff |
| ResNet-18 | ~11M | ~3 GB | Heavier but feasible |
| ResNet-50 | ~25M | ~5.5 GB | Marginal; requires small batch size |
| ViT-B (Vision Transformer) | ~86M | Exceeds 6GB | Not feasible |

**MobileNetV3-Small** is recommended if QR CNN is pursued in Milestone 3. Use mixed precision (fp16) to double effective batch size.

---

### 3.4 Recommended ML Library Stack

| Library | Version | Purpose |
|---|---|---|
| `scikit-learn` | >=1.5.0 | RF, LR, calibration, metrics, splitting |
| `xgboost` | >=2.0.0 | Primary model (CUDA GPU acceleration) |
| `lightgbm` | >=4.4.0 | Fast inference fallback |
| `joblib` | >=1.4.0 | Model serialization |
| `shap` | >=0.46.0 | Feature contribution explanations (TreeExplainer for speed) |
| `tldextract` | >=5.1.0 | Reliable TLD/domain/subdomain extraction |
| `cachetools` | >=5.3.0 | In-process TTL cache for TI results |
| `pandas`, `numpy` | Latest stable | Training data manipulation |

---

## 4. Task 3 — Detection Engine Module Design

### 4.1 Module Architecture Diagram

```
Client Input (URL / Message / QR decoded content)
         |
         v
┌──────────────────────┐
│  input_normalizer    │  Validates, sanitizes, canonicalizes; SSRF guard
└──────────┬───────────┘
           |
    ┌──────┴──────────────────────────┐
    |                                 |
    v                                 v
┌──────────────┐             ┌─────────────────┐
│ url_analyzer │             │message_analyzer  │
│ (rule-based) │             │(text heuristics) │
└──────┬───────┘             └────────┬─────────┘
       |                              |
       └──────────────────────────────┘
                    |
        ┌───────────┴───────────────────┐
        |                               |
        v                               v
┌──────────────────┐         ┌─────────────────────────┐
│   rule_engine    │         │   threat_intelligence    │
│  (coordinator)   │         │  (parallel TI lookups)  │
└────────┬─────────┘         └──────────┬──────────────┘
         |                              |
         |        ┌─────────────────────┘
         |        |
         v        v
     ┌─────────────────┐
     │   ml_engine     │  (URL classifier; fallback-safe)
     └────────┬────────┘
              |
              v
     ┌─────────────────────────┐
     │   evidence_correlator   │  Deduplicates, merges, weights
     └────────┬────────────────┘
              |
              v
     ┌─────────────────┐
     │   risk_scorer   │  Versioned scoring policy
     └────────┬────────┘
              |
              v
     ┌──────────────────────────┐
     │  explanation_generator   │  User-facing indicators + recommendations
     └──────────────────────────┘
              |
              v
     ScanResult → API Response → Database Persistence
```

---

### 4.2 Module Specifications

#### Module 1: `input_normalizer`

**File:** `backend/app/detection/input_normalizer.py`

**Responsibility:** Accept raw client input, validate strictly, and produce a safe normalized internal representation.

**Outputs — `NormalizedInput` dataclass:**
- `original_value: str`
- `input_type: Literal["URL", "MESSAGE", "QR"]`
- `extracted_urls: list[str]` — for MESSAGE type
- `primary_url: str | None`
- `hostname: str | None` — IDNA-decoded, lowercased
- `scheme: str | None`
- `path: str | None`
- `query: str | None`
- `is_ip_host: bool`
- `fingerprint: str` — SHA-256 of normalized URL (for dedup/cache)
- `validation_error: str | None`

**Security rules (non-negotiable):**
- Accept only `http` and `https` schemes; reject all others
- Enforce URL length ≤ 2083 characters
- Reject hostnames in loopback (127.x), link-local (169.254.x), private (10.x, 172.16-31.x, 192.168.x), multicast — SSRF prevention
- Use `urllib.parse.urlparse()` + `tldextract` for parsing; never concatenate strings to build URL components
- For MESSAGE type: extract URLs via length-limited regex; never run unconstrained regex on untrusted input
- Fingerprint: normalize scheme to lowercase, IDNA-decode hostname, strip utm_* tracking params, sort query params, hash with SHA-256
- Never resolve DNS, never fetch the URL

---

#### Module 2: `url_analyzer`

**File:** `backend/app/detection/url_analyzer.py`

**Responsibility:** Apply all rule-based structural heuristics to a normalized URL. No external calls.

**Output:** `list[EvidenceIndicator]`

**Indicator Codes:**

| Code | Points | Trigger Condition |
|---|---|---|
| `IP_HOST` | +30 | Hostname is a raw IPv4/IPv6 address |
| `IDN_LOOKALIKE` | +35 | Hostname contains punycode homoglyphs |
| `TYPOSQUATTING` | +40 | Edit distance ≤ 2 from a protected brand domain |
| `LOOKALIKE_HOST` | +30 | Brand name appears as subdomain or path prefix |
| `CREDENTIAL_KEYWORD` | +15 | Path/query contains: login, verify, account, password, confirm |
| `SUSPICIOUS_TLD` | +20 | TLD on high-risk list (.xyz, .top, .club, .tk, etc.) |
| `MANY_SUBDOMAINS` | +15 | Subdomain count ≥ 4 |
| `HYPHEN_IN_DOMAIN` | +10 | Domain contains hyphen |
| `NON_STANDARD_PORT` | +15 | Port is not 80 or 443 |
| `SUSPICIOUS_FILE_EXT` | +20 | Path ends with .exe, .bat, .sh, .zip, .js |
| `HIGH_URL_ENTROPY` | +10 | Shannon entropy of URL > 3.5 |
| `EXCESSIVE_DIGITS` | +10 | URL contains > 20% digit characters |
| `FREE_HOSTING_TLD` | +10 | Domain matches free hosting services |
| `KNOWN_REDIRECTOR` | +5 | Domain is a known URL shortener |
| `NO_HTTPS` | +10 | Scheme is `http` |
| `SUSPICIOUS_ENCODING` | +20 | URL contains double-encoding or unusual percent-encoding |
| `EXCESSIVE_URL_LENGTH` | +5 | URL exceeds 200 characters |

Protected brand list is maintained in `backend/app/detection/config/brand_domains.json` (version-controlled, separate from model artifacts).

---

#### Module 3: `message_analyzer`

**File:** `backend/app/detection/message_analyzer.py`

**Responsibility:** Analyze message text for phishing language patterns. Extract URLs and pass to `url_analyzer`.

**Output:** `list[EvidenceIndicator]` (message-level) + `list[str]` (extracted URLs for URL analysis)

**Message Indicator Codes:**

| Code | Points | Pattern |
|---|---|---|
| `URGENCY_LANGUAGE` | +20 | "urgent", "immediately", "within 24 hours", "verify now", "suspended" |
| `THREAT_LANGUAGE` | +20 | "will be closed", "legal action", "account compromised", "unauthorized access" |
| `REWARD_LANGUAGE` | +15 | "you have won", "congratulations", "free gift", "claim your prize" |
| `CREDENTIAL_REQUEST` | +20 | "enter your password", "confirm your details", "update your information" |
| `IMPERSONATION_KEYWORD` | +15 | Brand name + credential request in same message |

**Privacy:** Message text is NOT stored unless user explicitly reports an incident.

---

#### Module 4: `qr_analyzer`

**File:** `backend/app/detection/qr_analyzer.py`

**Responsibility (Milestone 2):** Parse the decoded QR payload, determine its type, and route URL payloads to `url_analyzer`.

**Output:**
- `payload_type: Literal["URL", "TEXT", "CONTACT", "WIFI", "UNSUPPORTED"]`
- `list[EvidenceIndicator]` (QR-specific)
- `primary_url: str | None`

**QR Indicator Codes:**

| Code | Points | Trigger |
|---|---|---|
| `QR_NON_URL_PAYLOAD` | — | QR payload is not a URL (reported in limitations, not scored) |
| `QR_SHORTENED_URL` | +5 | Decoded URL is a known shortener |
| `QR_SUSPICIOUS_SCHEME` | +20 | Decoded URL uses non-http/https scheme |

---

#### Module 5: `threat_intelligence`

**File:** `backend/app/threat_intel/` (package)

**Responsibility:** Query external TI providers asynchronously, cache results, normalize responses, handle failures.

**Output per provider — `ThreatIntelResult`:**
```python
class ThreatIntelResult:
    provider: str
    queried_at: datetime
    cache_hit: bool
    status: Literal["MALICIOUS", "CLEAN", "UNKNOWN", "UNAVAILABLE", "ERROR"]
    threat_types: list[str]
    source_details: dict   # minimal, sanitized
    latency_ms: int
```

**SSRF guarantee:** The TI module sends URL **strings** to external TI APIs as POST body or query parameters. The backend never fetches the submitted URL over its own network connection.

---

#### Module 6: `rule_engine`

**File:** `backend/app/detection/rule_engine.py`

**Responsibility:** Orchestrate `url_analyzer` and `message_analyzer`; return structured rule results.

**Output — `RuleEngineResult`:**
```python
class RuleEngineResult:
    indicators: list[EvidenceIndicator]
    rules_version: str    # e.g. "rules-v1.0.0"
    evaluated_at: datetime
```

---

#### Module 7: `ml_engine`

**File:** `backend/app/detection/ml_engine.py`

**Responsibility:** Load serialized model, extract features, run inference, return calibrated confidence with SHAP contributions.

**Output — `MLEngineResult`:**
```python
class MLEngineResult:
    model_name: str              # "url_xgboost_v1"
    model_version: str           # "1.0.0"
    prediction: Literal["phishing", "legitimate", "unavailable"]
    confidence: float            # 0.0–1.0 calibrated probability
    feature_contributions: dict[str, float]  # SHAP values for top-N features
    inference_latency_ms: int
    model_not_loaded: bool       # True if model file unavailable
```

**Fallback:** If model file is absent or corrupt, returns `prediction="unavailable"`, `model_not_loaded=True`. Scan endpoint must NOT fail — it continues with TI + rules only.

**Model storage:** `backend/models/` directory (gitignored; delivered as separate artifact).

---

#### Module 8: `evidence_correlator`

**File:** `backend/app/detection/evidence_correlator.py`

**Responsibility:** Merge rule, TI, and ML outputs into a single deduplicated evidence set.

**Output — `CorrelatedEvidence`:**
```python
class CorrelatedEvidence:
    indicators: list[EvidenceIndicator]     # deduplicated by code, sorted by score_contribution desc
    threat_intel_matches: list[str]         # provider names that returned MALICIOUS
    ml_signal: MLEngineResult | None
    has_confirmed_threat: bool              # any TI provider returned MALICIOUS
    has_heuristic_signals: bool             # any rule fired
    has_ml_signal: bool                     # ML confidence > 0.60
    evidence_count: int
```

**Deduplication rules:**
- The same indicator `code` is emitted only once even if multiple analysis paths trigger it
- ML confidence does NOT generate an indicator — it is a supporting signal only
- TI matches are always a separate evidence category from heuristics; never double-counted

---

#### Module 9: `risk_scorer`

**File:** `backend/app/detection/risk_scorer.py`

**Responsibility:** Apply the versioned scoring policy to `CorrelatedEvidence`; produce verdict and score.

**Output — `RiskScore`:**
```python
class RiskScore:
    score: int                  # 0–100
    risk_level: ScanRiskLevel
    verdict: ScanVerdict
    scoring_version: str        # "scorer-v1.0.0"
    model_version: str | None
    contributing_evidence: list[str]
```

---

#### Module 10: `explanation_generator`

**File:** `backend/app/detection/explanation_generator.py`

**Responsibility:** Convert evidence and score into the `ScanIndicator` list, recommendations, and explicit limitations that populate the API response.

**Rules:**
- Each fired rule → one `ScanIndicator` with `evidence_type: "heuristic"`
- Each TI MALICIOUS match → one `ScanIndicator` with `evidence_type: "threat_intelligence"`, provider name, and timestamp
- ML confidence → appears in `limitations`, never as a primary indicator
- Provider unavailability → explicit `limitations` item
- `UNKNOWN` verdict → explanation of why evidence was insufficient

---

## 5. Task 4 — Risk Scoring Design

### 5.1 Core Principles

1. **Confirmed TI match always produces MALICIOUS.** No other signal can override this.
2. **ML is supporting evidence, not verdict.** Maximum ML contribution is +15 points.
3. **Rules accumulate graduated evidence.** Multiple unrelated indicators accumulate points.
4. **No double-counting.** Each indicator `code` contributes exactly once.
5. **Conflicting TI providers:** Most cautious wins (any MALICIOUS → MALICIOUS verdict).
6. **Provider unavailability degrades gracefully.** Missing TI → UNKNOWN flag, not error.
7. **UNKNOWN is an honest answer.** When evidence is insufficient, return UNKNOWN.
8. **Scores are ordinal evidence accumulators, not statistical probabilities.**

### 5.2 Evidence Point System

> **PROVISIONAL — Subject to calibration against labeled test set. These are initial estimated values, not validated thresholds.**

#### Threat Intelligence Evidence

| Condition | Effect |
|---|---|
| Any TI provider returns MALICIOUS | Force `MALICIOUS` verdict (score capped at 100) |
| All TI providers return CLEAN | -10 points |
| All TI providers UNAVAILABLE | +0 points; add `UNKNOWN` caveat to limitations |
| Some providers available, none MALICIOUS | -5 points |

#### Rule-Based Evidence Points

| Code | Points |
|---|---|
| `TYPOSQUATTING` | +40 |
| `IDN_LOOKALIKE` | +35 |
| `IP_HOST` | +30 |
| `LOOKALIKE_HOST` | +30 |
| `SUSPICIOUS_ENCODING` | +20 |
| `SUSPICIOUS_TLD` | +20 |
| `SUSPICIOUS_FILE_EXT` | +20 |
| `CREDENTIAL_KEYWORD` | +15 |
| `NON_STANDARD_PORT` | +15 |
| `MANY_SUBDOMAINS` | +15 |
| `REWARD_LANGUAGE` | +15 |
| `URGENCY_LANGUAGE` | +20 |
| `THREAT_LANGUAGE` | +20 |
| `CREDENTIAL_REQUEST` | +20 |
| `IMPERSONATION_KEYWORD` | +15 |
| `HYPHEN_IN_DOMAIN` | +10 |
| `HIGH_URL_ENTROPY` | +10 |
| `EXCESSIVE_DIGITS` | +10 |
| `FREE_HOSTING_TLD` | +10 |
| `NO_HTTPS` | +10 |
| `EXCESSIVE_URL_LENGTH` | +5 |
| `KNOWN_REDIRECTOR` | +5 |

Rule points are capped at 85 (no rule-only scan reaches the MALICIOUS territory reserved for TI matches).

#### ML Engine Points (Supporting Signal Only)

| ML Confidence | Points |
|---|---|
| ≥ 0.90 (phishing) | +15 |
| 0.75–0.89 | +10 |
| 0.60–0.74 | +5 |
| < 0.60 or UNAVAILABLE | +0 |

Maximum ML contribution: **+15 points.**

#### Verdict and Risk Level Mapping

| Condition | Verdict | Risk Level |
|---|---|---|
| Any TI MALICIOUS match | `MALICIOUS` | `CRITICAL` |
| Score 65–100 (no TI match) | `SUSPICIOUS` | `HIGH` |
| Score 35–64 | `SUSPICIOUS` | `MEDIUM` |
| Score 10–34 | `LOW_RISK` | `LOW` |
| Score 0–9 | `LOW_RISK` | `LOW` |
| All TI UNAVAILABLE + score 0–9 | `UNKNOWN` | `UNKNOWN` |

`LOW_RISK` does not guarantee safety. This must appear in every response `limitations` field.

### 5.3 Conflict Resolution

| Scenario | Resolution |
|---|---|
| TI MALICIOUS, rules quiet | MALICIOUS; TI dominates |
| TI CLEAN, rules fire heavily | SUSPICIOUS; note "No TI match but structural indicators present" |
| Mixed TI (one MALICIOUS, one CLEAN) | MALICIOUS; most cautious wins; both results recorded in `ti_results` |
| ML says phishing, TI CLEAN, no rules | LOW_RISK; ML noted only in limitations |
| All TI UNAVAILABLE + ML unavailable + no rules | UNKNOWN |

### 5.4 Required Scan Metadata Fields

Every persisted scan must record:

| Field | Example Value |
|---|---|
| `scoring_version` | `"scorer-v1.0.0\|rules-v1.0.0\|model-url_xgboost_v1.0.0"` |
| `model_version` | `"url_xgboost_v1.0.0"` or `null` |
| `ti_providers_queried` | `["google_safe_browsing", "virustotal", "urlhaus"]` |
| `ti_providers_available` | `["google_safe_browsing", "urlhaus"]` |

---

## 6. Task 5 — Threat Intelligence Integration

### 6.1 Package Structure

```
backend/app/threat_intel/
├── __init__.py
├── base.py                    # Abstract ThreatIntelProvider
├── cache.py                   # TTLCache wrapper
├── client_pool.py             # Shared httpx.AsyncClient
├── coordinator.py             # Parallel execution + aggregation
└── providers/
    ├── __init__.py
    ├── google_safe_browsing.py
    ├── virustotal.py
    └── urlhaus.py
```

### 6.2 Base Provider Interface

```python
# base.py (design only — not implemented yet)
from abc import ABC, abstractmethod

class ThreatIntelProvider(ABC):
    name: str
    timeout_seconds: float = 5.0
    cache_ttl_seconds: int = 3600

    @abstractmethod
    async def lookup(self, url: str, hostname: str) -> ThreatIntelResult: ...

    def is_configured(self) -> bool:
        """Return False if API key missing; provider silently skipped."""
        ...
```

### 6.3 Provider Designs

#### A. Google Safe Browsing API v4

| Property | Value |
|---|---|
| Endpoint | `https://safebrowsing.googleapis.com/v4/threatMatches:find` |
| Auth | `GOOGLE_SAFE_BROWSING_API_KEY` environment variable |
| Rate limit | 100K queries/day free; 10 req/s burst |
| Cache TTL | 1 hour |
| Timeout | 5 seconds |
| Threat types | MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION |
| Indicator code | `TI_GOOGLE_SAFE_BROWSING` |
| Privacy note | Full URL sent to Google; disclose in privacy policy |

On timeout or network error → `status="UNAVAILABLE"`.

#### B. VirusTotal API v3

| Property | Value |
|---|---|
| Endpoint | `https://www.virustotal.com/api/v3/urls/{url_id}` |
| Auth | `VIRUSTOTAL_API_KEY` environment variable |
| Rate limit | 4 req/min, 500/day (free tier) |
| Cache TTL | 6 hours |
| Timeout | 8 seconds |
| MALICIOUS threshold | ≥ 3 AV engines flagging malicious (provisional) |
| Indicator code | `TI_VIRUSTOTAL` |
| Rate limit strategy | Token bucket (4 req/min); on limit exceeded → `status="UNAVAILABLE"` |
| Privacy note | Full URL sent to VT and may be shared with VT community; disclose in privacy policy |

#### C. URLhaus (abuse.ch)

| Property | Value |
|---|---|
| Endpoint | `https://urlhaus-api.abuse.ch/v1/url/` |
| Auth | None required |
| Rate limit | Fair use; throttle to 1 req/s |
| Cache TTL | 30 minutes |
| Timeout | 5 seconds |
| Indicator code | `TI_URLHAUS` |
| Privacy note | URL sent to URLhaus; consistent with its purpose as a threat-sharing platform |

### 6.4 Coordinator Design

```python
# coordinator.py (design only)
async def lookup_all(url: str, hostname: str) -> list[ThreatIntelResult]:
    providers = get_configured_providers()
    results = await asyncio.gather(
        *[p.lookup(url, hostname) for p in providers],
        return_exceptions=True
    )
    return normalize_results(results)  # exceptions → UNAVAILABLE status
```

Providers run in parallel. Individual provider failures are caught and produce `UNAVAILABLE` status. The coordinator never raises an exception to the caller.

### 6.5 API Key Management

- All keys read from environment variables via `pydantic-settings`
- Keys are never logged, included in error responses, or stored in the database
- If a key is absent, `is_configured()` returns `False`; the provider is skipped silently and marked as not queried

### 6.6 SSRF Prevention Summary

- `input_normalizer` rejects private/loopback/link-local hostnames before they reach TI
- TI adapters send URL strings to external provider APIs as POST bodies
- The backend never opens a network connection to the submitted URL
- Provider endpoints are hardcoded, not configurable by user input

### 6.7 Privacy Implications of URL Sharing

| Provider | Data Sent | Privacy Impact |
|---|---|---|
| Google Safe Browsing | Full URL (string) | Google processes the URL; must disclose in privacy policy |
| VirusTotal | Full URL (string) | URL shared with VT community by default; do not submit URLs containing session tokens or credentials |
| URLhaus | Full URL (string) | Public threat database; appropriate for phishing URLs; still disclose |

**Rule:** Never send query parameters that may contain user credentials or authentication tokens to external TI providers. Assess whether submitted URLs are stripped of sensitive query parameters before TI lookup — especially for institutional campus URLs that may contain session identifiers.

---

## 7. Task 6 — Database and API Compatibility

### 7.1 Existing `scans` Table Compatibility

| Column | M2 Status |
|---|---|
| `id` | ✅ No change |
| `submitted_by` | ✅ No change |
| `input_type` | ✅ No change (URL/MESSAGE/QR enum) |
| `input_fingerprint` | ✅ Will store SHA-256 fingerprint from `input_normalizer` |
| `verdict` | ✅ No change |
| `risk_level` | ✅ No change |
| `risk_score` | ✅ No change |
| `scoring_version` | ✅ No change; will store compound version string |
| `indicators` | ✅ No change; JSONB stores `list[ScanIndicator]` |
| `recommendations` | ✅ No change |
| `created_at` | ✅ No change |

### 7.2 Proposed Additional Columns (REQUIRES NEW MIGRATION — NOT YET APPLIED)

> **Do not apply this migration. This is a proposal for approval only. No SQL has been executed.**

```sql
-- Proposed addition in a new migration (NOT applied)
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS model_version TEXT,
  ADD COLUMN IF NOT EXISTS rules_version TEXT,
  ADD COLUMN IF NOT EXISTS ti_providers_queried JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ti_providers_available JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ti_results JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS analysis_scope TEXT;
```

These columns provide full audit traceability: which model, which rules, which TI providers, what they returned.

### 7.3 Proposed `indicators` JSONB Record Schema (Internal)

```json
{
  "code": "LOOKALIKE_HOST",
  "label": "Possible lookalike domain",
  "evidence_type": "heuristic",
  "detail": "The hostname resembles a known university service.",
  "score_contribution": 30,
  "source": "url_analyzer"
}
```

`score_contribution` and `source` are internal audit fields. They need not be included in the client-facing API response; they are stored in the JSONB column for debugging and future retraining data.

### 7.4 OpenAPI Contract Compatibility

| Schema Element | Status |
|---|---|
| `ScanVerdict` enum | ✅ No change required |
| `ScanRiskLevel` enum | ✅ No change required |
| `EvidenceType` enum | ✅ No change required |
| `ScanResultResponse` | ✅ No change required |
| `ScanIndicator` | ✅ No change required |
| `_mock_notice` field | ⚠️ Remove from production responses (additive removal; clients that ignore unknown fields are unaffected) |

### 7.5 `scoring_version` Format Proposal

Current default: `'v1'`  
Proposed compound format: `"scorer-v1.0.0|rules-v1.0.0|model-url_xgboost_v1.0.0"`

This allows reconstruction of the exact combination of components that produced a given scan result. It is backward-compatible with the existing `TEXT` column type.

---

## 8. Task 7 — Testing and Evaluation Strategy

### 8.1 Why Accuracy is Insufficient

On a 63% phishing dataset, a classifier that always predicts "phishing" achieves 63% accuracy while being completely useless for detecting legitimate URLs. In phishing detection:

- **False negatives (missed phishing) expose users to credential theft** — high security cost
- **False positives (blocking legitimate sites) erode user trust** — high usability cost

These are asymmetric costs that accuracy cannot express.

**Required metrics:**
- **Precision:** TP / (TP + FP) — quality of phishing predictions
- **Recall:** TP / (TP + FN) — coverage of actual phishing
- **F1-Score:** Harmonic mean of precision and recall
- **False Positive Rate:** FP / (FP + TN) — critical for user trust
- **False Negative Rate:** FN / (FN + TP) — critical for security
- **AUC-ROC:** Overall discriminative power across thresholds
- **Confusion matrix:** Full TP/TN/FP/FN breakdown

**Operational metrics:**
- **Inference latency** (p50 / p95 / p99) — must be ≤ 100ms median
- **Model file size** — target ≤ 50MB

### 8.2 Train / Validation / Test Split

- **Ratio:** 70% train / 15% validation / 15% test
- **Stratification:** Always use `stratify=y` to preserve class balance in all splits
- **Temporal ordering:** If harvest timestamps exist, use time-based split (older data in train, newer in test)
- **Domain-based grouping:** Group by registrable domain (eTLD+1); ensure no domain appears in both train and test sets. Use `GroupShuffleSplit` with domain as group key.
- **Deduplication before split:** Remove exact duplicates by URL fingerprint across both datasets

### 8.3 Leakage Prevention

| Leakage Type | Prevention |
|---|---|
| URL overlap between datasets | Cross-dataset URL fingerprint deduplication before any split |
| Domain memorization | Group-based split by eTLD+1 domain |
| Temporal leakage | Time-based split if timestamps available |
| Feature leakage | Re-extract all features from raw URL at inference time; do not use pre-computed features from dataset as-is at inference |

### 8.4 Model Evaluation Protocol

```
Phase 1 — Baseline
  Train Logistic Regression
  Evaluate on validation set
  Record all metrics

Phase 2 — Primary Model Training
  Train Random Forest (class_weight="balanced")
  Train XGBoost (scale_pos_weight = n_negative / n_positive)
  Train LightGBM (is_unbalance=True)
  Hyperparameter tuning via 5-fold cross-validation on train set
  Select best model by F1 on validation set

Phase 3 — Calibration
  Apply Platt Scaling to selected model
  Verify calibration curve (reliability diagram)

Phase 4 — Final Test Set Evaluation (ONCE)
  Evaluate final calibrated model on held-out test set
  Record: precision, recall, F1, FPR, FNR, AUC-ROC, confusion matrix
  Compute SHAP for top features (TreeExplainer — fast)

Phase 5 — False Positive Review
  Manually inspect top-20 highest-confidence false positives
  Identify patterns and adjust rule weights if needed
  Document findings in MODEL_CARD.md
```

### 8.5 Inference Latency Budget

| Component | Target P95 Latency |
|---|---|
| Input normalization | ≤ 5ms |
| Rule engine | ≤ 20ms |
| ML inference (URL) | ≤ 50ms |
| TI lookup (cache hit) | ≤ 5ms |
| TI lookup (cache miss, parallel) | ≤ 800ms |
| Evidence correlation + scoring | ≤ 10ms |
| Database write | ≤ 100ms |
| **Total (cold TI)** | **≤ 1.0 second** |
| **Total (all TI UNAVAILABLE)** | **≤ 200ms** |

### 8.6 Evaluation Checklist

- [ ] Duplicates removed before any split
- [ ] Stratified split (or temporally ordered)
- [ ] No domain in both train and test
- [ ] Model selected on validation; evaluated once on test
- [ ] Calibration verified via reliability diagram
- [ ] False positive rate reviewed at the operating threshold
- [ ] SHAP values reviewed for interpretability and model sanity
- [ ] Inference latency measured on development hardware
- [ ] Model size recorded
- [ ] Model card written in `docs/MODEL_CARD.md`
- [ ] Model artifact stored in `backend/models/`

---

## 9. Proposed Dependencies

### 9.1 New Production Dependencies (additions to `requirements.txt`)

> **Do not install until Milestone 2 implementation is approved.**

```
# ML and Feature Engineering
scikit-learn>=1.5.0,<2.0.0
xgboost>=2.0.0,<3.0.0
lightgbm>=4.4.0,<5.0.0
joblib>=1.4.0,<2.0.0

# URL Parsing
tldextract>=5.1.0,<6.0.0

# In-process TI cache
cachetools>=5.3.0,<6.0.0
```

### 9.2 New Development Dependencies (additions to `requirements-dev.txt`)

```
# Model training and evaluation
shap>=0.46.0,<1.0.0
pandas>=2.2.0,<3.0.0
numpy>=1.26.0,<2.0.0
matplotlib>=3.9.0,<4.0.0
seaborn>=0.13.0,<1.0.0
imbalanced-learn>=0.12.0,<1.0.0

# Future QR CNN (Milestone 3 only)
# torch>=2.3.0     (CUDA 12.x build — install separately; not via pip requirements.txt)
# torchvision>=0.18.0
```

### 9.3 No Frontend Dependency Changes

No changes to the Next.js dashboard, Chrome extension, or PWA dependencies are required for Milestone 2.

---

## 10. Phased Implementation Plan

### Phase 1 — Rule Engine and Input Normalization (Days 1–2)
- Implement `input_normalizer.py` with full SSRF prevention
- Implement `url_analyzer.py` with all 17 indicator rules
- Implement `message_analyzer.py`
- Implement `qr_analyzer.py` as URL routing layer
- Implement `rule_engine.py` coordinator
- Unit tests: each rule tested with known phishing and benign examples
- Connect to `POST /api/v1/scan/url` (replace mock)
- **Exit gate:** URL scan returns real rule-based indicators; response matches OpenAPI contract exactly

### Phase 2 — Threat Intelligence Adapters (Days 2–3)
- Implement `base.py`, `cache.py`, `client_pool.py`
- Implement `urlhaus.py` first (no API key required)
- Implement `google_safe_browsing.py`
- Implement `virustotal.py`
- Implement `coordinator.py` with parallel execution
- Integration tests with mocked HTTP responses; do not call live APIs in CI
- Test: timeout, key missing, MALICIOUS, CLEAN, rate limited
- **Exit gate:** All provider states handled correctly without exceptions to caller

### Phase 3 — Dataset Preparation and Model Training (Days 3–5)
- Download LegitPhish; run full audit (`scripts/audit_legit_phish.py`)
- Download CIC-Trap4Phish; read READMEs; audit URL Strings subset
- Cross-dataset URL deduplication
- Build inference-time feature extraction pipeline
- Train Logistic Regression baseline
- Train XGBoost primary model with GPU acceleration
- Evaluate and calibrate
- Serialize to `backend/models/url_xgboost_v1.0.0.joblib`
- Write `docs/MODEL_CARD.md`

### Phase 4 — ML Engine Integration (Days 5–6)
- Implement `ml_engine.py` with model loading, feature extraction, SHAP
- Wire into detection pipeline
- Test fallback when model absent
- Measure inference latency

### Phase 5 — Evidence Correlation, Scoring, Explanation (Day 6)
- Implement `evidence_correlator.py`
- Implement `risk_scorer.py` (version `scorer-v1.0.0`)
- Implement `explanation_generator.py`
- End-to-end test: submit known phishing URL → MALICIOUS verdict with correct indicators
- End-to-end test: submit legitimate URL → LOW_RISK verdict with limitations

### Phase 6 — Database Integration and Migration (Day 7)
- Draft new migration for additional `scans` columns
- **Submit migration for team review before applying**
- Implement scan persistence in detection service
- Connect all three scan endpoints to real detection engine
- Remove `_mock_notice` from production responses; notify clients

### Phase 7 — Testing, Security Hardening, Documentation (Days 7–8)
- Security: verify SSRF prevention for all private IP ranges
- Privacy: confirm no message content stored without explicit incident
- Performance: end-to-end latency measurement
- Update OpenAPI spec (remove `_mock_notice` from response schemas)
- Update this document with actual implementation results

---

## 11. Technical Risks and Unresolved Decisions

### 11.1 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| CIC-Trap4Phish requires institutional registration | MEDIUM | HIGH | Contact CIC; use LegitPhish alone if download blocked |
| LegitPhish quality issues revealed by local inspection | MEDIUM | HIGH | Audit before training; supplement with PhishTank/OpenPhish |
| 6GB VRAM insufficient for QR CNN on 1M images | HIGH | MEDIUM | Defer QR CNN to M3; use decoded URL routing in M2 |
| VirusTotal free tier rate limit (4 req/min) | HIGH | MEDIUM | Aggressive caching; UNAVAILABLE fallback |
| ML model poor generalization to campus-specific URLs | MEDIUM | MEDIUM | Post-deployment false positive review; domain whitelist |
| Dataset overlap inflates test performance | MEDIUM | HIGH | Mandatory cross-dataset deduplication before any split |
| SHAP inference latency exceeds budget | LOW | LOW | Use TreeExplainer (fast); compute top-5 features only |
| Google Safe Browsing quota exceeded | LOW | MEDIUM | Cache responses; exponential backoff |

### 11.2 Unresolved Decisions

| Decision | Options | Recommendation |
|---|---|---|
| VirusTotal tier | Free vs. paid | Start with free + caching; assess after M2 |
| Rule thresholds | Provisional vs. calibrated | Calibrate against validation set in Phase 3 |
| QR image CNN | M2 vs. M3 | **Defer to M3** |
| Model storage | Local vs. S3 vs. Git LFS | Local disk for M2; S3 for production |
| TI cache backend | In-process TTLCache vs. Redis | TTLCache for M2; Redis for production scale |
| Privacy disclosure for TI URL sharing | In-app notice vs. ToS | Team + stakeholder decision required |
| Campus domain whitelist | Yes vs. No | Define campus-specific whitelist config |
| `scoring_version` format | Compound string vs. separate columns | Compound string (simpler) |

### 11.3 Decisions Already Made (Non-Negotiable)

- API contract, existing migration, and authentication are preserved unchanged
- QR scan routes decoded URLs through URL analyzer; no client-side image upload to backend
- Backend never fetches submitted URLs (SSRF prevention)
- ML predictions are never used alone to produce a `MALICIOUS` verdict
- `UNKNOWN` is an intentional, valid verdict — not an error state
- `LOW_RISK` is never communicated as a safety guarantee

---

## 12. Verified Facts vs. Assumptions

### Verified (from direct inspection on 2026-10-30)

| Fact | Source |
|---|---|
| LegitPhish: 101,219 URLs; 63,678 phishing (0), 37,540 legitimate (1) | Mendeley dataset description page |
| LegitPhish: 17 features + 1 label (18 total); feature names listed above | Mendeley dataset description page |
| LegitPhish: phishing from URLhaus; legitimate from Wikipedia/SO | Mendeley dataset description page |
| LegitPhish: CC BY 4.0 license | Mendeley Data standard |
| CIC-Trap4Phish: multi-format dataset (Word, Excel, PDF, HTML, QR, URL) | UNB/CIC dataset page |
| CIC-Trap4Phish: ~1,048,576 URL strings (433,918 benign, 614,656 malicious) | UNB/CIC data table |
| CIC-Trap4Phish: ~1,000,000 QR images (430K benign, 575K malicious) | UNB/CIC data table |
| CIC-Trap4Phish: two-stage SHAP + feature importance selection | UNB/CIC dataset page |
| CIC-Trap4Phish: evaluated RF, DT, XGBoost on tabular subsets | UNB/CIC dataset page |
| `scans` table has `indicators JSONB`, `risk_level`, `scoring_version`, `risk_score` | `20261030000001_initial_schema.sql` |
| OpenAPI defines `ScanVerdict`, `ScanRiskLevel`, `EvidenceType` enums | `shared/api-contracts/openapi.yaml` |
| `backend/app/detection/` is an empty stub (143 bytes) | Directory inspection |
| `backend/app/threat_intel/` is an empty stub (155 bytes) | Directory inspection |
| `backend/requirements.txt` contains no ML libraries | File inspection |

### Assumptions (Unverified — Require Local Inspection)

| Assumption | Risk if Wrong | Verification Action |
|---|---|---|
| LegitPhish is a single CSV file | LOW | Download and run `df.info()` |
| LegitPhish has low missing values | MEDIUM | Run `df.isnull().sum()` |
| LegitPhish has low duplicate count | MEDIUM | Run `df.duplicated().sum()` |
| CIC-Trap4Phish URL Strings are in CSV format | MEDIUM | Download and read README |
| CIC-Trap4Phish download requires no special registration | HIGH | Test download at cicresearch.ca |
| SHAP TreeExplainer fits within 50ms ML latency | LOW | Benchmark after training |
| XGBoost GPU training is stable on RTX 4050 + CUDA | LOW | Test during Phase 3 |
| URLhaus API endpoint is stable at documented URL | LOW | Test during Phase 2 |
| VirusTotal and Google Safe Browsing API keys are obtainable | MEDIUM | Confirm with team |

---

*End of SignalSafe Campus Milestone 2 — Detection Architecture & Technical Planning Report*

**Prepared by:** Backend/Security Architect  
**Status:** DRAFT — Awaiting team review and approval before implementation begins  
**Next action:** Team review → approve or revise → begin Phase 1 implementation
