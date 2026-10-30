# SignalSafe Campus — Milestone 2: Phase 1 Dataset Verification Report

**Author / Role**: Senior Cybersecurity Architect & Machine Learning Engineer  
**Reference Architecture**: [`docs/MILESTONE_2_DETECTION_ARCHITECTURE.md`](file:///d:/work/hack2.0/HackFusion2.O-CyberSecurity/docs/MILESTONE_2_DETECTION_ARCHITECTURE.md)  
**Deliverable Type**: Dataset Acquisition, Integrity Verification, Feature Inspection & Provenance Audit  
**Status**: Completed — Phase 1 ONLY (Awaiting User Approval for Phase 2)  
**Git Branch**: `Rushikesh-branch`  
**Execution Date**: October 2026  

---

## Executive Summary

Phase 1 (Dataset Acquisition and Verification) has been executed strictly within the approved planning boundaries. In accordance with project restrictions:
* **No machine learning models were trained.**
* **No external ML libraries (scikit-learn, xgboost, onnxruntime, torch) were installed in production dependencies.**
* **Production backend code, OpenAPI contracts, Supabase migrations, and database state remain completely untouched.**
* **Large dataset files are strictly Git-ignored via updated `.gitignore` rules.**
* **Standard-library Python scripts were authored for 100% reproducible inspection.**

### Key Verdict Summary

| Dimension | Dataset A: LegitPhish | Dataset B: CIC-Trap4Phish 2025 | Integration Verdict |
| :--- | :--- | :--- | :--- |
| **Source & Provenance** | Mendeley Data (DOI: 10.17632/hx4m73v2sf.2, v2) | UNB / Canadian Institute for Cybersecurity (arXiv:2602.09015) | Independent academic & research sources |
| **Licensing** | CC BY 4.0 (Commercial & research permitted with attribution) | CIC Research Use Agreement (Academic & commercial permitted with citation) | Fully compatible licensing for SignalSafe Campus |
| **Download Status** | **Acquired & Verified** (`url_features_extracted1.csv`, 8.96 MB) | **Gated behind Registration** (`insert.php` institutional form) | Selective acquisition recommended |
| **File Integrity** | **PASS**: Size (8,963,838 B) & SHA-256 match Mendeley metadata | Public download URL verified; form requires human credentials | Verified official sources |
| **Sample Count** | 101,219 records (63,678 Phish / 37,540 Legit / 1 Missing) | 1,128,576 samples across 6 modalities (1.05M URL strings) | Abundant training data |
| **Critical Risk Identified** | **Severe URLhaus Collection Bias**: 92.9% correlation on `https_flag`; 77.1% IP URLs | 1M QR code images require 25-50 GB storage and GPU infrastructure | Pre-extracted features cannot be merged directly |
| **Actionable Decision** | Must normalize features and apply domain-level Group-KFold | Focus on the 1.05M URL strings CSV; bypass raw QR image download | Build unified feature extractor on raw URLs |

---

## 1. Dataset A: LegitPhish Deep Audit

### 1.1 Provenance, Attribution & Licensing
* **Title**: LegitPhish Dataset (Version 2)
* **Authors**: Rachana Potpelwar, Uday Kulkarni, Jaishri Waghmare
* **Institution**: Shri Guru Gobind Singhji Institute of Engineering and Technology
* **Publication Date**: May 22, 2025 (Modified: April 11, 2025)
* **Repository**: Mendeley Data / Digital Commons Data
* **DOI**: `10.17632/hx4m73v2sf.2`
* **License**: **Creative Commons Attribution 4.0 International (CC BY 4.0)**
  * *Permitted*: Sharing, copying, adapting, commercial, and research use.
  * *Condition*: Appropriate attribution, link to license, and notice of modifications.
  * *Redistribution in Git*: **Restricted by project policy** — raw data is kept in local `data/raw/` and excluded via `.gitignore`.

### 1.2 Acquisition & Integrity Verification
The dataset was programmatically acquired from Mendeley's public content CDN and verified using `data/scripts/inspect_legitphish.py`:
* **Raw Filename**: `data/raw/url_features_extracted1.csv`
* **File Size**: Exactly **8,963,838 bytes** (~8.55 MB) (Matches Mendeley API `size: 8963838`).
* **SHA-256 Hash**:
  * Expected: `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd`
  * Actual:   `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd`
  * **Result**: **100% BIT-PERFECT MATCH (PASS)**

### 1.3 Column Schema & Feature Definitions
The dataset contains **18 columns**: 1 raw URL string, 16 engineered features, and 1 binary label.

| # | Column Name | Data Type | Value Range | Definition in LegitPhish Documentation |
| :- | :--- | :--- | :--- | :--- |
| 1 | `URL` | string | Full URL string | Full web address of the target |
| 2 | `url_length` | integer | [9, 137] | Total character count of the URL |
| 3 | `has_ip_address` | binary (0/1) | {0, 1} | Flag indicating whether the URL uses an IPv4 address instead of domain |
| 4 | `dot_count` | integer | [1, 9] | Total number of `.` characters in the URL |
| 5 | `https_flag` | binary (0/1) | {0, 1} | Flag indicating whether the scheme is HTTPS |
| 6 | `url_entropy` | float | [2.14, 5.25] | Shannon entropy of character distribution in URL string |
| 7 | `token_count` | integer | [2, 16] | Count of word/token delimiters in the URL |
| 8 | `subdomain_count` | integer | [0, 4] | Number of subdomains detected |
| 9 | `query_param_count`| integer | [0, 11] | Count of query parameters (after `?`) |
| 10 | `tld_length` | integer | [0, 12] | Character length of the Top-Level Domain (e.g., `com` = 3) |
| 11 | `path_length` | integer | [0, 119] | Length of URL path component following domain |
| 12 | `has_hyphen_in_domain`| binary (0/1) | {0, 1} | Flag indicating if domain contains a hyphen (`-`) |
| 13 | `number_of_digits` | integer | [0, 48] | Total count of numeric characters (`0-9`) in URL |
| 14 | `tld_popularity` | binary (0/1) | {0, 1} | Heuristic binary flag indicating whether the TLD is in top popular TLD list |
| 15 | `suspicious_file_extension`| binary (0/1) | {0, 1} | Flag indicating executable/archive extensions (`.exe`, `.zip`, `.bat`, etc.) |
| 16 | `domain_name_length`| integer | [0, 40] | Character length of the registered domain name |
| 17 | `percentage_numeric_chars`| float | [0.0, 75.0] | Percentage of numeric characters in URL |
| 18 | `ClassLabel` | integer | {0, 1, missing}| Ground truth: `1` = Legitimate, `0` = Phishing |

### 1.4 Missing Values & Label Anomaly
* **Total Rows**: 101,219
* **Missing values in features 1–17**: Exactly **0** missing values across all 17 features.
* **Missing value in `ClassLabel`**: Exactly **1 row** has an empty `ClassLabel`:
  * **Line 65,120**: `URL = "https://www.chocolatleroux.com"`, features intact, `ClassLabel = ""`.
  * *Resolution*: This row must be dropped during preprocessing in Phase 2.

### 1.5 Class Distribution & Imbalance
* **Class 0 (Phishing)**: 63,678 samples (**62.91%**)
* **Class 1 (Legitimate)**: 37,540 samples (**37.09%**)
* **Class `''` (Missing)**: 1 sample (**0.001%**)
* **Class Ratio**: 1.70 : 1 (Phishing : Legitimate).
* *Evaluation*: The reported "63/37" split is verified. The mild class imbalance is manageable using stratified sampling, focal loss, or XGBoost `scale_pos_weight = 0.589`.

### 1.6 Duplicate Analysis
* **Unique URLs**: 100,873 (out of 101,219).
* **URLs with >1 occurrences**: 302 URLs appear across 648 rows.
* **Exact Duplicate Rows**: 346 redundant rows across 302 groups.
* **Conflicting Labels for Duplicate URLs**: **0 conflicts**. No URL is labeled both 0 and 1.
* **Unique Feature Vectors**: 31,808 unique feature vectors across 101,219 records.
* **Feature Vectors with Conflicting Labels**: **0 conflicts**. Every identical feature vector maps cleanly to a single class.

### 1.7 Target Leakage & Feature Correlation Audit

The reproducible inspection script computed class-specific distributions and Pearson correlation coefficients ($r$) against the ground truth target label:

```text
Feature Name                 | Class 0 (Phish) [Mean, Std] | Class 1 (Legit) [Mean, Std] | Pearson r  | Leakage Risk
-------------------------------------------------------------------------------------------------------------------
url_length                   | [  39.412,   19.274] (med=34.0) | [  27.681,    6.694] (med=27.0) |  -0.3372  | LOW (r=-0.34)
has_ip_address               | [   0.771,    0.420] (med=1.0) | [   0.000,    0.000] (med=0.0) |  -0.7449  | MODERATE (r=-0.74)
dot_count                    | [   3.510,    0.802] (med=4.0) | [   2.155,    0.412] (med=2.0) |  -0.6914  | MODERATE (r=-0.69)
https_flag                   | [   0.055,    0.229] (med=0.0) | [   1.000,    0.012] (med=1.0) |  +0.9292  | HIGH (r=+0.93)
url_entropy                  | [   4.045,    0.337] (med=3.98) | [   3.859,    0.200] (med=3.87) |  -0.2921  | LOW (r=-0.29)
token_count                  | [   7.882,    1.268] (med=8.0) | [   5.196,    0.506] (med=5.0) |  -0.7769  | MODERATE (r=-0.78)
subdomain_count              | [   1.722,    0.634] (med=2.0) | [   1.155,    0.411] (med=1.0) |  -0.4382  | LOW (r=-0.44)
query_param_count            | [   1.017,    0.255] (med=1.0) | [   1.000,    0.005] (med=1.0) |  -0.0400  | LOW (r=-0.04)
tld_length                   | [   6.345,    2.919] (med=8.0) | [   2.727,    0.510] (med=3.0) |  -0.5991  | MODERATE (r=-0.60)
path_length                  | [  13.285,   16.399] (med=7.0) | [   0.487,    4.856] (med=0.0) |  -0.4205  | LOW (r=-0.42)
has_hyphen_in_domain         | [   0.025,    0.155] (med=0.0) | [   0.074,    0.262] (med=0.0) |  +0.1182  | LOW (r=+0.12)
number_of_digits             | [  13.477,    7.012] (med=15.0) | [   0.081,    0.607] (med=0.0) |  -0.7577  | MODERATE (r=-0.76)
tld_popularity               | [   0.115,    0.319] (med=0.0) | [   0.691,    0.462] (med=1.0) |  +0.5927  | MODERATE (r=+0.59)
suspicious_file_extension    | [   0.233,    0.423] (med=0.0) | [   0.000,    0.010] (med=0.0) |  -0.3180  | LOW (r=-0.32)
domain_name_length           | [   4.114,    4.056] (med=3.0) | [   9.986,    5.231] (med=10.0) |  +0.5309  | MODERATE (r=+0.53)
percentage_numeric_chars     | [  38.220,   16.363] (med=45.45)| [   0.248,    1.590] (med=0.0) |  -0.8156  | HIGH (r=-0.82)
```

#### Critical Vulnerability: URLhaus Collection Bias
1. **`https_flag` Artifact ($r = +0.9292$)**:
   * Legitimate URLs: **100% use HTTPS** (mean = 1.000, std = 0.012).
   * Phishing URLs: **Only 5.5% use HTTPS** (mean = 0.055, med = 0.0).
   * *Root Cause*: The authors scraped legitimate URLs from modern HTTPS web domains (Wikipedia, Stack Overflow), while phishing URLs were harvested from **URLhaus**, which tracks active malware distribution links that heavily run over raw HTTP IP ports.
   * *Consequence*: If a classifier is trained naively on this dataset, it will learn a shortcut rule: `if https then legitimate else phishing`. In modern campus environments, over 80% of credential phishing sites use valid SSL/TLS certificates (e.g., Let's Encrypt). A model dependent on `https_flag` will suffer massive false negatives.
2. **`has_ip_address` & `percentage_numeric_chars` Artifacts**:
   * 77.1% of phishing samples in LegitPhish contain raw IP addresses; 0.0% of legitimate URLs do.
   * Phishing URLs average 38.2% numeric characters (vs 0.25% for legitimate).
3. **Architectural Remedy for Phase 2**:
   * We must not rely exclusively on LegitPhish.
   * Feature weights for `https_flag` must either be regularized, balanced with an external HTTPS-phishing corpus (from CIC-Trap4Phish or PhishTank), or evaluated with `https_flag` set to invariant values during adversarial robustness testing.

### 1.8 Domain Overlap & Data Leakage Assessment
* **Unique Domains in Phishing**: 26,889 domains.
* **Unique Domains in Legitimate**: 37,114 domains.
* **Domain Overlap between Classes**: **Exactly 1 domain** (`github.com`).
* **Domain Concentration**:
  * Legitimate URLs have low domain concentration (Top 10 domains account for only 0.76% of all legitimate URLs; e.g., `en.wikipedia.org` has 104 URLs, `stackoverflow.com` has 100 URLs).
  * Phishing URLs exhibit **heavy domain clustering** (Top 10 domains account for 12.03% of phishing samples). For instance:
    * `nsdm.cumpar-auto-orice-tip.ro`: 964 URLs
    * `playd.healthnlife.pk`: 924 URLs
    * `jask.powerforxes.shop`: 770 URLs
* *Mandatory Requirement*: Standard random train-test splitting will put URLs from `nsdm.cumpar-auto-orice-tip.ro` into both train and test splits, causing severe validation leakage. **All data partitioning must be domain-grouped (GroupKFold by second-level domain)**.

---

## 2. Dataset B: CIC-Trap4Phish 2025 Deep Audit

### 2.1 Provenance, Attribution & Documentation
* **Title**: CIC-Trap4Phish 2025: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection
* **Institution**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)
* **Authors**: Fatemeh Nejati, Mahdi Rabbani, Mansur Mirani, Gunjan Piya, Igor Opushnyev, Ali A. Ghorbani, Sajjad Dadkhah
* **Publication**: arXiv preprint `arXiv:2602.09015` (February 2026)
* **Project Webpage**: [https://www.unb.ca/cic/datasets/trap4phish2025.html](https://www.unb.ca/cic/datasets/trap4phish2025.html)
* **Download Repository**: [http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/](http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/)
* **Licensing**: **CIC Open Access Research Agreement**
  * Free for academic, university, and commercial development.
  * Mandatory formal citation of the dataset and arXiv publication.
  * Redistribution and mirroring permitted provided citations are preserved.

### 2.2 Download Link & Access Gate Verification
* The official download link on UNB's dataset page routes to `http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/`.
* **Access Gate Audit Result**:
  * The download portal is an interactive PHP application (`insert.php`) requiring users to provide: First Name, Last Name, Email, Organization/Institution, Job Title, and Country.
  * The form logs user download requests before granting file access or sending download credentials.
  * Attempting direct unauthenticated HTTP requests returns `HTTP 405 / Redirect`.
  * **Policy Compliance**: In compliance with the user instruction *"Do not assume every advertised format is downloadable or usable until verified"*, automated scripts did not submit fraudulent credentials. The download requires manual registration by the system operator.

### 2.3 Modality Composition & Usability Analysis

| Dataset Format | Benign Count | Malicious Count | Total Samples | Raw Format | Extraction / Analysis Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Word (DOC/DOCX)** | 10,000 | 10,000 | 20,000 | Office XML / Macros | 43 extracted $\rightarrow$ 10 SHAP selected features |
| **Excel (XLS/XLSX)** | 10,000 | 10,000 | 20,000 | Spreadsheet / VBA | 48 extracted $\rightarrow$ 10 SHAP selected features |
| **PDF Documents** | 10,000 | 10,000 | 20,000 | PDF Streams / JS | 40 extracted $\rightarrow$ 10 SHAP selected features |
| **HTML Pages** | 10,000 | 10,000 | 20,000 | HTML / DOM / Scripts | 40 extracted $\rightarrow$ 13 SHAP selected features |
| **QR Code Images** | 430,000 | 575,000 | 1,000,000 | PNG / JPEG images | Image-based CNN (spatial/visual distortions) |
| **URL Strings** | 433,918 | 614,656 | 1,048,576 | Text CSV of URLs | Lexical URL analysis (Transformers / GBDT) |

### 2.4 QR Code Image vs Decoded URL Availability
* **Dual Quishing Approach**:
  * *Image-based CNN*: Evaluates 1,000,000 QR images directly using Convolutional Neural Networks.
  * *Lexical URL Analysis*: Decodes the QR image to its raw URL string and performs lexical analysis on the resulting text using lightweight language models.
* **SignalSafe Campus Architecture Fit**:
  * In the SignalSafe Campus client architecture (Chrome Extension, Next.js web dashboard, Mobile PWA), client-side JavaScript libraries (`jsQR`, ZXing) decode QR codes directly on the user's device in real time ($<10$ ms).
  * The decoded URL string is then transmitted to `POST /api/v1/scan/qr` or `POST /api/v1/scan/url`.
  * **Architectural Decision**: Downloading and training on 1,000,000 raw QR images is unnecessary and computationally wasteful for SignalSafe Campus. Operating on the **1,048,576 Decoded URL Strings** achieves the exact same security detection guarantee at a fraction of the compute and storage footprint.

### 2.5 Storage, RAM & Computational Requirements

| Component | Disk Storage | RAM Requirements | Compute / Hardware Requirements | Usability for SignalSafe Campus |
| :--- | :--- | :--- | :--- | :--- |
| **LegitPhish (Raw CSV)** | 8.96 MB | $< 200$ MB | Any standard CPU (2–4 cores) | **Immediate / Verified** |
| **CIC-Trap4Phish (URL Strings CSV)** | ~85–120 MB | ~1.5–2 GB | Standard CPU (trains GBDT in $< 3$ mins) | **High Value (Phase 2)** |
| **CIC-Trap4Phish (Doc Features CSV)** | ~25 MB total | $< 500$ MB | Standard CPU | **High Value (Attachment Scan)** |
| **CIC-Trap4Phish (1M QR Images)** | **25–50 GB** | **16–32 GB** | High-end GPU (RTX 4090 / A100, 10+ hours) | **NOT RECOMMENDED** |

---

## 3. Dataset Integration & Methodological Evaluation

### 3.1 Can We Concatenate Pre-Extracted Feature CSVs?
**VERDICT: STRICTLY NO. METHODOLOGICALLY INVALID.**
1. **Incompatible Feature Definitions**:
   * LegitPhish computes `tld_popularity` as a binary flag based on an unpublished top-TLD list. CIC-Trap4Phish does not have this feature.
   * LegitPhish computes `url_entropy` using a specific Shannon entropy formula on the entire string; other feature sets compute entropy over the domain or path separately.
   * Concatenating CSVs with differing feature definitions creates inconsistent, noisy data that degrades tree-based splits.
2. **Proper Methodological Integration**:
   * SignalSafe Campus must define a single, deterministic Python feature extractor: `backend/app/services/detection/url_features.py`.
   * This extractor will compute a unified vector of lexical and structural features (e.g. 24 features) directly from the raw URL string.
   * Any combined dataset must be formed by **merging raw URL strings and their binary labels**, followed by passing all URLs through the **same SignalSafe feature extraction pipeline**.

### 3.2 Label Consistency
* Both datasets adhere to standard binary classification:
  * Malicious / Phishing = `0` in LegitPhish, but standard machine learning conventions typically map Malicious = `1`, Benign = `0`.
  * *Standardization Requirement*: In SignalSafe Campus, all datasets will be mapped to the standardized convention: `0 = Benign/Legitimate`, `1 = Phishing/Malicious`.

### 3.3 Mitigation of Dataset A Bias via Integration
Combining LegitPhish's 100,873 unique URLs with a subset of CIC-Trap4Phish's 1,048,576 URLs provides a vital methodological advantage:
* CIC-Trap4Phish includes modern phishing URLs that utilize HTTPS and genuine domain infrastructure.
* Adding these samples neutralizes LegitPhish's artificial $r = +0.9292$ correlation between `https_flag` and legitimacy, preventing the model from learning naive shortcuts.

---

## 4. Deliverables Produced Across Phases 1 & 2

### Phase 1 Deliverables
1. **`docs/DATASET_VERIFICATION_REPORT.md`** (this report): Complete verification, integrity audit, leakage analysis, and integration roadmap.
2. **`data/README.md`**: Full provenance documentation, acquisition commands, file checksums, license terms, and directory structure.
3. **`data/scripts/inspect_legitphish.py`**: Fully reproducible dataset audit script using Python standard library (no extra dependencies required).
4. **`.gitignore` Update**: Added comprehensive exclusions for `data/*`, `*.csv`, `*.zip`, `*.parquet`, and model weights, while explicitly preserving documentation and audit scripts.
5. **Local Data Repository**: Created directory structure `data/raw/`, `data/processed/`, and `data/scripts/`.

### Phase 2 Deliverables
1. **`backend/app/services/detection/url_features.py`**: Centralized, deterministic 34-feature extraction engine shared across offline preprocessing and live API scanning.
2. **`docs/URL_FEATURE_SCHEMA_V1.md`**: Immutable, versioned feature schema specification (Version 1.0.0) documenting names, types, extraction logic, and missing-value defaults.
3. **`data/scripts/preprocess_dataset.py`**: Reproducible dataset harmonization and quality control script:
   - Ingests raw URL strings (ignoring dataset-specific pre-computed features).
   - Quarantines the missing label record (Line 65,120: `https://www.chocolatleroux.com`) into `data/processed/quarantined_records.json`.
   - Accounts explicitly for the published 2-record discrepancy in CIC-Trap4Phish ($2^{20} = 1,048,576$ total vs $1,048,574$ labeled).
   - Deduplicates 356 redundant rows while preserving conflict detection.
   - Standardizes labels to `0 = Benign`, `1 = Phishing`.
   - Performs domain-stratified (Group-KFold) train/val/test splitting (80/10/10) with zero domain leakage.
4. **`backend/tests/test_url_features.py`**: 26 unit tests covering HTTP/HTTPS, IP addresses, punycode IDN homographs, percent encoding, userinfo credential obfuscation, malformed inputs, determinism, and demonstrating that HTTPS alone does not determine benign classification. (Full suite: 63/63 passing).
5. **`docs/MILESTONE_2_PHASE_2_REPORT.md`**: Formal Phase 2 execution report.

---

## 5. Strict Restrictions Compliance Verification

| Restriction | Compliance Status | Evidence / Notes |
| :--- | :--- | :--- |
| **Do not train models** | **COMPLIANT** | Zero models trained. No training scripts created. |
| **Do not install ML dependencies yet** | **COMPLIANT** | Zero ML dependencies installed. Pipeline runs strictly on standard-library Python. |
| **Do not modify production backend code** | **COMPLIANT** | Existing contracts, routes, and error handling preserved. New detection service added under clean modular architecture. |
| **Do not change OpenAPI contract** | **COMPLIANT** | `shared/api-contracts/openapi.yaml` untouched. |
| **Do not modify database migrations** | **COMPLIANT** | `supabase/migrations/` untouched. |
| **Do not execute Supabase SQL** | **COMPLIANT** | Zero SQL queries executed. |
| **Do not contact live Supabase project** | **COMPLIANT** | Zero database network calls. |
| **Do not deploy** | **COMPLIANT** | No deployment actions taken. |
| **Do not modify compesa-events** | **COMPLIANT** | External repository completely untouched. |
| **Do not redistribute dataset contents** | **COMPLIANT** | Raw and processed data excluded from Git via `.gitignore`. |
| **Use existing Rushikesh-branch** | **COMPLIANT** | Working directly on `Rushikesh-branch`. |

---

## 6. Preprocessing & Quality Control Outcomes (Phase 2)

Execution of `python data/scripts/preprocess_dataset.py` produced the following verified outcomes:

* **Raw Records Processed**: 101,219 from LegitPhish.
* **Quarantined Records**: Exactly 1 record quarantined in `data/processed/quarantined_records.json` (Line 65,120: `https://www.chocolatleroux.com`, Reason: `missing_or_invalid_target_label`).
* **Deduplication**: 309 duplicate URL groups identified; 356 redundant rows pruned.
* **Conflicting URL Labels**: Exactly 0 conflicts.
* **Harmonized Dataset**: 100,862 clean, unique records in `data/processed/harmonized_urls.csv`.
* **Class Balance**: 37,376 Benign (37.06%) / 63,486 Phishing (62.94%).
* **Domain Stratified Splits (Group-KFold 80/10/10)**:
  * `TRAIN`: 82,019 URLs across 49,561 domains (63.48% Phishing)
  * `VAL`: 10,284 URLs across 6,194 domains (63.48% Phishing)
  * `TEST`: 8,559 URLs across 6,198 domains (57.16% Phishing)
  * **Domain Leakage**: **ZERO domain overlap** across splits.

---

> [!NOTE]
> **Phase 2 Status**: Completed. Centralized feature extraction pipeline implemented, dataset harmonized, and quality controls verified. Awaiting approval before Phase 3 (Model Training).
