# SignalSafe Campus — Dataset Repository & Provenance Guide

This directory contains the dataset artifacts, raw sources, processed partitions, and verification scripts for the **SignalSafe Campus Milestone 2: Hybrid Detection Engine**.

> **IMPORTANT**: Raw dataset files (`*.csv`, `*.zip`, `*.parquet`, etc.) and trained model weights are excluded from Git version control via `.gitignore`. Do not commit raw or processed datasets to Git.

---

## 1. Directory Structure

```text
data/
├── README.md                          # Dataset provenance, acquisition, and verification documentation
├── raw/                               # Raw acquired dataset files (Git-ignored)
│   └── url_features_extracted1.csv    # Dataset A (LegitPhish, 101,219 records, 8.96 MB)
├── processed/                         # Standardized, deduplicated, and split datasets (Git-ignored)
└── scripts/                           # Reproducible audit, download, and verification scripts
    └── inspect_legitphish.py          # Standard-library inspection script for LegitPhish
```

---

## 2. Dataset A: LegitPhish

* **Source**: Mendeley Data / Digital Commons Data
* **Identifier**: `10.17632/hx4m73v2sf.2` (Version 2, Published 22 May 2025)
* **Direct Web URL**: [https://data.mendeley.com/datasets/hx4m73v2sf/2](https://data.mendeley.com/datasets/hx4m73v2sf/2)
* **Direct File Download URL**: [https://data.mendeley.com/public-files/datasets/hx4m73v2sf/files/0ed51e4d-d160-4047-b650-3f0801eea4aa/file_downloaded](https://data.mendeley.com/public-files/datasets/hx4m73v2sf/files/0ed51e4d-d160-4047-b650-3f0801eea4aa/file_downloaded)
* **License**: **Creative Commons Attribution 4.0 International (CC BY 4.0)**
* **Authors**: Rachana Potpelwar, Uday Kulkarni, Jaishri Waghmare (Shri Guru Gobind Singhji Institute of Engineering and Technology)

### Integrity & File Specifications

| Attribute | Expected Value | Verified Actual | Status |
| :--- | :--- | :--- | :--- |
| **Filename** | `url_features_extracted1.csv` | `url_features_extracted1.csv` | PASS |
| **File Size** | 8,963,838 bytes (~8.55 MB) | 8,963,838 bytes | PASS |
| **SHA-256 Checksum** | `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd` | `8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd` | PASS |
| **Row Count** | 101,219 records + 1 header | 101,219 records | PASS |
| **Column Count** | 18 columns | 18 columns | PASS |

### Acquisition Instructions

```bash
# From workspace root
python -c "
import os, urllib.request, hashlib
os.makedirs('data/raw', exist_ok=True)
url = 'https://data.mendeley.com/public-files/datasets/hx4m73v2sf/files/0ed51e4d-d160-4047-b650-3f0801eea4aa/file_downloaded'
dest = 'data/raw/url_features_extracted1.csv'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (SignalSafeCampus/1.0)'})
with urllib.request.urlopen(req) as resp, open(dest, 'wb') as f:
    f.write(resp.read())
print('Downloaded successfully.')
"
# Inspect and verify
python data/scripts/inspect_legitphish.py
```

### Citation

```bibtex
@dataset{potpelwar2025legitphish,
  author = {Potpelwar, Rachana and Kulkarni, Uday and Waghmare, Jaishri},
  title = {LegitPhish Dataset},
  year = {2025},
  month = {May},
  version = {2},
  publisher = {Mendeley Data},
  doi = {10.17632/hx4m73v2sf.2},
  url = {https://data.mendeley.com/datasets/hx4m73v2sf/2}
}
```

---

## 3. Dataset B: CIC-Trap4Phish 2025

* **Source**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)
* **Information URL**: [https://www.unb.ca/cic/datasets/trap4phish2025.html](https://www.unb.ca/cic/datasets/trap4phish2025.html)
* **Download Portal**: [http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/](http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/)
* **License**: **CIC Open Access License / Research Use Agreement** (Freely usable for academic, research, and commercial applications with mandatory citation; redistribution permitted under identical attribution).
* **Reference Paper**: *CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection* (arXiv:2602.09015, February 2026).
* **Authors**: Fatemeh Nejati, Mahdi Rabbani, Mansur Mirani, Gunjan Piya, Igor Opushnyev, Ali A. Ghorbani, Sajjad Dadkhah.

### Verification Status & Acquisition Gate

> **CRITICAL VERIFICATION FINDING**: 
> Access to the raw files at `http://cicresearch.ca/IOTDataset/CIC_Trap4Phish_2025_Dataset/` is **gated behind an institutional registration form** (`insert.php`) requiring user details (First Name, Last Name, Work/Academic Email, Organization/Institution, Job Title, Country).
>
> Automated download scripts cannot and must not forge institutional registration credentials. The dataset must be requested manually by an authorized researcher or acquired via official mirrors once credentials are confirmed.

### Dataset Composition & Modalities

| Modality / Subset | Benign Samples | Malicious Samples | Total Samples | Features / Format | Estimated Storage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Word (DOC/DOCX)** | 10,000 | 10,000 | 20,000 | 43 extracted, 10 selected (SHAP) | ~5 MB CSV |
| **Excel (XLS/XLSX)** | 10,000 | 10,000 | 20,000 | 48 extracted, 10 selected (SHAP) | ~5 MB CSV |
| **PDF Documents** | 10,000 | 10,000 | 20,000 | 40 extracted, 10 selected (SHAP) | ~5 MB CSV |
| **HTML Pages** | 10,000 | 10,000 | 20,000 | 40 extracted, 13 selected (SHAP) | ~6 MB CSV |
| **QR Code Images** | 430,000 | 575,000 | 1,000,000 | Raw PNG/JPEG images for CNN | ~15 GB to 40 GB |
| **URL Strings** | 433,918 | 614,656 | 1,048,576 | Raw URL strings for NLP / Transformers | ~90 MB CSV |

### Acquisition Recommendation for Phase 2

1. **Selective Acquisition**: Acquire the **URL Strings CSV** (~90 MB) and **HTML / PDF feature CSVs** (~11 MB total).
2. **Do Not Download Raw 1M QR Images**: Downloading 1,000,000 QR images requires >25 GB disk and significant GPU resources. In SignalSafe Campus, QR code detection at runtime extracts the encoded URL string and routes it through the URL detection engine. Hence, the 1.05M URL strings subset provides 100% of the lexical quishing defense without image overhead.

### Citation

```bibtex
@article{nejati2026trap4phish,
  author = {Nejati, Fatemeh and Rabbani, Mahdi and Eskandarian, M. and Mirani, Mansur and Piya, Gunjan and Opushnyev, Igor and Ghorbani, Ali A. and Dadkhah, Sajjad},
  title = {CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection},
  journal = {arXiv preprint arXiv:2602.09015},
  year = {2026}
}
```

---

## 4. Dataset Integration Rules

1. **Never Blindly Merge Pre-Computed Feature CSVs**:
   LegitPhish features were generated using arbitrary heuristics (e.g., custom `tld_popularity` thresholds, specific regex tokenizers). Merging LegitPhish's 16 features with CIC-Trap4Phish or other datasets without unified feature extraction causes severe feature skew and uncalibrated models.
2. **Unified Feature Extraction Engine**:
   All features used in training and production inference must be computed dynamically by SignalSafe Campus's own deterministic Python feature extractor (`backend/app/services/detection/url_features.py`) operating on raw URL strings.
3. **Domain-Stratified Partitioning (Group-KFold)**:
   LegitPhish contains multiple URLs sharing the same base domain (e.g. 964 URLs under one subdomain). Standard random splitting leaks domain signatures into the test set, creating overly optimistic accuracy. All train/validation/test splits must use domain grouping.
