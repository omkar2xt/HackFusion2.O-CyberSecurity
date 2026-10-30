"""
SignalSafe Campus - Dataset Harmonization & Preprocessing Pipeline
Module: data/scripts/preprocess_dataset.py

Harmonizes raw datasets (LegitPhish and CIC-Trap4Phish) using raw URL strings
and the centralized URL normalization engine from backend.app.services.detection.url_features.

Outputs:
1. data/processed/harmonized_urls.csv: Deduplicated, normalized URLs with standardized labels (0=Benign, 1=Phishing).
2. data/processed/quarantined_records.json: Quarantined records with explicit provenance & failure rationale.
3. data/processed/preprocessing_summary.json: Full statistical summary and quality control metrics.
4. data/processed/domain_splits.json: Domain-stratified partition index for Group-KFold train/val/test splits.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

# Add repository root to path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA_VERSION,
    extract_url_features,
    normalize_url,
)

RAW_LEGITPHISH_PATH = os.path.join(REPO_ROOT, "data", "raw", "url_features_extracted1.csv")
RAW_CIC_PATH = os.path.join(REPO_ROOT, "data", "raw", "cic_trap4phish_urls.csv")
PROCESSED_DIR = os.path.join(REPO_ROOT, "data", "processed")


def process_legitphish(
    file_path: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Counter]:
    """
    Ingests raw LegitPhish dataset.
    
    Standardization:
    - LegitPhish original: ClassLabel 1 = Legitimate, 0 = Phishing
    - SignalSafe standard: label 0 = Benign/Legitimate, 1 = Phishing/Malicious
    """
    records: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    stats = Counter()

    if not os.path.exists(file_path):
        print(f"[WARN] LegitPhish file not found at {file_path}")
        return records, quarantined, stats

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, start=2):
            stats["legitphish_total_read"] += 1
            raw_url = row.get("URL", "")
            raw_label = row.get("ClassLabel", "").strip()

            # 1. Missing target label quarantine
            if raw_label not in ("0", "1"):
                quarantined.append({
                    "source_dataset": "legitphish",
                    "source_line": line_num,
                    "raw_url": raw_url,
                    "raw_label": raw_label,
                    "quarantine_reason": "missing_or_invalid_target_label",
                })
                stats["legitphish_quarantined_missing_label"] += 1
                continue

            # 2. URL Normalization check
            norm = normalize_url(raw_url)
            if not norm.is_valid:
                quarantined.append({
                    "source_dataset": "legitphish",
                    "source_line": line_num,
                    "raw_url": raw_url,
                    "raw_label": raw_label,
                    "quarantine_reason": f"invalid_url: {norm.error_reason}",
                })
                stats["legitphish_quarantined_invalid_url"] += 1
                continue

            # Map to standard labels (0=Benign, 1=Phishing)
            # Original LegitPhish: 1=Legit -> 0, 0=Phish -> 1
            std_label = 0 if raw_label == "1" else 1

            records.append({
                "source_dataset": "legitphish",
                "source_line": line_num,
                "raw_url": raw_url,
                "normalized_url": norm.normalized_url,
                "hostname": norm.hostname,
                "registrable_domain": norm.registrable_domain,
                "tld": norm.tld,
                "label": std_label,
            })
            stats["legitphish_valid_parsed"] += 1

    return records, quarantined, stats


def process_cic_trap4phish(
    file_path: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Counter]:
    """
    Ingests CIC-Trap4Phish URL records if present.
    Accounts explicitly for the published 2-record discrepancy:
    Published Total = 1,048,576 vs Benign (433,918) + Malicious (614,656) = 1,048,574.
    """
    records: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    stats = Counter()

    if not os.path.exists(file_path):
        # File is gated behind institutional registration form (Phase 1 finding)
        stats["cic_trap4phish_present"] = 0
        return records, quarantined, stats

    stats["cic_trap4phish_present"] = 1
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, start=2):
            stats["cic_total_read"] += 1
            raw_url = row.get("URL", "") or row.get("url", "")
            raw_label = (row.get("Label", "") or row.get("label", "") or row.get("class", "")).strip().lower()

            if not raw_label or raw_label in ("unlabeled", "unknown", "nan", ""):
                quarantined.append({
                    "source_dataset": "cic_trap4phish_2025",
                    "source_line": line_num,
                    "raw_url": raw_url,
                    "raw_label": raw_label,
                    "quarantine_reason": "unassigned_cic_trap4phish_discrepancy_record",
                })
                stats["cic_quarantined_unassigned"] += 1
                continue

            norm = normalize_url(raw_url)
            if not norm.is_valid:
                quarantined.append({
                    "source_dataset": "cic_trap4phish_2025",
                    "source_line": line_num,
                    "raw_url": raw_url,
                    "raw_label": raw_label,
                    "quarantine_reason": f"invalid_url: {norm.error_reason}",
                })
                stats["cic_quarantined_invalid_url"] += 1
                continue

            std_label = 1 if any(m in raw_label for m in ("phish", "malicious", "bad", "1")) else 0
            records.append({
                "source_dataset": "cic_trap4phish_2025",
                "source_line": line_num,
                "raw_url": raw_url,
                "normalized_url": norm.normalized_url,
                "hostname": norm.hostname,
                "registrable_domain": norm.registrable_domain,
                "tld": norm.tld,
                "label": std_label,
            })
            stats["cic_valid_parsed"] += 1

    return records, quarantined, stats


def harmonize_and_deduplicate(
    all_records: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Counter]:
    """
    Deduplicates URLs by normalized_url while detecting conflicting labels.
    If a URL appears with multiple conflicting labels, quarantees all occurrences.
    """
    stats = Counter()
    url_groups = defaultdict(list)
    for rec in all_records:
        url_groups[rec["normalized_url"]].append(rec)

    harmonized: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []

    for norm_url, instances in url_groups.items():
        distinct_labels = {inst["label"] for inst in instances}
        
        # Check conflicting ground truth
        if len(distinct_labels) > 1:
            for inst in instances:
                quarantined.append({
                    "source_dataset": inst["source_dataset"],
                    "source_line": inst["source_line"],
                    "raw_url": inst["raw_url"],
                    "normalized_url": norm_url,
                    "raw_label": inst["label"],
                    "quarantine_reason": f"conflicting_ground_truth_labels: {sorted(list(distinct_labels))}",
                })
            stats["conflicting_url_groups"] += 1
            stats["conflicting_records_quarantined"] += len(instances)
            continue

        if len(instances) > 1:
            stats["duplicate_url_groups"] += 1
            stats["redundant_rows_removed"] += (len(instances) - 1)

        # Retain canonical primary record (preserves first occurrence)
        primary = instances[0].copy()
        primary["duplicate_occurrences"] = len(instances)
        harmonized.append(primary)

    stats["harmonized_unique_records"] = len(harmonized)
    return harmonized, quarantined, stats


def generate_domain_stratified_splits(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.80,
    val_ratio: float = 0.10,
    test_ratio: float = 0.10,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Groups records by registrable_domain to ensure zero domain overlap between train/val/test splits.
    Stratifies domain assignment to balance class distribution across splits.
    """
    random.seed(seed)
    domain_to_records = defaultdict(list)
    domain_to_class = defaultdict(Counter)

    for rec in records:
        dom = rec["registrable_domain"] or rec["hostname"]
        domain_to_records[dom].append(rec)
        domain_to_class[dom][rec["label"]] += 1

    all_domains = list(domain_to_records.keys())
    # Shuffle domains deterministically
    random.shuffle(all_domains)

    # Sort domains by predominant class to facilitate stratified binning
    phish_domains = [d for d in all_domains if domain_to_class[d][1] > domain_to_class[d][0]]
    legit_domains = [d for d in all_domains if domain_to_class[d][0] >= domain_to_class[d][1]]

    split_domains = {"train": [], "val": [], "test": []}

    def assign_bucket(dom_list: List[str]):
        n = len(dom_list)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        split_domains["train"].extend(dom_list[:n_train])
        split_domains["val"].extend(dom_list[n_train:n_train + n_val])
        split_domains["test"].extend(dom_list[n_train + n_val:])

    assign_bucket(phish_domains)
    assign_bucket(legit_domains)

    split_summary = {}
    for split_name in ("train", "val", "test"):
        doms = set(split_domains[split_name])
        split_recs = [r for r in records if (r["registrable_domain"] or r["hostname"]) in doms]
        label_counts = Counter(r["label"] for r in split_recs)
        split_summary[split_name] = {
            "domain_count": len(doms),
            "record_count": len(split_recs),
            "benign_count": label_counts[0],
            "phishing_count": label_counts[1],
            "phishing_percentage": round((label_counts[1] / max(len(split_recs), 1)) * 100.0, 2),
        }

    return {
        "metadata": {
            "strategy": "RegistrableDomainGroupKFold",
            "seed": seed,
            "train_ratio": train_ratio,
            "val_ratio": val_ratio,
            "test_ratio": test_ratio,
        },
        "splits": split_summary,
        "domain_assignment": {
            dom: split
            for split, doms in split_domains.items()
            for dom in doms
        },
    }


def run_pipeline():
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    print("=" * 80)
    print("SignalSafe Campus - Dataset Harmonization & Preprocessing")
    print("=" * 80)

    # 1. Process LegitPhish
    print("\n[Step 1] Ingesting LegitPhish raw dataset...")
    lp_recs, lp_quar, lp_stats = process_legitphish(RAW_LEGITPHISH_PATH)
    print(f"  Total rows read:           {lp_stats['legitphish_total_read']:,}")
    print(f"  Valid normalized parsed:   {lp_stats['legitphish_valid_parsed']:,}")
    print(f"  Quarantined missing label: {lp_stats['legitphish_quarantined_missing_label']:,}")
    print(f"  Quarantined invalid URL:   {lp_stats['legitphish_quarantined_invalid_url']:,}")

    # 2. Process CIC-Trap4Phish (if raw file present)
    print("\n[Step 2] Ingesting CIC-Trap4Phish raw dataset...")
    cic_recs, cic_quar, cic_stats = process_cic_trap4phish(RAW_CIC_PATH)
    if cic_stats["cic_trap4phish_present"]:
        print(f"  Total rows read:           {cic_stats['cic_total_read']:,}")
        print(f"  Valid normalized parsed:   {cic_stats['cic_valid_parsed']:,}")
        print(f"  Quarantined unassigned:    {cic_stats['cic_quarantined_unassigned']:,}")
    else:
        print("  CIC-Trap4Phish raw file not locally present (Gated download from Phase 1).")
        print("  Pipeline configured to gracefully handle CIC records upon authorized acquisition.")

    # 3. Combine and Deduplicate
    print("\n[Step 3] Harmonizing and deduplicating records across sources...")
    all_raw = lp_recs + cic_recs
    all_quar = lp_quar + cic_quar
    harmonized, dedup_quar, dedup_stats = harmonize_and_deduplicate(all_raw)
    all_quar.extend(dedup_quar)

    print(f"  Total input valid records:  {len(all_raw):,}")
    print(f"  Harmonized unique URLs:    {dedup_stats['harmonized_unique_records']:,}")
    print(f"  Duplicate URL groups:      {dedup_stats['duplicate_url_groups']:,}")
    print(f"  Redundant rows removed:    {dedup_stats['redundant_rows_removed']:,}")
    print(f"  Conflicting URL groups:    {dedup_stats['conflicting_url_groups']:,}")
    print(f"  Total quarantined records: {len(all_quar):,}")

    # 4. Class Distribution
    final_class_counts = Counter(r["label"] for r in harmonized)
    print("\n[Step 4] Harmonized Class Distribution:")
    print(f"  Benign (Class 0):   {final_class_counts[0]:,} ({final_class_counts[0] / len(harmonized) * 100:.2f}%)")
    print(f"  Phishing (Class 1): {final_class_counts[1]:,} ({final_class_counts[1] / len(harmonized) * 100:.2f}%)")

    # 5. Domain Split Generation
    print("\n[Step 5] Generating domain-stratified train/val/test splits (80/10/10)...")
    domain_splits = generate_domain_stratified_splits(harmonized)
    for s_name, s_data in domain_splits["splits"].items():
        print(f"  {s_name.upper():<6}: {s_data['record_count']:,} URLs across {s_data['domain_count']:,} domains ({s_data['phishing_percentage']}% Phishing)")

    # 6. Save Harmonized CSV
    harmonized_csv_path = os.path.join(PROCESSED_DIR, "harmonized_urls.csv")
    fieldnames = [
        "url_id",
        "raw_url",
        "normalized_url",
        "hostname",
        "registrable_domain",
        "tld",
        "label",
        "source_dataset",
        "duplicate_occurrences",
    ]
    with open(harmonized_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for idx, rec in enumerate(harmonized, start=1):
            writer.writerow({
                "url_id": idx,
                "raw_url": rec["raw_url"],
                "normalized_url": rec["normalized_url"],
                "hostname": rec["hostname"],
                "registrable_domain": rec["registrable_domain"],
                "tld": rec["tld"],
                "label": rec["label"],
                "source_dataset": rec["source_dataset"],
                "duplicate_occurrences": rec["duplicate_occurrences"],
            })
    print(f"\n[Artifact] Harmonized CSV saved to: {harmonized_csv_path}")

    # 7. Save Quarantined Records Report
    quarantined_json_path = os.path.join(PROCESSED_DIR, "quarantined_records.json")
    with open(quarantined_json_path, "w", encoding="utf-8") as f:
        json.dump(all_quar, f, indent=2)
    print(f"[Artifact] Quarantined records saved to: {quarantined_json_path}")

    # 8. Save Domain Splits
    domain_splits_path = os.path.join(PROCESSED_DIR, "domain_splits.json")
    with open(domain_splits_path, "w", encoding="utf-8") as f:
        json.dump(domain_splits, f, indent=2)
    print(f"[Artifact] Domain splits index saved to: {domain_splits_path}")

    # 9. Save Preprocessing Summary
    summary = {
        "pipeline_version": "1.0.0",
        "feature_schema_version": URL_FEATURE_SCHEMA_VERSION,
        "input_sources": {
            "legitphish": {
                "file_path": RAW_LEGITPHISH_PATH,
                "total_read": lp_stats["legitphish_total_read"],
                "valid_parsed": lp_stats["legitphish_valid_parsed"],
                "quarantined_missing_label": lp_stats["legitphish_quarantined_missing_label"],
            },
            "cic_trap4phish_2025": {
                "present": bool(cic_stats["cic_trap4phish_present"]),
                "discrepancy_accounting": "Published total: 1,048,576 vs (433,918 Benign + 614,656 Malicious = 1,048,574). 2 unaccounted records quarantined if present.",
            },
        },
        "quality_controls": {
            "total_raw_records": len(all_raw),
            "harmonized_unique_records": len(harmonized),
            "redundant_duplicate_rows_pruned": dedup_stats["redundant_rows_removed"],
            "conflicting_url_groups": dedup_stats["conflicting_url_groups"],
            "total_quarantined_samples": len(all_quar),
            "final_class_distribution": {
                "benign_count": final_class_counts[0],
                "phishing_count": final_class_counts[1],
                "phishing_ratio": round(final_class_counts[1] / max(len(harmonized), 1), 4),
            },
        },
        "domain_splits_summary": domain_splits["splits"],
    }
    summary_path = os.path.join(PROCESSED_DIR, "preprocessing_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[Artifact] Preprocessing summary saved to: {summary_path}")
    print("\nPreprocessing & harmonization complete.")


if __name__ == "__main__":
    run_pipeline()
