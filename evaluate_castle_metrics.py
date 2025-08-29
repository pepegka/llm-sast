#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# CASTLE Benchmark scorer for custom SAST outputs (JSON)
# -------------------------------------------------------
# What it does:
# - Reads CASTLE ground truth JSON with test metadata
# - Reads your SAST results (custom JSON format)
# - Normalizes findings per test case (CASTLE-XXX-Y.c) with deduplication
# - Computes detection and CWE identification metrics
# - Prints summary and writes detailed CSV reports
#
# Usage example:
#   python evaluate_castle_metrics.py \
#     --ground-truth castle_ground_truth.json \
#     --predictions-json sast_results.json \
#     --out-dir ./castle_score_out

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

def normalize_test_name_from_path(path: str) -> Optional[str]:
    """Extract CASTLE test name from file path (e.g., CASTLE-125-1.c)"""
    if not path:
        return None
    base = os.path.basename(path)
    name, _ext = os.path.splitext(base)
    # Match CASTLE-XXX-Y pattern
    if re.match(r"CASTLE-\d+-\d+", name):
        return name
    # Fallback regex search
    match = re.search(r"(CASTLE-\d+-\d+)", base)
    return match.group(1) if match else None

def normalize_cwe(raw: Optional[str]) -> Optional[str]:
    """Normalize CWE to string digits (e.g., CWE-22 -> '22')"""
    if raw is None:
        return None
    match = re.search(r"(\d+)", str(raw))
    return match.group(1) if match else None

@dataclass
class GTEntry:
    test: str
    vulnerable: bool
    cwe: Optional[str]
    description: Optional[str] = None

def load_ground_truth_json(json_path: Path) -> Dict[str, GTEntry]:
    """Load CASTLE ground truth from JSON file"""
    gt: Dict[str, GTEntry] = {}
    
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Handle different JSON structures
    tests = data.get("tests", [])
    if not tests and isinstance(data, list):
        tests = data
    
    for test_entry in tests:
        if not isinstance(test_entry, dict):
            continue
            
        test_name = test_entry.get("name", "")
        if not test_name:
            continue
            
        # Normalize test name
        normalized_name = normalize_test_name_from_path(test_name)
        if not normalized_name:
            continue
            
        vulnerable = bool(test_entry.get("vulnerable", False))
        cwe = normalize_cwe(test_entry.get("cwe"))
        description = test_entry.get("description", "")
        
        gt[normalized_name] = GTEntry(
            test=normalized_name,
            vulnerable=vulnerable,
            cwe=cwe,
            description=description
        )
    
    return gt

def load_predictions_json(json_path: Path) -> Dict[str, Set[Optional[str]]]:
    """Load SAST predictions from JSON file"""
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    preds: Dict[str, Set[Optional[str]]] = defaultdict(set)
    
    vulnerabilities = data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
            
        # Extract file path from location
        location = vuln.get("location", {})
        file_path = location.get("file_path", "") if isinstance(location, dict) else ""
        
        if not file_path:
            continue
            
        # Extract test name
        test_name = normalize_test_name_from_path(file_path)
        if not test_name:
            continue
            
        # Extract CWE
        cwe = normalize_cwe(vuln.get("cwe_id") or vuln.get("cwe"))
        preds[test_name].add(cwe)
    
    return preds

@dataclass
class Confusion:
    TP: int
    FP: int
    TN: int
    FN: int
    
    def metrics(self) -> Dict[str, float]:
        tp, fp, tn, fn = self.TP, self.FP, self.TN, self.FN
        total = tp + fp + tn + fn
        pos = tp + fn
        neg = tn + fp
        
        # Basic metrics
        acc = (tp + tn) / total if total else 0.0
        tpr = tp / pos if pos else 0.0  # sensitivity/recall
        tnr = tn / neg if neg else 0.0  # specificity
        fpr = 1 - tnr
        fnr = 1 - tpr
        ppv = tp / (tp + fp) if (tp + fp) else 0.0  # precision
        npv = tn / (tn + fn) if (tn + fn) else 0.0
        f1 = (2 * ppv * tpr / (ppv + tpr)) if (ppv + tpr) else 0.0
        
        # Additional metrics
        prevalence = pos / total if total else 0.0
        balanced_acc = (tpr + tnr) / 2
        youden_j = tpr + tnr - 1
        
        # Matthews Correlation Coefficient
        import math
        denom = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) if all([(tp+fp),(tp+fn),(tn+fp),(tn+fn)]) else 0.0
        mcc = ((tp*tn - fp*fn)/denom) if denom else 0.0
        
        return {
            "total": total,
            "pos_support": pos,
            "neg_support": neg,
            "accuracy": acc,
            "tpr_recall_sensitivity": tpr,
            "tnr_specificity": tnr,
            "fpr": fpr,
            "fnr": fnr,
            "precision_ppv": ppv,
            "npv": npv,
            "f1": f1,
            "prevalence": prevalence,
            "balanced_accuracy": balanced_acc,
            "youden_j": youden_j,
            "mcc": mcc,
        }

def confusion_for_subset(gt_subset: List[GTEntry], preds_any: Dict[str, bool], preds_match_cwe: Dict[str, bool]):
    """Calculate confusion matrices for vulnerability detection and CWE matching"""
    TP_A = FP_A = TN_A = FN_A = 0
    TP_B = FP_B = TN_B = FN_B = 0
    
    for entry in gt_subset:
        y = entry.vulnerable
        p_any = preds_any.get(entry.test, False)
        p_cwe = preds_match_cwe.get(entry.test, False)
        
        # Task A: Any alert (vulnerability detection)
        if y and p_any: TP_A += 1
        elif y and not p_any: FN_A += 1
        elif (not y) and p_any: FP_A += 1
        else: TN_A += 1
        
        # Task B: CWE-aware (correct CWE identification)
        if y and p_cwe: TP_B += 1
        elif y and not p_cwe: FN_B += 1
        elif (not y) and p_cwe: FP_B += 1
        else: TN_B += 1
    
    return Confusion(TP_A, FP_A, TN_A, FN_A), Confusion(TP_B, FP_B, TN_B, FN_B)

def build_predictions_views(gt: Dict[str, GTEntry], preds_map: Dict[str, Set[Optional[str]]]):
    """Build prediction views for any alert and CWE matching"""
    preds_any: Dict[str, bool] = {}
    preds_match_cwe: Dict[str, bool] = {}
    per_test_pred_cwes: Dict[str, List[str]] = {}

    for test, entry in gt.items():
        cwes = preds_map.get(test, set())
        preds_any[test] = bool(cwes)
        
        if not entry.vulnerable:
            # For negative tests, any alert is considered wrong for CWE task
            preds_match_cwe[test] = bool(cwes)
        else:
            # For positive tests, check if predicted CWE matches ground truth
            gt_cwe = entry.cwe
            match = gt_cwe is not None and (gt_cwe in {c for c in cwes if c is not None})
            preds_match_cwe[test] = bool(match)
        
        per_test_pred_cwes[test] = sorted([c if c is not None else "NA" for c in cwes])
    
    return preds_any, preds_match_cwe, per_test_pred_cwes

def write_csv(path: Path, rows: List[Dict]):
    """Write rows to CSV file"""
    if not rows:
        return
    
    keys = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def main():
    parser = argparse.ArgumentParser(description="Evaluate CASTLE benchmark results")
    parser.add_argument("--ground-truth", required=True, type=Path, help="Path to CASTLE ground truth JSON")
    parser.add_argument("--predictions-json", required=True, type=Path, help="Path to SAST results JSON")
    parser.add_argument("--out-dir", type=Path, default=Path("./castle_score_out"), help="Output directory")
    args = parser.parse_args()

    # Load data
    print(f"Loading ground truth from: {args.ground_truth}")
    gt = load_ground_truth_json(args.ground_truth)
    print(f"Loaded {len(gt)} ground truth entries")
    
    print(f"Loading predictions from: {args.predictions_json}")
    preds_map = load_predictions_json(args.predictions_json)
    print(f"Loaded predictions for {len(preds_map)} tests")

    if not gt:
        raise SystemExit("Ground truth JSON parsed empty. Check the file format.")

    # Build prediction views
    preds_any, preds_match_cwe, per_test_pred_cwes = build_predictions_views(gt, preds_map)

    # Calculate global confusion matrices
    all_entries = list(gt.values())
    conf_any, conf_cwe = confusion_for_subset(all_entries, preds_any, preds_match_cwe)

    # Create output directory
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Global metrics
    global_rows = [
        {"level": "global", "task": "any_alert", **conf_any.metrics(), "TP": conf_any.TP, "FP": conf_any.FP, "TN": conf_any.TN, "FN": conf_any.FN},
        {"level": "global", "task": "cwe_aware", **conf_cwe.metrics(), "TP": conf_cwe.TP, "FP": conf_cwe.FP, "TN": conf_cwe.TN, "FN": conf_cwe.FN},
    ]
    write_csv(out_dir / "metrics_global.csv", global_rows)

    # Per-test results
    per_test_rows = []
    for test, entry in sorted(gt.items()):
        per_test_rows.append({
            "test": test,
            "gt_vulnerable": entry.vulnerable,
            "gt_cwe": entry.cwe or "NA",
            "gt_description": entry.description or "",
            "pred_any_alert": preds_any.get(test, False),
            "pred_cwe_match": preds_match_cwe.get(test, False),
            "pred_cwes": "|".join(per_test_pred_cwes.get(test, [])),
        })
    write_csv(out_dir / "per_test.csv", per_test_rows)

    # Summary
    def fmt(m):
        return (
            f"Acc={m['accuracy']:.4f}  "
            f"TPR={m['tpr_recall_sensitivity']:.4f}  TNR={m['tnr_specificity']:.4f}  "
            f"FPR={m['fpr']:.4f}  FNR={m['fnr']:.4f}  "
            f"P/PPV={m['precision_ppv']:.4f}  NPV={m['npv']:.4f}  F1={m['f1']:.4f}  "
            f"MCC={m['mcc']:.4f}  BalAcc={m['balanced_accuracy']:.4f}  "
            f"YoudenJ={m['youden_j']:.4f}"
        )

    # Print and save summary
    txt_lines = []
    txt_lines.append("CASTLE Benchmark — Scoring Summary\n")
    txt_lines.append(f"Total tests: {len(gt)}\n")
    
    # Any alert task
    m_any = global_rows[0]
    txt_lines.append("Task A — ANY ALERT (vulnerability detection without CWE consideration):\n")
    txt_lines.append(f"  Confusion: TP={m_any['TP']} FP={m_any['FP']} TN={m_any['TN']} FN={m_any['FN']}\n")
    txt_lines.append(f"  Metrics:   {fmt(m_any)}\n")
    
    # CWE aware task
    m_cwe = global_rows[1]
    txt_lines.append("Task B — CWE-AWARE (requires correct CWE identification for positive tests):\n")
    txt_lines.append(f"  Confusion: TP={m_cwe['TP']} FP={m_cwe['FP']} TN={m_cwe['TN']} FN={m_cwe['FN']}\n")
    txt_lines.append(f"  Metrics:   {fmt(m_cwe)}\n")
    
    # Save summary
    with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))

    # Print to console
    print("\n".join(txt_lines))
    print(f"\nWrote outputs to: {out_dir.resolve()}")

if __name__ == "__main__":
    main()
