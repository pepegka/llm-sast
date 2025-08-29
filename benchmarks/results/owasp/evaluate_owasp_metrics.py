
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OWASP Benchmark Java scorer for custom SAST outputs (JSON / SARIF)
# ------------------------------------------------------------------
# What it does
# - Reads OWASP ground truth CSV (expectedresults-*.csv).
# - Reads your SAST results (custom JSON as shown in the screenshots and/or SARIF).
# - Normalizes findings per test case (BenchmarkTestNNNNN) with deduplication.
# - Computes TWO tasks (fully separated everywhere):
#   A) any_alert:   "вообще нашёл уязвимость в тесте?" (без учёта CWE)
#   B) cwe_aware:   "нашёл уязвимость И угадал CWE?"  (для отрицательных тестов: ЛЮБОЙ алерт = FP)
# - Prints summary and writes rich CSVs per task, per category и per CWE.
#
# Metrics
# -------
# Мы считаем расширенный набор метрик (везде одинаковый):
#   counts: TP, FP, TN, FN, total, pos_support, neg_support
#   rates:  tpr/recall/sensitivity, tnr/specificity, fpr, fnr, prevalence,
#           predicted_positive_rate (PPR), predicted_negative_rate (PNR)
#   values: precision (PPV), npv, fdr, for_, f1, f0_5, f2, threat_score (Jaccard/Tversky beta=1),
#           mcc, youden_j, balanced_accuracy, g_mean, lr_plus, lr_minus, dor, kappa, markedness
#   owasp_score = 100 * (tpr - fpr)  (эквивалент 100 * Youden J)
#
# Usage example:
#   python owasp_benchmark_scoring.py \
#     --ground-truth expectedresults-1.2.csv \
#     --predictions-json results.json \
#     --out-dir ./score_out
#
# Notes:
# - Test name extraction: берём filename без расширения из JSON location.file_path;
#   плюс regex-фоллбек по "BenchmarkTest\d{5}". Для SARIF делаем tolerant-разбор.
# - CWE нормализуем к строке цифр: "22" для "CWE-22"/"CWE-0022".
#
import argparse
import csv
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

RE_TEST = re.compile(r"(BenchmarkTest\d{5})", re.IGNORECASE)

def normalize_test_name_from_path(path: str) -> Optional[str]:
    if not path:
        return None
    base = os.path.basename(path)
    name, _ext = os.path.splitext(base)
    if RE_TEST.fullmatch(name):
        return name
    m = RE_TEST.search(base)
    return m.group(1) if m else None

def normalize_test_name_from_any(s: str) -> Optional[str]:
    if not s:
        return None
    m = RE_TEST.search(s)
    return m.group(1) if m else None

def normalize_cwe(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    m = re.search(r"(\d+)", str(raw))
    return m.group(1) if m else None

@dataclass
class GTEntry:
    test: str
    category: str
    vuln: bool
    cwe: Optional[str]

def load_ground_truth(csv_path: Path) -> Dict[str, GTEntry]:
    gt: Dict[str, GTEntry] = {}
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            # expected: test name, category, real vulnerability, cwe, ...
            test_raw = row[0].strip()
            m = RE_TEST.search(test_raw)
            if not m:
                continue
            test = m.group(1)
            category = (row[1].strip() if len(row) > 1 else "") or ""
            vuln_str = (row[2].strip() if len(row) > 2 else "").lower()
            vuln = vuln_str in ("true", "1", "yes", "y")
            cwe = normalize_cwe(row[3].strip() if len(row) > 3 else None)
            gt[test] = GTEntry(test=test, category=category, vuln=vuln, cwe=cwe)
    return gt

def load_predictions_json(json_path: Path) -> Dict[str, Set[Optional[str]]]:
    """
    Returns mapping: test_name -> set of CWE strings (digits) seen in alerts.
    If a finding lacks CWE, stores None for that finding.
    Assumes JSON with top-level key "vulnerabilities": [ { location: {file_path: ...}, cwe_id: "CWE-XXX" } ]
    """
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    preds: Dict[str, Set[Optional[str]]] = defaultdict(set)

    vulns = data.get("vulnerabilities") or data.get("results") or []
    for v in vulns:
        fp = None
        if isinstance(v, dict):
            loc = v.get("location") or {}
            if isinstance(loc, dict):
                fp = loc.get("file_path") or loc.get("artifact") or loc.get("uri")
            if not fp:
                fp = v.get("file") or v.get("path")
        test = None
        if fp:
            test = normalize_test_name_from_path(str(fp))
        if not test:
            test = normalize_test_name_from_any(json.dumps(v, ensure_ascii=False))
        if not test:
            continue

        cwe = None
        if isinstance(v, dict):
            cwe = v.get("cwe_id") or v.get("cwe") or v.get("cweId") or v.get("ruleId")
            if not cwe:
                props = v.get("properties") or {}
                tags = props.get("tags") if isinstance(props, dict) else None
                if isinstance(tags, list):
                    for t in tags:
                        if isinstance(t, str) and "cwe" in t.lower():
                            cwe = t
                            break
        preds[test].add(normalize_cwe(cwe))
    return preds

def load_predictions_sarif(sarif_path: Path) -> Dict[str, Set[Optional[str]]]:
    """
    Tolerant SARIF reader (v2.1.0-ish). Extracts locations and CWEs.
    """
    with sarif_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    preds: Dict[str, Set[Optional[str]]] = defaultdict(set)

    runs = data.get("runs") or []
    # Build ruleId -> CWE map if available
    rule_to_cwe: Dict[str, Optional[str]] = {}
    for run in runs:
        tool = (run or {}).get("tool") or {}
        driver = (tool or {}).get("driver") or {}
        rules = driver.get("rules") or []
        for rule in rules:
            rule_id = rule.get("id")
            cwe = None
            props = rule.get("properties") or {}
            tags = props.get("tags") or []
            for t in tags:
                if isinstance(t, str) and "cwe" in t.lower():
                    cwe = normalize_cwe(t)
                    break
            if not cwe:
                cwe = normalize_cwe(rule.get("helpUri") or rule.get("name"))
            if rule_id:
                rule_to_cwe[rule_id] = cwe

    for run in runs:
        results = run.get("results") or []
        for r in results:
            fp = None
            locs = r.get("locations") or []
            if locs:
                pl = (locs[0] or {}).get("physicalLocation") or {}
                al = pl.get("artifactLocation") or {}
                fp = al.get("uri") or al.get("uriBaseId")
            if not fp:
                fp = r.get("analysisTarget", {}).get("uri")

            test = None
            if fp:
                test = normalize_test_name_from_path(str(fp))
            if not test:
                test = normalize_test_name_from_any(json.dumps(r, ensure_ascii=False))
            if not test:
                continue

            cwe = None
            rule_id = r.get("ruleId") or (r.get("rule") or {}).get("id")
            if rule_id in rule_to_cwe:
                cwe = rule_to_cwe.get(rule_id)
            if not cwe:
                props = r.get("properties") or {}
                tags = props.get("tags") or []
                for t in tags:
                    if isinstance(t, str) and "cwe" in t.lower():
                        cwe = normalize_cwe(t)
                        break
            preds[test].add(normalize_cwe(cwe))
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
        # base
        acc = (tp + tn) / total if total else 0.0
        tpr = tp / pos if pos else 0.0  # sensitivity/recall
        tnr = tn / neg if neg else 0.0  # specificity
        fpr = 1 - tnr
        fnr = 1 - tpr
        ppv = tp / (tp + fp) if (tp + fp) else 0.0  # precision
        npv = tn / (tn + fn) if (tn + fn) else 0.0
        f1 = (2 * ppv * tpr / (ppv + tpr)) if (ppv + tpr) else 0.0
        # extra F-scores
        beta05 = 0.5
        f0_5 = (((1+beta05**2) * ppv * tpr) / (beta05**2 * ppv + tpr)) if (beta05**2 * ppv + tpr) else 0.0
        beta2 = 2.0
        f2 = (((1+beta2**2) * ppv * tpr) / (beta2**2 * ppv + tpr)) if (beta2**2 * ppv + tpr) else 0.0
        # others
        prevalence = pos / total if total else 0.0
        ppr = (tp + fp) / total if total else 0.0  # predicted positive rate
        pnr = (tn + fn) / total if total else 0.0
        fdr = fp / (tp + fp) if (tp + fp) else 0.0
        for_ = fn / (fn + tn) if (fn + tn) else 0.0
        threat_score = tp / (tp + fn + fp) if (tp + fn + fp) else 0.0  # Jaccard/Tversky beta=1
        # MCC
        import math
        denom = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) if all([(tp+fp),(tp+fn),(tn+fp),(tn+fn)]) else 0.0
        mcc = ((tp*tn - fp*fn)/denom) if denom else 0.0
        bal_acc = (tpr + tnr) / 2
        youden_j = tpr + tnr - 1
        g_mean = math.sqrt(max(tpr,0.0) * max(tnr,0.0))
        # Likelihood ratios & diagnostic odds
        lr_plus = (tpr / fpr) if fpr > 0 else float("inf") if tpr > 0 else 0.0
        lr_minus = (fnr / tnr) if tnr > 0 else float("inf") if fnr > 0 else 0.0
        dor = (lr_plus / lr_minus) if (lr_minus not in (0.0, float("inf")) and lr_plus not in (0.0,)) else float("inf") if (lr_minus>0 and lr_plus>0) else 0.0
        # Cohen's kappa
        pe = (((tp+fp)*(tp+fn)) + ((fn+tn)*(fp+tn))) / (total*total) if total else 0.0
        kappa = (acc - pe) / (1 - pe) if (1 - pe) > 0 else 0.0
        # Markedness
        markedness = ppv + npv - 1
        owasp_score = 100.0 * youden_j  # 100*(tpr-fpr)
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
            "f0_5": f0_5,
            "f2": f2,
            "prevalence": prevalence,
            "predicted_positive_rate": ppr,
            "predicted_negative_rate": pnr,
            "fdr": fdr,
            "for": for_,
            "threat_score": threat_score,
            "mcc": mcc,
            "balanced_accuracy": bal_acc,
            "youden_j": youden_j,
            "g_mean": g_mean,
            "lr_plus": lr_plus,
            "lr_minus": lr_minus,
            "diagnostic_odds_ratio": dor,
            "cohens_kappa": kappa,
            "markedness": markedness,
            "owasp_score": owasp_score,
        }

def confusion_for_subset(gt_subset, preds_any, preds_match_cwe):
    TP_A = FP_A = TN_A = FN_A = 0
    TP_B = FP_B = TN_B = FN_B = 0
    for e in gt_subset:
        y = e.vuln
        p_any = preds_any.get(e.test, False)
        p_cwe = preds_match_cwe.get(e.test, False)
        # Task A
        if y and p_any: TP_A += 1
        elif y and not p_any: FN_A += 1
        elif (not y) and p_any: FP_A += 1
        else: TN_A += 1
        # Task B
        if y and p_cwe: TP_B += 1
        elif y and not p_cwe: FN_B += 1
        elif (not y) and p_cwe: FP_B += 1
        else: TN_B += 1
    return Confusion(TP_A, FP_A, TN_A, FN_A), Confusion(TP_B, FP_B, TN_B, FN_B)

def build_predictions_views(gt: Dict[str, 'GTEntry'], preds_map: Dict[str, Set[Optional[str]]]):
    preds_any: Dict[str, bool] = {}
    preds_match_cwe: Dict[str, bool] = {}
    per_test_pred_cwes: Dict[str, List[str]] = {}

    for test, entry in gt.items():
        cwes = preds_map.get(test, set())
        preds_any[test] = bool(cwes)
        if not entry.vuln:
            preds_match_cwe[test] = bool(cwes)  # negatives: any alert is FP in CWE-aware task
        else:
            gt_cwe = entry.cwe
            match = gt_cwe is not None and (gt_cwe in {c for c in cwes if c is not None})
            preds_match_cwe[test] = bool(match)
        per_test_pred_cwes[test] = sorted([c if c is not None else "NA" for c in cwes])
    return preds_any, preds_match_cwe, per_test_pred_cwes

def compute_group_metrics(gt: Dict[str, 'GTEntry'], preds_any, preds_match_cwe):
    groups_cwe = defaultdict(list)
    groups_cat = defaultdict(list)
    for e in gt.values():
        groups_cwe[str(e.cwe or "NA")].append(e)
        groups_cat[str(e.category or "NA")].append(e)
    rows_cwe = []
    rows_cat = []
    for key, subset in groups_cwe.items():
        cA, cB = confusion_for_subset(subset, preds_any, preds_match_cwe)
        rows_cwe.append({"group": "cwe", "key": key, "task": "any_alert", **cA.metrics(), "TP": cA.TP, "FP": cA.FP, "TN": cA.TN, "FN": cA.FN})
        rows_cwe.append({"group": "cwe", "key": key, "task": "cwe_aware", **cB.metrics(), "TP": cB.TP, "FP": cB.FP, "TN": cB.TN, "FN": cB.FN})
    for key, subset in groups_cat.items():
        cA, cB = confusion_for_subset(subset, preds_any, preds_match_cwe)
        rows_cat.append({"group": "category", "key": key, "task": "any_alert", **cA.metrics(), "TP": cA.TP, "FP": cA.FP, "TN": cA.TN, "FN": cA.FN})
        rows_cat.append({"group": "category", "key": key, "task": "cwe_aware", **cB.metrics(), "TP": cB.TP, "FP": cB.FP, "TN": cB.TN, "FN": cB.FN})
    return rows_cwe, rows_cat

def write_csv(path: Path, rows: List[Dict]):
    if not rows:
        return
    # stable header
    keys = sorted(set().union(*[r.keys() for r in rows]), key=lambda x: list(r.keys()).index(x) if (r:=rows[0]) and x in rows[0] else 999)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def split_and_write(rows: List[Dict], out_dir: Path, stem: str):
    # Write combined and split by task
    write_csv(out_dir / f"{stem}.csv", rows)
    for task in ("any_alert", "cwe_aware"):
        write_csv(out_dir / f"{stem}_{task}.csv", [r for r in rows if r.get("task")==task])

def main():
    ap = argparse.ArgumentParser(description="Score OWASP Benchmark Java results (JSON/SARIF).")
    ap.add_argument("--ground-truth", required=True, type=Path, help="Path to expectedresults-*.csv")
    ap.add_argument("--predictions-json", type=Path, nargs="*", default=[], help="One or more JSON files from your parser")
    ap.add_argument("--predictions-sarif", type=Path, nargs="*", default=[], help="One or more SARIF files")
    ap.add_argument("--out-dir", type=Path, default=Path("./score_out"))
    args = ap.parse_args()

    gt = load_ground_truth(args.ground_truth)
    if not gt:
        raise SystemExit("Ground truth CSV parsed empty. Check the file format.")

    # Merge predictions from all inputs
    preds_map: Dict[str, Set[Optional[str]]] = defaultdict(set)
    for p in args.predictions_json:
        m = load_predictions_json(p)
        for k, v in m.items():
            preds_map[k].update(v)
    for p in args.predictions_sarif:
        m = load_predictions_sarif(p)
        for k, v in m.items():
            preds_map[k].update(v)

    preds_any, preds_match_cwe, per_test_pred_cwes = build_predictions_views(gt, preds_map)

    # Global confusions
    all_entries = list(gt.values())
    conf_any, conf_cwe = confusion_for_subset(all_entries, preds_any, preds_match_cwe)

    # Grouped metrics
    rows_cwe, rows_cat = compute_group_metrics(gt, preds_any, preds_match_cwe)

    # Outputs
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # confusion matrices table (global) + extended metrics
    global_rows = [
        {"level":"global", "task": "any_alert", **conf_any.metrics(), "TP": conf_any.TP, "FP": conf_any.FP, "TN": conf_any.TN, "FN": conf_any.FN},
        {"level":"global", "task": "cwe_aware", **conf_cwe.metrics(), "TP": conf_cwe.TP, "FP": conf_cwe.FP, "TN": conf_cwe.TN, "FN": conf_cwe.FN},
    ]
    write_csv(out_dir / "metrics_global.csv", global_rows)

    # per-test table
    per_test_rows = []
    for test, entry in sorted(gt.items()):
        per_test_rows.append({
            "test": test,
            "category": entry.category,
            "gt_vuln": entry.vuln,
            "gt_cwe": entry.cwe or "NA",
            "pred_any_alert": preds_any.get(test, False),
            "pred_cwe_match": preds_match_cwe.get(test, False),
            "pred_cwes": "|".join(per_test_pred_cwes.get(test, [])),
        })
    write_csv(out_dir / "per_test.csv", per_test_rows)

    # group exports (combined and split by task)
    split_and_write(rows_cwe, out_dir, "metrics_by_cwe")
    split_and_write(rows_cat, out_dir, "metrics_by_category")

    # JSON summary for machines + TXT for humans
    summary = {
        "total_tests": len(gt),
        "json_files": [str(p) for p in args.predictions_json],
        "sarif_files": [str(p) for p in args.predictions_sarif],
        "global": {row["task"]: {"confusion": {"TP": row["TP"], "FP": row["FP"], "TN": row["TN"], "FN": row["FN"]},
                                 "metrics": {k: v for k, v in row.items() if k not in {"level","task","TP","FP","TN","FN"}}}
                   for row in global_rows},
        "outputs": {
            "metrics_global_csv": str(out_dir / "metrics_global.csv"),
            "per_test_csv": str(out_dir / "per_test.csv"),
            "metrics_by_cwe_csv": str(out_dir / "metrics_by_cwe.csv"),
            "metrics_by_cwe_any_alert_csv": str(out_dir / "metrics_by_cwe_any_alert.csv"),
            "metrics_by_cwe_cwe_aware_csv": str(out_dir / "metrics_by_cwe_cwe_aware.csv"),
            "metrics_by_category_csv": str(out_dir / "metrics_by_category.csv"),
            "metrics_by_category_any_alert_csv": str(out_dir / "metrics_by_category_any_alert.csv"),
            "metrics_by_category_cwe_aware_csv": str(out_dir / "metrics_by_category_cwe_aware.csv"),
            "summary_txt": str(out_dir / "summary.txt"),
            "summary_json": str(out_dir / "summary.json"),
        }
    }
    with (out_dir / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    def fmt(m):
        return (
            f"Acc={m['accuracy']:.4f}  "
            f"TPR={m['tpr_recall_sensitivity']:.4f}  TNR={m['tnr_specificity']:.4f}  "
            f"FPR={m['fpr']:.4f}  FNR={m['fnr']:.4f}  "
            f"P/PPV={m['precision_ppv']:.4f}  NPV={m['npv']:.4f}  F1={m['f1']:.4f}  "
            f"MCC={m['mcc']:.4f}  BalAcc={m['balanced_accuracy']:.4f}  "
            f"YoudenJ={m['youden_j']:.4f}  OWASP={m['owasp_score']:.2f}"
        )

    txt_lines = []
    txt_lines.append("OWASP Benchmark Java — Scoring Summary\n")
    txt_lines.append(f"Total tests: {len(gt)}\n")
    # Any alert
    m_any = global_rows[0]
    txt_lines.append("Task A — ANY ALERT (нашёл уязвимость без учёта CWE):\n")
    txt_lines.append(f"  Confusion: TP={m_any['TP']} FP={m_any['FP']} TN={m_any['TN']} FN={m_any['FN']}\n")
    txt_lines.append(f"  Metrics:   {fmt(m_any)}\n")
    # CWE aware
    m_cwe = global_rows[1]
    txt_lines.append("Task B — CWE-AWARE (для позитивных тестов требуется совпадение CWE):\n")
    txt_lines.append(f"  Confusion: TP={m_cwe['TP']} FP={m_cwe['FP']} TN={m_cwe['TN']} FN={m_cwe['FN']}\n")
    txt_lines.append(f"  Metrics:   {fmt(m_cwe)}\n")
    with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))

    # Print compact stdout summary
    print("\n".join(txt_lines))
    print(f"\nWrote outputs to: {out_dir.resolve()}")

if __name__ == "__main__":
    main()
