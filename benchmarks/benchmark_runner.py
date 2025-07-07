"""Benchmark harness comparing LLM-SAST with other OSS SAST tools on
all files inside a target folder.

Usage:
    python benchmarks/benchmark_runner.py --target ./old_scripts --out ./bench_results

Requires:
    semgrep, bandit (install via pip) and any other engines you've registered.
    Ground-truth is optional; if omitted we only measure engine agreement counts.
"""
from __future__ import annotations
import argparse, csv, json, datetime, asyncio
from pathlib import Path
from typing import List, Tuple

from engines import ENGINE_REGISTRY  # noqa: E402

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _extract_ids(sarif: Path, severity_cutoff: str = "LOW") -> List[Tuple[str, str]]:
    with sarif.open() as f:
        doc = json.load(f)
    out = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            sev = res.get("properties", {}).get("severity", "LOW").upper()
            if SEV_RANK[sev] < SEV_RANK[severity_cutoff.upper()]:
                continue
            rule = res["ruleId"]
            loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            out.append((rule, loc))
    return out


def _metrics(gt: List[Tuple[str, str]], found: List[Tuple[str, str]]):
    s_gt, s_found = set(gt), set(found)
    tp = len(s_gt & s_found)
    fp = len(s_found - s_gt)
    fn = len(s_gt - s_found)
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Folder to scan")
    ap.add_argument("--out", default="./bench_results", help="Output directory")
    ap.add_argument("--severity", default="LOW", help="Severity cutoff")
    ap.add_argument("--ground_truth", help="Optional SARIF with known vulns for metrics")
    args = ap.parse_args()

    target_dir = Path(args.target).resolve()
    out_root = Path(args.out).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    results_rows = []

    # Load ground-truth ids if provided
    gt_ids = _extract_ids(Path(args.ground_truth), args.severity) if args.ground_truth else None

    for name, runner in ENGINE_REGISTRY.items():
        print(f"[+] Running {name}…")
        engine_out_dir = out_root / f"{name}_{ts}"
        engine_out_dir.mkdir(exist_ok=True)
        try:
            sarif_path = await runner(target_dir, engine_out_dir)
        except Exception as e:
            print(f"  [!] {name} failed: {e}")
            continue
        found_ids = _extract_ids(sarif_path, args.severity)
        metrics = _metrics(gt_ids, found_ids) if gt_ids else {"count": len(found_ids)}
        results_rows.append({"engine": name, **metrics})

    # Write CSV summary
    csv_path = out_root / f"summary_{ts}.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results_rows[0].keys())
        writer.writeheader(); writer.writerows(results_rows)
    print("Summary written to", csv_path)

if __name__ == "__main__":
    asyncio.run(main())
