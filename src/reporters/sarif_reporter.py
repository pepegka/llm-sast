"""SARIF reporter converts collected Vulnerability objects into SARIF v2.1.0
without requiring extra LLM calls.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from ..models.vulnerability import Vulnerability, Severity
from ..models.config import ScannerConfig

class SARIFReporter:
    """Generate SARIF output so results can be consumed by tools & benchmarks."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.output_file: Path | None = None

    async def report(self, vulnerabilities: List[Vulnerability]) -> None:
        # Guarantee directory
        out_dir = self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = out_dir / f"sast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"

        sarif_doc = self._build_sarif(vulnerabilities)
        import aiofiles  # type: ignore
        async with aiofiles.open(self.output_file, "w", encoding="utf-8") as f:
            await f.write(json.dumps(sarif_doc, indent=2))

    async def get_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        return f"SARIF file saved to {self.output_file}" if self.output_file else "No SARIF file generated"

    # ---------------------------------------------------------------------
    def _build_sarif(self, vulns: List[Vulnerability]) -> Dict[str, Any]:
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for idx, v in enumerate(vulns):
            rule_id = v.cwe_id or v.title.replace(" ", "_")[:60]
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": v.title,
                    "shortDescription": {"text": v.title},
                    "fullDescription": {"text": v.description},
                    "help": {"text": v.recommendation or v.fix or "", "markdown": v.recommendation or v.fix or ""},
                    "properties": {
                        "security-severity": Severity[v.severity.name].level,
                    },
                }
            # Build result
            res = {
                "ruleId": rule_id,
                "level": v.severity.value.lower(),
                "message": {"text": v.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(v.location.file_path)},
                            "region": {
                                "startLine": v.location.start_line,
                                "endLine": v.location.end_line,
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": v.severity.value,
                    "confidence": v.confidence,
                },
            }
            results.append(res)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLM-SAST",
                            "informationUri": "https://github.com/your-org/llm-sast",
                            "rules": list(rules.values()),
                        }
                    },
                    "columnKind": "unicodeCodePoints",
                    "results": results,
                }
            ],
        }
        return sarif
