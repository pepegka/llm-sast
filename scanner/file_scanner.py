from pathlib import Path
from typing import Optional
from scanner.detector import Detector
from scanner.enricher import Enricher
from scanner.models import FileScanResult

class FileScanner:
    def __init__(self, detector: Detector, enricher: Enricher):
        self.detector = detector
        self.enricher = enricher

    async def scan(self, filepath: Path) -> Optional[FileScanResult]:
        """
        Detects and enriches vulnerabilities in a single file.
        Returns FileScanResult if issues found, else None.
        """
        code = filepath.read_text()
        vulns = await self.detector.detect(code)
        if not vulns:
            return None
        enriched = []
        for vuln in vulns:
            enriched_vuln = await self.enricher.enrich(vuln, code)
            enriched.append(enriched_vuln)
        return FileScanResult(file_path=str(filepath), vulnerabilities=enriched)
