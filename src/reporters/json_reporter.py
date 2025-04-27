import json
from pathlib import Path
from typing import List, Dict
import aiofiles
from datetime import datetime
from .base_reporter import BaseReporter
from ..models.vulnerability import Vulnerability, Severity

class JSONReporter(BaseReporter):
    """JSON implementation of the vulnerability reporter."""
    
    async def report(self, vulnerabilities: List[Vulnerability]) -> None:
        """Generate and save a JSON report of the vulnerabilities found."""
        report_data = {
            "scan_time": datetime.now().isoformat(),
            "target_directory": str(self.config.target_dir),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": [self._format_vulnerability(vuln) for vuln in vulnerabilities],
            "summary": await self.get_summary(vulnerabilities)
        }
        
        output_file = self.config.output_dir / f"sast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        async with aiofiles.open(output_file, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(report_data, indent=2))
            
    async def get_summary(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Get a summary of the vulnerabilities found."""
        severity_counts = {severity: 0 for severity in Severity}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
            
        return {
            "total_count": len(vulnerabilities),
            "severity_breakdown": {
                severity.value: count
                for severity, count in severity_counts.items()
                if count > 0
            }
        }
        
    def _format_vulnerability(self, vuln: Vulnerability) -> Dict:
        """Format a vulnerability for JSON output - excluding PoC and fix details."""
        return vuln.to_json_dict() 