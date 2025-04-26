from pathlib import Path
import json
from typing import List
from scanner.models import FileScanResult

class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def save(self, results: List[FileScanResult]):
        self.save_json(results)
        self.save_markdown(results)

    def save_json(self, results: List[FileScanResult]):
        path = self.output_dir / "report.json"
        data = [
            {"file": r.file_path, "vulnerabilities": [v.to_dict() for v in r.vulnerabilities]}
            for r in results
        ]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def save_markdown(self, results: List[FileScanResult]):
        path = self.output_dir / "report.md"
        with open(path, "w") as f:
            for result in results:
                f.write(f"## File: {result.file_path}\n\n")
                for v in result.vulnerabilities:
                    f.write(f"### {v.title} ({v.vuln_id})\n\n")
                    f.write(f"{v.description}\n\n")
                    if v.locations:
                        f.write("**Locations:**\n")
                        for loc in v.locations:
                            f.write(f"- Line {loc.get('line')}: `{loc.get('snippet')}`\n")
                        f.write("\n")
                    # Proof of Concept
                    poc = v.proof_of_concept
                    if isinstance(poc, dict):
                        poc_desc = poc.get('description', '')
                        poc_code = poc.get('code', '')
                    else:
                        poc_desc = poc
                        poc_code = ''
                    f.write("**POC:**\n")
                    f.write(f"{poc_desc}\n\n")
                    if poc_code:
                        f.write("```python\n")
                        f.write(f"{poc_code}\n")
                        f.write("```\n\n")
                    # Remediation
                    rem = v.remediation
                    if isinstance(rem, dict):
                        rem_desc = rem.get('description', '')
                        rem_code = rem.get('code', '')
                    else:
                        rem_desc = rem
                        rem_code = ''
                    f.write("**Remediation:**\n")
                    f.write(f"{rem_desc}\n\n")
                    if rem_code:
                        f.write("```python\n")
                        f.write(f"{rem_code}\n")
                        f.write("```\n\n")
                    if v.references:
                        f.write("**References:**\n")
                        for ref in v.references:
                            if isinstance(ref, dict):
                                title = ref.get('title', '').strip()
                                link = ref.get('url', '').strip()
                                f.write(f"- [{title}]({link})\n")
                            else:
                                f.write(f"- {ref}\n")
                        f.write("\n")
