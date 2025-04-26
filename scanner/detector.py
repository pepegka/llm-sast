from typing import List
from scanner.client import GPTClient
from scanner.models import Vulnerability

class Detector:
    def __init__(self, client: GPTClient):
        self.client = client

    async def detect(self, code: str) -> List[Vulnerability]:
        """
        Identify vulnerabilities in code and return list of Vulnerability objects.
        """
        raw = await self.client.detect(code)
        vulns: List[Vulnerability] = []
        for item in raw:
            # map reported snippets to actual file lines
            mapped_locs = []
            for loc in item.get('locations', []):
                snippet = loc.get('snippet', '').strip()
                for idx, line in enumerate(code.splitlines(), start=1):
                    if snippet and snippet in line:
                        mapped_locs.append({'line': idx, 'snippet': line.strip()})
            # dedupe
            unique_locs = []
            for ml in mapped_locs:
                if ml not in unique_locs:
                    unique_locs.append(ml)
            vuln = Vulnerability(
                vuln_id=item.get('vuln_id', ''),
                title=item.get('title', ''),
                description=item.get('description', ''),
                locations=unique_locs
            )
            vulns.append(vuln)
        return vulns
