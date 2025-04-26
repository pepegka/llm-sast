from scanner.client import GPTClient
from scanner.models import Vulnerability

class Enricher:
    def __init__(self, client: GPTClient):
        self.client = client

    async def enrich(self, vuln: Vulnerability, code: str) -> Vulnerability:
        """
        Enrich a Vulnerability with proof_of_concept, remediation, and references.
        """
        # use only the relevant code snippets for enrichment
        if vuln.locations:
            snippets = [loc.get('snippet', '') for loc in vuln.locations]
        else:
            snippets = [code]
        context = "\n".join(snippets)
        raw = await self.client.enrich(vuln.to_dict(), context)
        # return enriched Vulnerability including original locations
        return Vulnerability(
            vuln_id=raw.get('vuln_id', vuln.vuln_id),
            title=raw.get('title', vuln.title),
            description=raw.get('description', vuln.description),
            locations=vuln.locations,
            proof_of_concept=raw.get('proof_of_concept', ''),
            remediation=raw.get('remediation', ''),
            references=raw.get('references', []),
        )
