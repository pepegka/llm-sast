from dataclasses import dataclass, field
from typing import List

@dataclass
class Vulnerability:
    vuln_id: str
    title: str
    description: str
    locations: List[dict] = field(default_factory=list)
    proof_of_concept: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "title": self.title,
            "description": self.description,
            "locations": self.locations,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "references": self.references,
        }

@dataclass
class FileScanResult:
    file_path: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def has_issues(self) -> bool:
        return bool(self.vulnerabilities)
