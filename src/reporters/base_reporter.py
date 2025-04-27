from abc import ABC, abstractmethod
from typing import List
from ..models.vulnerability import Vulnerability
from ..models.config import ScannerConfig

class BaseReporter(ABC):
    """Abstract base class for vulnerability reporters."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        
    @abstractmethod
    async def report(self, vulnerabilities: List[Vulnerability]) -> None:
        """Generate and save a report of the vulnerabilities found."""
        pass
        
    @abstractmethod
    async def get_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        """Get a summary of the vulnerabilities found."""
        pass 