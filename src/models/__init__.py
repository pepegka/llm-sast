"""Data models and configurations."""

from .config import ScannerConfig
from .vulnerability import Vulnerability, CodeLocation, Severity

__all__ = ['ScannerConfig', 'Vulnerability', 'CodeLocation', 'Severity'] 