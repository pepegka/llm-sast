class ScannerError(Exception):
    """Base exception for all scanner-related errors."""
    pass

class APIError(ScannerError):
    """Raised when there's an error communicating with the LLM API."""
    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message)

class ConfigurationError(ScannerError):
    """Raised when there's an error in the scanner configuration."""
    pass

class FileAccessError(ScannerError):
    """Raised when there's an error accessing or reading files."""
    pass

class ReportGenerationError(ScannerError):
    """Raised when there's an error generating the vulnerability report."""
    pass 