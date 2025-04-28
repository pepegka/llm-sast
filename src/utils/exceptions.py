class LLMServiceError(Exception):
    """Base exception for LLM service errors."""
    pass

class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""
    pass

class ScannerError(Exception):
    """Exception raised for scanner-related errors."""
    pass

class FileAccessError(Exception):
    """Exception raised for file access-related errors."""
    pass

class ReportGenerationError(Exception):
    """Exception raised for report generation errors."""
    pass

class ValidationError(Exception):
    """Exception raised for validation errors."""
    pass

class APIError(ScannerError):
    """Raised when there's an error communicating with the LLM API."""
    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message) 