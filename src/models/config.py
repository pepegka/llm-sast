from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class ScannerConfig:
    """Configuration class for the SAST scanner."""
    target_dir: Path
    output_dir: Path
    concurrency: int
    api_key: str
    log_level: str = "INFO"
    timeout: int = 3600
    max_file_size: int = 1024 * 1024  # 1MB
    excluded_patterns: list[str] = None
    
    def __post_init__(self):
        self.target_dir = Path(self.target_dir).resolve()
        self.output_dir = Path(self.output_dir).resolve()
        if self.excluded_patterns is None:
            self.excluded_patterns = [
                "**/.git/**",
                "**/node_modules/**",
                "**/venv/**",
                "**/__pycache__/**"
            ] 