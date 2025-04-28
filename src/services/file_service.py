import asyncio
from pathlib import Path
from typing import AsyncGenerator, List, Set
import aiofiles
import fnmatch
import logging
from ..models.config import ScannerConfig
from ..config.file_extensions import ALL_SCANNABLE, SPECIAL_FILES

logger = logging.getLogger(__name__)

class FileService:
    """Service for handling file operations."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        
    async def scan_files(self) -> AsyncGenerator[Path, None]:
        """Scan directory for files to analyze."""
        for file_path in self.config.target_dir.rglob("*"):
            if await self._should_analyze_file(file_path):
                yield file_path
                
    async def read_file(self, file_path: Path) -> str:
        """Read file contents."""
        async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
            return await f.read()
            
    async def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        # Basic checks
        if not file_path.is_file():
            return False
            
        # Check file size
        if file_path.stat().st_size > self.config.max_file_size:
            logger.debug(f"Skipping large file: {file_path}")
            return False
            
        # Check excluded patterns
        rel_path = file_path.relative_to(self.config.target_dir)
        for pattern in self.config.excluded_patterns:
            if fnmatch.fnmatch(str(rel_path), pattern):
                logger.debug(f"Skipping excluded file: {file_path}")
                return False
                
        # Check if file is in our scannable list
        is_special_file = file_path.name in SPECIAL_FILES
        has_valid_extension = file_path.suffix.lower() in ALL_SCANNABLE
        
        if not (is_special_file or has_valid_extension):
            logger.debug(f"Skipping unsupported file type: {file_path}")
            return False
            
        # Try to read file to check if it's text
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
                await f.read(1024)  # Try to read first 1KB
            return True
        except UnicodeDecodeError:
            logger.debug(f"Skipping binary file: {file_path}")
            return False
            
    async def ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True) 