import asyncio
from pathlib import Path
from typing import AsyncGenerator, List, Set
import aiofiles
import fnmatch
from ..models.config import ScannerConfig

class FileService:
    """Service for handling file operations."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        
    async def scan_files(self) -> AsyncGenerator[Path, None]:
        """
        Asynchronously scan for files in the target directory.
        Yields file paths that should be analyzed.
        """
        for file_path in self.config.target_dir.rglob("*"):
            if await self._should_analyze_file(file_path):
                yield file_path
                
    async def read_file(self, file_path: Path) -> str:
        """Read the contents of a file asynchronously."""
        async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
            return await f.read()
            
    async def _should_analyze_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be analyzed based on configuration rules.
        """
        # Skip if not a file
        if not file_path.is_file():
            return False
            
        # Skip if file is too large
        if file_path.stat().st_size > self.config.max_file_size:
            return False
            
        # Skip if matches excluded patterns
        rel_path = str(file_path.relative_to(self.config.target_dir))
        for pattern in self.config.excluded_patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return False
                
        # Skip binary files and known non-code files
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
                await f.read(1024)  # Try to read first 1KB
            return True
        except UnicodeDecodeError:
            return False
            
    async def ensure_output_dir(self) -> None:
        """Ensure the output directory exists."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True) 