import asyncio
from pathlib import Path
from typing import AsyncGenerator, List, Set
import aiofiles
import fnmatch
import logging
import mimetypes
import chardet
from ..models.config import ScannerConfig
from ..config.file_extensions import ALL_SCANNABLE, SPECIAL_FILES
from ..utils.exceptions import FileAccessError

class FileService:
    """Service for handling file operations."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger("llm_sast.file_service")
        self._processed_files = 0
        self._skipped_files = 0
        
    async def scan_files(self) -> AsyncGenerator[Path, None]:
        """Scan directory for files to analyze."""
        try:
            for file_path in self.config.target_dir.rglob("*"):
                if await self._should_analyze_file(file_path):
                    yield file_path
                else:
                    self._skipped_files += 1
                    
            self.logger.info(f"File scanning complete. Processed: {self._processed_files}, Skipped: {self._skipped_files}")
        except Exception as e:
            self.logger.error(f"Error scanning directory: {str(e)}")
            raise FileAccessError(f"Failed to scan directory: {str(e)}")
                
    async def read_file(self, file_path: Path) -> str:
        """Read file contents with encoding detection."""
        try:
            # First try UTF-8
            try:
                async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
                    return await f.read()
            except UnicodeDecodeError:
                # If UTF-8 fails, detect encoding
                async with aiofiles.open(file_path, mode='rb') as f:
                    content = await f.read()
                    result = chardet.detect(content)
                    encoding = result['encoding'] or 'utf-8'
                    
                # Read with detected encoding
                async with aiofiles.open(file_path, mode='r', encoding=encoding) as f:
                    return await f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            raise FileAccessError(f"Failed to read file: {str(e)}")
            
    async def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        try:
            # Basic checks
            if not file_path.is_file():
                return False
                
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.config.max_file_size:
                self.logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return False
                
            # Check excluded patterns
            rel_path = file_path.relative_to(self.config.target_dir)
            for pattern in self.config.excluded_patterns:
                if fnmatch.fnmatch(str(rel_path), pattern):
                    self.logger.debug(f"Skipping excluded file: {file_path}")
                    return False
                    
            # Check if file is in our scannable list
            is_special_file = file_path.name in SPECIAL_FILES
            has_valid_extension = file_path.suffix.lower() in ALL_SCANNABLE
            
            if not (is_special_file or has_valid_extension):
                self.logger.debug(f"Skipping unsupported file type: {file_path}")
                return False
                
            # Check MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and not mime_type.startswith(('text/', 'application/json', 'application/xml')):
                self.logger.debug(f"Skipping non-text file: {file_path} (MIME type: {mime_type})")
                return False
                
            # Try to read file to check if it's text
            try:
                async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
                    await f.read(1024)  # Try to read first 1KB
                self._processed_files += 1
                return True
            except UnicodeDecodeError:
                self.logger.debug(f"Skipping binary file: {file_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking file {file_path}: {str(e)}")
            return False
            
    async def ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        try:
            self.config.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Error creating output directory: {str(e)}")
            raise FileAccessError(f"Failed to create output directory: {str(e)}") 