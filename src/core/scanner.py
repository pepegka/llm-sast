import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
from ..models.config import ScannerConfig
from ..models.vulnerability import Vulnerability
from ..services.llm_service import LLMService, OpenAIService
from ..services.file_service import FileService
from ..reporters.base_reporter import BaseReporter
from ..reporters.json_reporter import JSONReporter
from ..reporters.markdown_reporter import MarkdownReporter
from ..utils.exceptions import ScannerError, FileAccessError

class Scanner:
    """Main scanner class that orchestrates the SAST scanning process."""
    
    def __init__(self, config: ScannerConfig, openai_config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            config: Scanner configuration
            openai_config: OpenAI configuration dictionary
        """
        self.config = config
        self.llm_service = OpenAIService({"openai": openai_config})
        self.file_service = FileService(config=config)
        # Initialize both reporters
        self.reporters = [
            JSONReporter(config=config),
            MarkdownReporter(config=config)
        ]
        self.logger = logging.getLogger("llm_sast.scanner")
        self._processed_files = 0
        self._total_files = 0
        self._start_time = None
        self._file_times = {}
        
    async def _count_total_files(self) -> int:
        """Count total number of files to be scanned."""
        count = 0
        async for _ in self.file_service.scan_files():
            count += 1
        return count
        
    async def scan(self) -> List[Vulnerability]:
        """Run the SAST scan and return all found vulnerabilities."""
        self._start_time = time.time()
        self.logger.info("Starting SAST scan...")
        
        # Count total files first
        self._total_files = await self._count_total_files()
        self.logger.info(f"Found {self._total_files} files to scan")
        
        all_vulnerabilities = []
        async for file_path in self.file_service.scan_files():
            file_start_time = time.time()
            self._processed_files += 1
            self.logger.info(f"Scanning file {self._processed_files}/{self._total_files}: {file_path}")
            
            try:
                # Read file content
                self.logger.debug(f"Reading file: {file_path}")
                content = await self.file_service.read_file(file_path)
                
                # Analyze code
                self.logger.debug(f"Analyzing code in: {file_path}")
                vulnerabilities = await self.llm_service.analyze_code(content, str(file_path))
                
                # Enrich findings
                self.logger.debug(f"Enriching findings for: {file_path}")
                enriched_vulnerabilities = []
                for vuln in vulnerabilities:
                    enriched_vuln = await self.llm_service.enrich_finding(vuln)
                    enriched_vulnerabilities.append(enriched_vuln)
                
                all_vulnerabilities.extend(enriched_vulnerabilities)
                
                # Log file completion
                file_time = time.time() - file_start_time
                self._file_times[str(file_path)] = file_time
                self.logger.info(f"Completed scanning {file_path} in {file_time:.2f} seconds. Found {len(vulnerabilities)} vulnerabilities.")
                
            except FileAccessError as e:
                self.logger.error(f"Error accessing file {file_path}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error scanning file {file_path}: {str(e)}")
        
        # Generate reports
        self.logger.info("Generating reports...")
        report_start_time = time.time()
        for reporter in self.reporters:
            await reporter.report(all_vulnerabilities)
            summary = await reporter.get_summary(all_vulnerabilities)
            self.logger.info(f"Report generated using {reporter.__class__.__name__}. {summary}")
        report_time = time.time() - report_start_time
        
        # Log final statistics
        total_time = time.time() - self._start_time
        self.logger.info("\nScan Statistics:")
        self.logger.info(f"Total scan time: {total_time:.2f} seconds")
        self.logger.info(f"Report generation time: {report_time:.2f} seconds")
        self.logger.info(f"Total files scanned: {self._processed_files}")
        self.logger.info(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
        
        # Log per-file timing statistics
        avg_file_time = sum(self._file_times.values()) / len(self._file_times) if self._file_times else 0
        max_file_time = max(self._file_times.values()) if self._file_times else 0
        min_file_time = min(self._file_times.values()) if self._file_times else 0
        self.logger.info(f"Average file scan time: {avg_file_time:.2f} seconds")
        self.logger.info(f"Fastest file scan: {min_file_time:.2f} seconds")
        self.logger.info(f"Slowest file scan: {max_file_time:.2f} seconds")
        
        return all_vulnerabilities