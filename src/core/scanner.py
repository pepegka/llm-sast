import asyncio
import logging
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
        self.logger = logging.getLogger(__name__)
        
    async def run(self) -> List[Vulnerability]:
        """Run the scanning process."""
        self.logger.info(f"Starting scan of {self.config.target_dir}")
        await self.file_service.ensure_output_dir()
        
        vulnerabilities = []
        async for file_path in self.file_service.scan_files():
            try:
                self.logger.debug(f"Scanning file: {file_path}")
                content = await self.file_service.read_file(file_path)
                
                # Analyze the file
                file_vulnerabilities = await self.llm_service.analyze_code(
                    code=content,
                    file_path=str(file_path)
                )
                
                # Enrich findings
                for vuln in file_vulnerabilities:
                    enriched_vuln = await self.llm_service.enrich_finding(vuln)
                    vulnerabilities.append(enriched_vuln)
                    
            except FileAccessError as e:
                self.logger.error(f"Error accessing file {file_path}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error scanning file {file_path}: {str(e)}")
                
        # Generate reports using all configured reporters
        for reporter in self.reporters:
            try:
                await reporter.report(vulnerabilities)
                summary = await reporter.get_summary(vulnerabilities)
                self.logger.info(f"Report generated using {reporter.__class__.__name__}. {summary}")
            except Exception as e:
                self.logger.error(f"Error generating report with {reporter.__class__.__name__}: {str(e)}")
        
        return vulnerabilities