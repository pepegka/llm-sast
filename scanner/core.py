import os
from pathlib import Path
import asyncio
from scanner.client import GPTClient
from scanner.detector import Detector
from scanner.enricher import Enricher
from scanner.file_scanner import FileScanner
from scanner.report import ReportGenerator
from rich.console import Console
import logging
import time

logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self, target_dir: str, output_dir: str, concurrency: int = 5):
        self.target_dir = Path(target_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()
        api_key = os.getenv("OPENAI_API_KEY")
        self.client = GPTClient(api_key, concurrency)
        self.detector = Detector(self.client)
        self.enricher = Enricher(self.client)
        self.file_scanner = FileScanner(self.detector, self.enricher)
        self.report_generator = ReportGenerator(self.output_dir)
        logger.debug(f"Scanner initialized: target={self.target_dir}, output={self.output_dir}, concurrency={concurrency}")

    async def run(self):
        t_total_start = time.monotonic()
        print("Starting scan...")
        t_scan_start = t_total_start
        tasks = []
        # support wide range of file types
        extensions = [
            '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.go', '.rb', '.php', '.pl', '.r', '.swift', '.kt', '.kts',
            '.scala', '.rs', '.dart', '.m', '.mm', '.lua', '.sql', '.sh', '.ps1',
            '.bat', '.xml', '.json', '.yaml', '.yml', '.ini', '.cfg', '.toml', '.env',
            'Dockerfile', 'Makefile', '.dockerfile', '.tf'
        ]
        for ext in extensions:
            for filepath in self.target_dir.rglob(f"*{ext}"):
                print(f"Scanning scheduled: {filepath}")
                tasks.append(self.file_scanner.scan(filepath))
        logger.debug(f"Scanner.run: created {len(tasks)} scan tasks")
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        t_scan_end = time.monotonic()
        results = []
        for res in scan_results:
            if isinstance(res, Exception):
                print(f"Error scanning file: {res}")
            elif res is None:
                continue
            else:
                results.append(res)
        for res in results:
            self.console.log(f"Found {len(res.vulnerabilities)} issues in {res.file_path}")
        t_report_start = time.monotonic()
        self.report_generator.save(results)
        t_report_end = time.monotonic()
        print(f"Reports saved to {self.output_dir}")
        total = time.monotonic() - t_total_start
        print(f"Time Summary: scanning {t_scan_end - t_scan_start:.2f}s, reporting {t_report_end - t_report_start:.2f}s, total {total:.2f}s")
