import argparse
import asyncio
import os
import logging
from pathlib import Path
from src.models.config import ScannerConfig
from src.core.scanner import Scanner
from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logger

def main():
    """Main entry point for the SAST scanner."""
    parser = argparse.ArgumentParser(description="LLM-powered SAST Scanner")
    parser.add_argument("--target-dir", "-t", required=True, help="Directory to scan")
    parser.add_argument("--output-dir", "-o", default="reports", help="Directory to save reports")
    parser.add_argument("--config", "-c", help="Path to custom configuration file")
    parser.add_argument("--env-file", "-e", help="Path to environment file")
    parser.add_argument("--log-level", "-l", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                      help="Set the logging level")
    args = parser.parse_args()
    
    # Setup logging
    setup_logger("llm_sast", args.log_level)
    logger = logging.getLogger("llm_sast")
    
    try:
        # Load configuration
        config = ConfigLoader.load_config(
            config_path=Path(args.config) if args.config else None,
            env_file=Path(args.env_file) if args.env_file else None
        )
        
        # Create scanner configuration
        scanner_config = ScannerConfig(
            target_dir=Path(args.target_dir),
            output_dir=Path(args.output_dir),
            concurrency=config["openai"].get("max_concurrent_calls", 5),
            api_key=config["openai"]["api_key"],
            log_level=args.log_level,
            timeout=config["openai"].get("timeout", 30),
            max_file_size=config["scanner"].get("max_file_size", 1024 * 1024),
            excluded_patterns=config["scanner"].get("excluded_patterns", None)
        )
        
        # Create and run scanner with both configs
        scanner = Scanner(
            config=scanner_config,
            openai_config=config["openai"]
        )
        asyncio.run(scanner.run())
        
    except Exception as e:
        logger.error(f"Error running scanner: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
