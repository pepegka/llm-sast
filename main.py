import argparse
import asyncio
import logging
import time
import sys
from pathlib import Path
from src.models.config import ScannerConfig
from src.core.scanner import Scanner
from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logger
from src.utils.exceptions import ConfigurationError, ScannerError

def main():
    """Main entry point for the SAST scanner."""
    parser = argparse.ArgumentParser(description="Static Application Security Testing using LLM")
    parser.add_argument("-t", "--target-dir", required=True, help="Target directory to scan")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory for reports")
    parser.add_argument("-c", "--config", help="Path to custom config file")
    parser.add_argument("-e", "--env-file", help="Path to .env file")
    parser.add_argument("-l", "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                      help="Logging level")
    parser.add_argument("--log-file", help="Path to log file")
    args = parser.parse_args()
    
    try:
        # Setup logging
        log_file = Path(args.log_file) if args.log_file else None
        logger = setup_logger("llm_sast", args.log_level, log_file=log_file)
        
        # Validate target directory
        target_dir = Path(args.target_dir)
        if not target_dir.exists() or not target_dir.is_dir():
            raise ScannerError(f"Target directory does not exist or is not a directory: {target_dir}")
            
        # Load configuration
        logger.info("Loading configuration...")
        config = ConfigLoader.load_config(
            config_path=Path(args.config) if args.config else None,
            env_file=Path(args.env_file) if args.env_file else None
        )
        
        provider = config.get("llm_provider", "openai").lower()
        llm_conf = config[provider]
        
        # Create scanner configuration
        logger.info("Initializing scanner...")
        scanner_config = ScannerConfig(
            target_dir=target_dir,
            output_dir=Path(args.output_dir),
            concurrency=llm_conf.get("max_concurrent_calls", 5),
            api_key=llm_conf.get("api_key", ""),
            llm_provider=provider,
            log_level=args.log_level,
            timeout=llm_conf.get("timeout", 30),
            max_file_size=config["scanner"].get("max_file_size", 1024 * 1024),
            excluded_patterns=config["scanner"].get("excluded_patterns", None)
        )
        
        # Create and run scanner
        logger.info("Starting scan process...")
        scanner = Scanner(
            config=scanner_config,
            llm_config=llm_conf,
            provider=provider
        )
        
        # Run the scan
        start_time = time.time()
        vulnerabilities = asyncio.run(scanner.scan())
        total_time = time.time() - start_time
        
        # Log final summary
        logger.info("\nScan Complete!")
        logger.info(f"Total execution time: {total_time:.2f} seconds")
        logger.info(f"Total vulnerabilities found: {len(vulnerabilities)}")
        logger.info(f"Reports generated in: {args.output_dir}")
        
    except Exception as e:
        logger.error(f"Error running scanner: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
