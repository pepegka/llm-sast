import argparse
import asyncio
import os
import logging
from pathlib import Path
from src.models.config import ScannerConfig
from src.core.scanner import Scanner
from src.utils.config_loader import ConfigLoader
from src.services.llm_service import OllamaService
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
    parser.add_argument("--model", "-m", default="hengwen/DeepSeek-R1-Distill-Qwen-32B:q4_k_m", 
                        help="Name of the model to use (default: DeepSeek-R1-Distill-Qwen-32B:q4_k_m)")
    parser.add_argument("--service", "-s", default="openai", choices=["openai", "ollama"],
                        help="Service to use for scanning (default: openai)")
    args = parser.parse_args()
    service_type = args.service
    model_name = args.model
    
    # Setup logging
    setup_logger("llm_sast", args.log_level)
    logger = logging.getLogger("llm_sast")
    
    try:
        # Load configuration
        config = ConfigLoader.load_config(
            config_path=Path(args.config) if args.config else None,
            env_file=Path(args.env_file) if args.env_file else None
        )
        
        if service_type == "openai":
            # Create scanner configuration for OpenAI
            api_key = config["openai"]["api_key"]

            scanner_config = ScannerConfig(
                target_dir=Path(args.target_dir),
                output_dir=Path(args.output_dir),
                concurrency=config["openai"].get("max_concurrent_calls", 5),
                api_key=api_key,
                log_level=args.log_level,
                timeout=config["openai"].get("timeout", 30),
                max_file_size=config["scanner"].get("max_file_size", 1024 * 1024),
                excluded_patterns=config["scanner"].get("excluded_patterns", None)
            )
            
            # Create and run scanner with OpenAI service
            scanner = Scanner(
                config=scanner_config,
                openai_config=config["openai"]
            )
        elif service_type == "ollama":
            # Create scanner configuration for Ollama
            if "ollama" not in config:
                logger.error("Configuration for 'ollama' service is missing. Please ensure the configuration file includes the necessary settings for the 'ollama' service.")
                exit(1)
            
            scanner_config = ScannerConfig(
                target_dir=Path(args.target_dir),
                output_dir=Path(args.output_dir),
                concurrency=config["ollama"].get("max_concurrent_calls", 5),
                api_key=None,  # No API key required for Ollama
                log_level=args.log_level,
                timeout=config["ollama"].get("timeout", 30),
                max_file_size=config["scanner"].get("max_file_size", 1024 * 1024),
                excluded_patterns=config["scanner"].get("excluded_patterns", None)
            )
            
            # Create and run scanner with Ollama service
            ollama_service = OllamaService(
                config=config["ollama"],
                model_name=model_name
            )
            scanner = Scanner(
                config=scanner_config,
                openai_config=config["ollama"]
            )
        asyncio.run(scanner.run())
        
    except Exception as e:
        logger.error(f"Error running scanner: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
