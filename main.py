import argparse
import asyncio
import os
import logging
from dotenv import load_dotenv
from scanner.core import Scanner

logging.basicConfig(level=logging.WARNING)

def main():
    parser = argparse.ArgumentParser(description="Cascade SAST Scanner")
    parser.add_argument("--target-dir", "-t", required=True, help="Directory to scan")
    parser.add_argument("--output-dir", "-o", default="reports", help="Directory to save reports")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Concurrency limit for API calls")
    args = parser.parse_args()
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "key.env"))
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY not set in key.env")
        exit(1)
    scanner = Scanner(target_dir=args.target_dir, output_dir=args.output_dir, concurrency=args.concurrency)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
