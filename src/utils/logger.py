import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log messages."""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        # Add color to the level name
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

def setup_logger(
    name: str,
    level: str = "INFO",
    log_format: Optional[str] = None,
    log_file: Optional[Path] = None
) -> logging.Logger:
    """
    Set up a logger with the specified name and level.
    
    Args:
        name: The name of the logger
        level: The logging level (DEBUG, INFO, WARNING, ERROR)
        log_format: Optional custom log format
        log_file: Optional path to log file
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Get the root logger
    root_logger = logging.getLogger()
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set up console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    if log_format is None:
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
    # Use colored formatter for console
    console_formatter = ColoredFormatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Set up file handler if specified
    if log_file:
        try:
            # Ensure log directory exists
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add timestamp to log filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = log_file.with_name(f"{log_file.stem}_{timestamp}{log_file.suffix}")
            
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(log_format)
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            
            root_logger.info(f"Logging to file: {log_file}")
        except Exception as e:
            root_logger.error(f"Failed to set up file logging: {str(e)}")
    
    # Set level for root logger
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)
    
    # Get the specific logger
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)
    
    # Ensure log messages propagate to root logger
    logger.propagate = True
    
    return logger 