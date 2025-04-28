import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from dotenv import load_dotenv
from ..utils.exceptions import ConfigurationError

class ConfigLoader:
    """Configuration loader that handles YAML config files and environment variables."""
    
    DEFAULT_CONFIG_PATH = Path("config/default_config.yaml")
    
    @classmethod
    def load_config(cls, config_path: Optional[Path] = None, env_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Load configuration from YAML file and environment variables.
        
        Args:
            config_path: Path to custom config file (will be merged with default config)
            env_file: Path to .env file for environment variables
            
        Returns:
            Dict containing the merged configuration
        """
        # Load environment variables
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()  # Try to load from default locations
            
        # Load default config
        if not cls.DEFAULT_CONFIG_PATH.exists():
            raise ConfigurationError(f"Default config file not found at {cls.DEFAULT_CONFIG_PATH}")
            
        with open(cls.DEFAULT_CONFIG_PATH) as f:
            config = yaml.safe_load(f)
            
        # Merge with custom config if provided
        if config_path and config_path.exists():
            with open(config_path) as f:
                custom_config = yaml.safe_load(f)
                cls._deep_merge(config, custom_config)
                
        # Override with environment variables
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            config["openai"]["api_key"] = api_key
            
        api_base = os.getenv("OPENAI_API_BASE")
        if api_base:
            config["openai"]["api_base_url"] = api_base
            
        model = os.getenv("OPENAI_MODEL")
        if model:
            config["openai"]["model"] = model
            
        # Validate configuration
        if config.get("openai"):
            cls._validate_config(config)
        
        return config
        
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> None:
        """
        Deep merge two dictionaries, modifying the base dictionary.
        
        Args:
            base: Base dictionary to merge into
            update: Dictionary to merge from
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                ConfigLoader._deep_merge(base[key], value)
            else:
                base[key] = value
                
    @staticmethod
    def _validate_config(config: Dict) -> None:
        """
        Validate the configuration.
        
        Args:
            config: Configuration dictionary to validate
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if config.get("openai"):
            # Check required OpenAI settings
            openai_config = config["openai"]
            if not openai_config.get("api_key"):
                raise ConfigurationError("OpenAI API key is not set")
                
            # Validate model name
            if not openai_config.get("model"):
                raise ConfigurationError("OpenAI model name is not set")
                
            # Validate numeric values
            if not isinstance(openai_config.get("timeout", 30), (int, float)):
                raise ConfigurationError("OpenAI timeout must be a number")
                
            if not isinstance(openai_config.get("max_concurrent_calls", 5), int):
                raise ConfigurationError("OpenAI max_concurrent_calls must be an integer")
