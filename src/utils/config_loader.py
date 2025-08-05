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
            
        Raises:
            ConfigurationError: If configuration is invalid or cannot be loaded
        """
        try:
            # Load environment variables
            if env_file:
                if not env_file.exists():
                    raise ConfigurationError(f"Environment file not found at {env_file}")
                load_dotenv(env_file)
            else:
                load_dotenv()  # Try to load from default locations
                
            # Load default config
            if not cls.DEFAULT_CONFIG_PATH.exists():
                raise ConfigurationError(f"Default config file not found at {cls.DEFAULT_CONFIG_PATH}")
                
            with open(cls.DEFAULT_CONFIG_PATH) as f:
                config = yaml.safe_load(f)
                
            # Merge with custom config if provided
            if config_path:
                if not config_path.exists():
                    raise ConfigurationError(f"Custom config file not found at {config_path}")
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
                
            # Ensure llm_provider is set
            if "llm_provider" not in config:
                config["llm_provider"] = "openai"
            else:
                config["llm_provider"] = str(config["llm_provider"]).lower()
            
            # Validate configuration
            cls._validate_config(config)
            
            return config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Error parsing YAML configuration: {str(e)}")
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {str(e)}")
            
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> None:
        """
        Deep merge two dictionaries, modifying the base dictionary.
        
        Args:
            base: Base dictionary to merge into
            update: Dictionary to merge from
            
        Raises:
            ConfigurationError: If merge fails
        """
        try:
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    ConfigLoader._deep_merge(base[key], value)
                else:
                    base[key] = value
        except Exception as e:
            raise ConfigurationError(f"Error merging configurations: {str(e)}")
                
    @staticmethod
    def _validate_config(config: Dict) -> None:
        """
        Validate the configuration.
        
        Args:
            config: Configuration dictionary to validate
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        provider = config.get("llm_provider", "openai").lower()
        
        if provider == "openai":
            if not config.get("openai"):
                raise ConfigurationError("OpenAI configuration section is missing")
            openai_config = config["openai"]
            if not openai_config.get("api_key"):
                raise ConfigurationError("OpenAI API key is not set")
            if not openai_config.get("model"):
                raise ConfigurationError("OpenAI model name is not set")
            if not isinstance(openai_config.get("timeout", 30), (int, float)):
                raise ConfigurationError("OpenAI timeout must be a number")
            if not isinstance(openai_config.get("max_concurrent_calls", 5), int):
                raise ConfigurationError("OpenAI max_concurrent_calls must be an integer")
                
        elif provider == "ollama":
            if not config.get("ollama"):
                raise ConfigurationError("Ollama configuration section is missing")
            ollama_config = config["ollama"]
            if not ollama_config.get("model"):
                raise ConfigurationError("Ollama model name is not set")
            if not isinstance(ollama_config.get("timeout", 30), (int, float)):
                raise ConfigurationError("Ollama timeout must be a number")
            if not isinstance(ollama_config.get("max_concurrent_calls", 5), int):
                raise ConfigurationError("Ollama max_concurrent_calls must be an integer")
        else:
            raise ConfigurationError(f"Unknown llm_provider '{provider}'. Supported values are 'openai' and 'ollama'")
            
        # Validate scanner settings
        if not config.get("scanner"):
            raise ConfigurationError("Scanner configuration section is missing")
            
        scanner_config = config["scanner"]
        if not isinstance(scanner_config.get("max_file_size", 1048576), int):
            raise ConfigurationError("Scanner max_file_size must be an integer")
            
        if not isinstance(scanner_config.get("excluded_patterns", []), list):
            raise ConfigurationError("Scanner excluded_patterns must be a list")
            
        # Validate logging level
        log_level = scanner_config.get("log_level", "INFO")
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR"}
        if log_level not in valid_levels:
            raise ConfigurationError(f"Invalid log level: {log_level}. Must be one of {valid_levels}") 
