"""
Secure configuration management for Censys Data Summarization Agent.
Handles API keys and settings with proper security practices.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class Config:
    """Secure configuration manager for API keys and settings."""
    
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = Path(config_file)
        self.config_data = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
                return self._get_default_config()
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "api_keys": {
                "openai": None,
                "gemini": None
            },
            "models": {
                "openai": ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo-preview"],
                "gemini": ["gemini-pro", "gemini-pro-vision"]
            },
            "default_provider": "openai",
            "default_model": "gpt-3.5-turbo",
            "default_temperature": 0.3
        }
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """
        Get API key for specified provider.
        
        Args:
            provider: API provider ("openai" or "gemini")
            
        Returns:
            API key if available, None otherwise
        """
        # First check environment variables (highest priority)
        env_key = f"{provider.upper()}_API_KEY"
        env_value = os.getenv(env_key)
        if env_value:
            return env_value
        
        # Then check config file
        return self.config_data.get("api_keys", {}).get(provider.lower())
    
    def set_api_key(self, provider: str, api_key: str, save: bool = True) -> bool:
        """
        Set API key for specified provider.
        
        Args:
            provider: API provider ("openai" or "gemini")
            api_key: API key value
            save: Whether to save to config file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if "api_keys" not in self.config_data:
                self.config_data["api_keys"] = {}
            
            self.config_data["api_keys"][provider.lower()] = api_key
            
            if save:
                self._save_config()
            
            return True
        except Exception as e:
            logger.error(f"Failed to set API key: {e}")
            return False
    
    def get_available_providers(self) -> list:
        """Get list of providers with available API keys."""
        providers = []
        
        for provider in ["openai", "gemini"]:
            if self.get_api_key(provider):
                providers.append(provider)
        
        return providers
    
    def get_models(self, provider: str) -> list:
        """Get available models for specified provider."""
        return self.config_data.get("models", {}).get(provider.lower(), [])
    
    def get_default_provider(self) -> str:
        """Get default provider."""
        return self.config_data.get("default_provider", "openai")
    
    def get_default_model(self) -> str:
        """Get default model."""
        return self.config_data.get("default_model", "gpt-3.5-turbo")
    
    def get_default_temperature(self) -> float:
        """Get default temperature."""
        return self.config_data.get("default_temperature", 0.3)
    
    def _save_config(self) -> bool:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            
            # Set restrictive permissions (owner read/write only)
            self.config_file.chmod(0o600)
            
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def create_config_template(self) -> bool:
        """Create a template configuration file."""
        template = {
            "api_keys": {
                "openai": "your-openai-api-key-here",
                "gemini": "your-google-api-key-here"
            },
            "models": {
                "openai": ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo-preview"],
                "gemini": ["gemini-pro", "gemini-pro-vision"]
            },
            "default_provider": "openai",
            "default_model": "gpt-3.5-turbo",
            "default_temperature": 0.3
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(template, f, indent=2)
            
            # Set restrictive permissions
            self.config_file.chmod(0o600)
            
            logger.info(f"Created config template at {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to create config template: {e}")
            return False


def get_config() -> Config:
    """Get global configuration instance."""
    return Config()


def setup_secure_config() -> bool:
    """
    Set up secure configuration system.
    Creates config template if it doesn't exist.
    
    Returns:
        True if setup successful, False otherwise
    """
    config = get_config()
    
    if not config.config_file.exists():
        logger.info("Creating secure configuration template...")
        return config.create_config_template()
    
    return True


def validate_api_keys() -> Dict[str, bool]:
    """
    Validate API keys for all providers.
    
    Returns:
        Dictionary mapping provider names to validation status
    """
    config = get_config()
    results = {}
    
    for provider in ["openai", "gemini"]:
        api_key = config.get_api_key(provider)
        results[provider] = api_key is not None and len(api_key) > 10
    
    return results


# Global configuration instance
_config_instance = None

def get_global_config() -> Config:
    """Get or create global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
