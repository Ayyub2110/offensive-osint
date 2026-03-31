"""
Configuration management for the OSINT application.

This module handles loading and managing configuration from environment
variables, configuration files, and default settings.

Configuration includes:
    - API keys and credentials
    - Agent parameters and timeouts
    - LLM model settings
    - Tool-specific configurations
"""

import os
from typing import Dict, Any
from dotenv import load_dotenv


def load_config() -> Dict[str, Any]:
    """
    Load configuration from environment and configuration files.
    
    Loads configuration in the following priority:
        1. Environment variables
        2. .env file
        3. Default values
    
    Returns:
        Configuration dictionary
    """
    # Load environment variables from .env file
    load_dotenv()
    
    config = {
        # LLM Configuration
        "llm": {
            "provider": os.getenv("LLM_PROVIDER", "openai"),
            "model": os.getenv("LLM_MODEL", "gpt-4"),
            "api_key": os.getenv("OPENAI_API_KEY", ""),
            "temperature": float(os.getenv("LLM_TEMPERATURE", "0.7")),
        },
        
        # Agent Configuration
        "agents": {
            "recon": {
                "timeout": int(os.getenv("RECON_TIMEOUT", "300")),
                "max_subdomains": int(os.getenv("MAX_SUBDOMAINS", "100")),
            },
            "vulnerability": {
                "timeout": int(os.getenv("VULN_TIMEOUT", "600")),
                "max_ports": int(os.getenv("MAX_PORTS", "1000")),
            },
            "intelligence": {
                "timeout": int(os.getenv("INTEL_TIMEOUT", "300")),
            }
        },
        
        # Workflow Configuration
        "workflow": {
            "max_iterations": int(os.getenv("MAX_ITERATIONS", "10")),
            "enable_checkpointing": os.getenv("ENABLE_CHECKPOINTING", "true").lower() == "true",
        }
    }
    
    return config


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration values.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        True if configuration is valid, raises ValueError otherwise
    """
    # TODO: Implement configuration validation
    if not config.get("llm", {}).get("api_key"):
        raise ValueError("LLM API key is required")
    
    return True
