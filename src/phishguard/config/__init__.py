import json
import os
from pathlib import Path
from typing import Dict, Any

def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration from JSON file.
    config_path: Path to config file. If None, uses default config.json
        
    Returns: Dictionary containing configuration data
    
    Raises: FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file contains invalid JSON
    """
    if config_path is None:
        # Get the project root directory (where config/ folder is)
        current_dir = Path(__file__).parent.parent.parent.parent
        config_path = current_dir / "config" / "config.json"
    
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Load default configuration once when module is imported
try:
    DEFAULT_CONFIG = load_config()
except (FileNotFoundError, json.JSONDecodeError):
    # Fallback if config file is not found
    DEFAULT_CONFIG = {}
