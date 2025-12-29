import yaml
import sys
from pathlib import Path


class ConfigManager:
    _instance = None
    _config = None
    _base_dir = None
    _config_loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._base_dir = Path(__file__).resolve().parent.parent
            cls._instance._config = {}
            cls._instance._config_loaded = False
        return cls._instance

    def load_config(self):
        if self._config_loaded:
            return True
            
        config_path = self._base_dir / "config.yaml"
        example_path = self._base_dir / "config.example.yaml"
        
        if not config_path.exists():
            print(f"WARNING: Config file not found at {config_path}", file=sys.stderr)
            print(f"Please copy config.example.yaml to config.yaml:", file=sys.stderr)
            print(f"  cp {example_path} {config_path}", file=sys.stderr)
            
            # Try to load example as fallback for basic functionality
            if example_path.exists():
                print(f"Using {example_path} as fallback (NOT recommended for production)", file=sys.stderr)
                config_path = example_path
            else:
                self._config = {}
                return False
        
        try:
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
            self._config_loaded = True
            return True
        except Exception as e:
            print(f"ERROR: Failed to load config: {e}", file=sys.stderr)
            self._config = {}
            return False

    def ensure_loaded(self):
        """Ensure config is loaded, return True if successful."""
        if not self._config_loaded:
            return self.load_config()
        return True

    def get_path(self, path_str):
        """Resolves a path relative to the base directory, or returns absolute path."""
        if not path_str:
            return None
            
        path = Path(path_str)
        if path.is_absolute():
            return path
        
        if str(path).startswith('~'):
            return path.expanduser()
            
        return (self._base_dir / path).resolve()

    def get(self, key_path, default=None):
        """Get config value using dot notation (e.g. 'general.log_file')"""
        self.ensure_loaded()
        
        keys = key_path.split('.')
        value = self._config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
                
        return value
    
    @property
    def base_dir(self):
        return self._base_dir


# Global instance - does NOT load config at import time anymore
config_manager = ConfigManager()
