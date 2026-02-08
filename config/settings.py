"""
Centralized configuration management for the system.
Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application settings loaded from environment variables."""
    
    def __init__(self):
        # Project paths
        self.BASE_DIR = Path(__file__).parent.parent
        self.LOG_DIR = self.BASE_DIR / os.getenv('LOG_DIR', 'logs')
        self.MODEL_DIR = self.BASE_DIR / os.getenv('MODEL_DIR', 'models')
        self.DATA_DIR = self.BASE_DIR / 'data'
        
        # Create directories if they don't exist
        self.LOG_DIR.mkdir(exist_ok=True)
        self.MODEL_DIR.mkdir(exist_ok=True)
        self.DATA_DIR.mkdir(exist_ok=True)
        
        # Database configuration
        self.DB_HOST = os.getenv('DB_HOST', 'localhost')
        self.DB_PORT = int(os.getenv('DB_PORT', '3306'))
        self.DB_NAME = os.getenv('DB_NAME', 'exposure_discovery')
        self.DB_USER = os.getenv('DB_USER', 'root')
        self.DB_PASSWORD = os.getenv('DB_PASSWORD', '')
        
        # API Keys
        self.SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
        self.CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
        self.CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
        self.GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
        self.HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')
        
        # System configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.DATA_RETENTION_DAYS = int(os.getenv('DATA_RETENTION_DAYS', '365'))
        
        # ML Model configuration
        self.EMBEDDING_MODEL = os.getenv('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
        self.BATCH_SIZE = int(os.getenv('BATCH_SIZE', '32'))
        
        # Risk scoring weights
        self.WEIGHT_SEVERITY = float(os.getenv('WEIGHT_SEVERITY', '0.30'))
        self.WEIGHT_BREACH = float(os.getenv('WEIGHT_BREACH', '0.25'))
        self.WEIGHT_GRAPH = float(os.getenv('WEIGHT_GRAPH', '0.20'))
        self.WEIGHT_ANOMALY = float(os.getenv('WEIGHT_ANOMALY', '0.15'))
        self.WEIGHT_CVE = float(os.getenv('WEIGHT_CVE', '0.10'))
        
    @property
    def database_url(self) -> str:
        """Get MySQL database connection URL."""
        return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    # Model and feature settings
    MODEL_DIR: Path = Path(__file__).parent.parent / 'models'
    EMBEDDING_MODEL: str = 'all-MiniLM-L6-v2'  # Sentence-BERT model
    
    def validate_api_keys(self) -> dict:
        """Validate that required API keys are present."""
        keys = {
            'shodan': bool(self.SHODAN_API_KEY),
            'censys': bool(self.CENSYS_API_ID and self.CENSYS_API_SECRET),
            'github': bool(self.GITHUB_TOKEN),
            'hibp': bool(self.HIBP_API_KEY)
        }
        return keys
    
    def get_missing_keys(self) -> list:
        """Get list of missing API keys."""
        validation = self.validate_api_keys()
        return [key for key, present in validation.items() if not present]


# Singleton instance
_settings: Optional[Settings] = None

def get_settings() -> Settings:
    """Get or create settings singleton instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
