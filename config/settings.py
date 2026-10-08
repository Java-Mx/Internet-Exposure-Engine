
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


load_dotenv()

class Settings:

    def __init__(self):

        self.BASE_DIR = Path(__file__).parent.parent
        self.LOG_DIR = self.BASE_DIR / os.getenv('LOG_DIR', 'logs')
        self.MODEL_DIR = self.BASE_DIR / os.getenv('MODEL_DIR', 'models')
        self.DATA_DIR = self.BASE_DIR / 'data'


        self.LOG_DIR.mkdir(exist_ok=True)
        self.MODEL_DIR.mkdir(exist_ok=True)
        self.DATA_DIR.mkdir(exist_ok=True)


        # ── SQLite Database ────────────────────────────────────────────────────────
        # Primary storage: records/data/aeris.db (managed by records.db_manager)
        # SQLite requires no host, port, user, or password configuration.


        self.SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
        self.CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
        self.CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
        self.GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
        self.HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')
        self.NVD_API_KEY = os.getenv('NVD_API_KEY', '')

        # ── AERIS Security / Secret Keys ──────────────────────────────────────
        self.GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.AERIS_SIGNING_KEY = os.getenv('AERIS_SIGNING_KEY', '')
        self.IS_PRODUCTION = os.getenv('AERIS_ENV', 'development').lower() == 'production'


        self.NVD_DB_PATH = self.DATA_DIR / os.getenv('NVD_DB_PATH', 'nvd_cve_cache.db')
        self.NVD_SYNC_INTERVAL_DAYS = int(os.getenv('NVD_SYNC_INTERVAL_DAYS', '7'))


        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.DATA_RETENTION_DAYS = int(os.getenv('DATA_RETENTION_DAYS', '365'))


        self.EMBEDDING_MODEL = os.getenv('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
        self.BATCH_SIZE = int(os.getenv('BATCH_SIZE', '32'))


        self.WEIGHT_SEVERITY = float(os.getenv('WEIGHT_SEVERITY', '0.30'))
        self.WEIGHT_BREACH = float(os.getenv('WEIGHT_BREACH', '0.25'))
        self.WEIGHT_GRAPH = float(os.getenv('WEIGHT_GRAPH', '0.20'))
        self.WEIGHT_ANOMALY = float(os.getenv('WEIGHT_ANOMALY', '0.15'))
        self.WEIGHT_CVE = float(os.getenv('WEIGHT_CVE', '0.10'))

    @property
    def database_url(self) -> str:
        return "sqlite:///data/exposure_discovery.db"

    def validate_api_keys(self) -> dict:
        keys = {
            'shodan': bool(self.SHODAN_API_KEY),
            'censys': bool(self.CENSYS_API_ID and self.CENSYS_API_SECRET),
            'github': bool(self.GITHUB_TOKEN),
            'hibp': bool(self.HIBP_API_KEY),
            'nvd': bool(self.NVD_API_KEY)
        }
        return keys

    def validate_secrets(self) -> dict:
        """Return a dict of {secret_name: bool} indicating whether each secret is configured."""
        return {
            'GOOGLE_SAFE_BROWSING_API_KEY': bool(self.GOOGLE_SAFE_BROWSING_API_KEY),
            'VIRUSTOTAL_API_KEY': bool(self.VIRUSTOTAL_API_KEY),
            'AERIS_SIGNING_KEY': bool(self.AERIS_SIGNING_KEY),
        }

    def get_missing_keys(self) -> list:
        validation = self.validate_api_keys()
        return [key for key, present in validation.items() if not present]


_settings: Optional[Settings] = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings