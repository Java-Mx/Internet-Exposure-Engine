"""
Main entry point for the Internet Exposure Discovery and Risk Scoring System.
Orchestrates the entire pipeline from data ingestion to risk reporting.
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import get_settings
from config.logging_config import setup_logging, get_logger
from database.connection import test_connection, init_database


def check_prerequisites():
    """Check that all prerequisites are met before running the system."""
    settings = get_settings()
    logger = get_logger(__name__)
    
    logger.info("Checking system prerequisites...")
    
    # Check API keys
    missing_keys = settings.get_missing_keys()
    if missing_keys:
        logger.warning(f"Missing API keys: {', '.join(missing_keys)}")
        logger.warning("Some data sources will not be available.")
    else:
        logger.info("All API keys are configured.")
    
    # Test database connection
    logger.info("Testing database connection...")
    if not test_connection():
        logger.error("Database connection failed. Please check your configuration.")
        return False
    
    logger.info("All prerequisites met.")
    return True


def initialize_system():
    """Initialize the system on first run."""
    logger = get_logger(__name__)
    
    logger.info("Initializing Internet Exposure Discovery System...")
    
    # Initialize database tables
    try:
        init_database()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False
    
    logger.info("System initialization complete.")
    return True


def main():
    """Main execution function."""
    # Setup logging
    settings = get_settings()
    setup_logging(settings.LOG_DIR, settings.LOG_LEVEL)
    logger = get_logger(__name__)
    
    logger.info("=" * 80)
    logger.info("Internet Exposure Discovery and Risk Scoring System")
    logger.info("=" * 80)
    
    # Check prerequisites
    if not check_prerequisites():
        logger.error("Prerequisites check failed. Exiting.")
        sys.exit(1)
    
    # Initialize system (creates tables if they don't exist)
    if not initialize_system():
        logger.error("System initialization failed. Exiting.")
        sys.exit(1)
    
    logger.info("System is ready.")
    logger.info("Next steps:")
    logger.info("  1. Configure API keys in .env file")
    logger.info("  2. Run data ingestion: python -m data_ingestion.run_ingestion")
    logger.info("  3. Train ML models: python -m ml_models.train")
    logger.info("  4. Generate risk reports: python -m reporting.generate_reports")
    
    # TODO: Implement pipeline orchestration
    # This will be expanded in later phases to run:
    # - Data ingestion
    # - Feature engineering
    # - ML model training/inference
    # - Graph analysis
    # - Risk scoring
    # - Report generation


if __name__ == "__main__":
    main()
