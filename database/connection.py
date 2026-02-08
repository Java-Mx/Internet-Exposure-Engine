"""
Database connection management using SQLAlchemy.
Provides connection pooling and session management.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
from typing import Generator

from config.settings import get_settings
from config.logging_config import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Global engine instance
_engine = None
_SessionLocal = None


def get_engine():
    """Get or create SQLAlchemy engine with connection pooling."""
    global _engine
    
    if _engine is None:
        logger.info(f"Creating database engine for {settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")
        
        _engine = create_engine(
            settings.database_url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,  # Verify connections before using
            pool_recycle=3600,   # Recycle connections after 1 hour
            echo=False,          # Set to True for SQL query logging
        )
        
        # Add connection event listeners
        @event.listens_for(_engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            logger.debug("Database connection established")
        
        @event.listens_for(_engine, "close")
        def receive_close(dbapi_conn, connection_record):
            logger.debug("Database connection closed")
    
    return _engine


def get_session_factory():
    """Get or create session factory."""
    global _SessionLocal
    
    if _SessionLocal is None:
        engine = get_engine()
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )
    
    return _SessionLocal


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.
    Automatically handles commit/rollback and cleanup.
    
    Usage:
        with get_session() as session:
            session.query(Asset).all()
    """
    SessionLocal = get_session_factory()
    session = SessionLocal()
    
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {e}")
        raise
    finally:
        session.close()


def init_database():
    """
    Initialize database by creating all tables.
    This should be called once during setup.
    """
    from .models import Base
    
    engine = get_engine()
    logger.info("Creating database tables...")
    
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def test_connection() -> bool:
    """
    Test database connection.
    
    Returns:
        True if connection successful, False otherwise
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        logger.info("Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False
