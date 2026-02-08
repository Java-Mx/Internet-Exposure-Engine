"""
SQLAlchemy ORM models for the database schema.
These models map to the tables defined in schema.sql.
"""

from sqlalchemy import (
    Column, Integer, BigInteger, String, Text, DateTime, Date,
    Boolean, DECIMAL, JSON, ForeignKey, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()


class Asset(Base):
    """Core entity representing a discovered internet-facing asset."""
    __tablename__ = 'assets'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    ip = Column(String(45))
    domain = Column(String(255))
    port = Column(Integer)
    service = Column(String(100))
    banner = Column(Text)
    asn = Column(Integer)
    country = Column(String(3))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source = Column(String(50), nullable=False)
    meta_data = Column(JSON)
    
    __table_args__ = (
        Index('idx_ip', 'ip'),
        Index('idx_domain', 'domain'),
        Index('idx_asn', 'asn'),
        Index('idx_discovered_at', 'discovered_at'),
        Index('idx_source', 'source'),
    )
    
    def __repr__(self):
        return f"<Asset(asset_id='{self.asset_id}', ip='{self.ip}', domain='{self.domain}', port={self.port})>"


class CVEData(Base):
    """Vulnerability information from NVD."""
    __tablename__ = 'cve_data'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), unique=True, nullable=False)
    description = Column(Text)
    cvss_score = Column(DECIMAL(3, 1))
    severity = Column(String(20))
    published_date = Column(Date)
    last_modified = Column(Date)
    cpe_matches = Column(JSON)
    references = Column(JSON)
    
    __table_args__ = (
        Index('idx_cve_id', 'cve_id'),
        Index('idx_severity', 'severity'),
        Index('idx_cvss_score', 'cvss_score'),
    )
    
    def __repr__(self):
        return f"<CVEData(cve_id='{self.cve_id}', severity='{self.severity}', cvss={self.cvss_score})>"


class BreachData(Base):
    """Breach information from HaveIBeenPwned."""
    __tablename__ = 'breach_data'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    breach_name = Column(String(100), unique=True, nullable=False)
    title = Column(String(255))
    domain = Column(String(255))
    breach_date = Column(Date)
    added_date = Column(Date)
    modified_date = Column(Date)
    pwn_count = Column(BigInteger)
    description = Column(Text)
    data_classes = Column(JSON)
    is_verified = Column(Boolean)
    is_sensitive = Column(Boolean)
    
    __table_args__ = (
        Index('idx_domain', 'domain'),
        Index('idx_breach_date', 'breach_date'),
    )
    
    def __repr__(self):
        return f"<BreachData(breach_name='{self.breach_name}', domain='{self.domain}', pwn_count={self.pwn_count})>"


class GitHubExposure(Base):
    """Potential credential/secret leaks from GitHub."""
    __tablename__ = 'github_exposures'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    repo_full_name = Column(String(255))
    commit_sha = Column(String(40))
    file_path = Column(String(500))
    exposure_type = Column(String(50))
    confidence = Column(DECIMAL(3, 2))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    meta_data = Column(JSON)
    
    __table_args__ = (
        Index('idx_repo', 'repo_full_name'),
        Index('idx_exposure_type', 'exposure_type'),
        Index('idx_discovered_at', 'discovered_at'),
    )
    
    def __repr__(self):
        return f"<GitHubExposure(repo='{self.repo_full_name}', type='{self.exposure_type}')>"


class AssetFeature(Base):
    """Engineered features for ML models."""
    __tablename__ = 'asset_features'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(36), ForeignKey('assets.asset_id', ondelete='CASCADE'), nullable=False)
    feature_vector = Column(JSON, nullable=False)
    numeric_features = Column(JSON)
    categorical_features = Column(JSON)
    text_embedding = Column(Text)  # Base64 encoded binary data
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_asset_id', 'asset_id'),
        Index('idx_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AssetFeature(asset_id='{self.asset_id}')>"


class RiskAssessment(Base):
    """Final risk scores and explanations."""
    __tablename__ = 'risk_assessments'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(36), ForeignKey('assets.asset_id', ondelete='CASCADE'), nullable=False)
    risk_score = Column(DECIMAL(5, 2), nullable=False)
    risk_level = Column(String(20), nullable=False)
    confidence = Column(DECIMAL(3, 2))
    
    # Component scores
    severity_score = Column(DECIMAL(3, 2))
    breach_score = Column(DECIMAL(3, 2))
    graph_score = Column(DECIMAL(3, 2))
    anomaly_score = Column(DECIMAL(3, 2))
    cve_score = Column(DECIMAL(3, 2))
    
    # Explanations
    explanation = Column(JSON)
    evidence = Column(JSON)
    
    assessed_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_asset_id', 'asset_id'),
        Index('idx_risk_level', 'risk_level'),
        Index('idx_risk_score', 'risk_score'),
        Index('idx_assessed_at', 'assessed_at'),
    )
    
    def __repr__(self):
        return f"<RiskAssessment(asset_id='{self.asset_id}', risk_level='{self.risk_level}', score={self.risk_score})>"


class MLPrediction(Base):
    """Store individual ML model predictions."""
    __tablename__ = 'ml_predictions'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(36), ForeignKey('assets.asset_id', ondelete='CASCADE'), nullable=False)
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(20))
    prediction = Column(String(50))
    confidence = Column(DECIMAL(3, 2))
    prediction_data = Column(JSON)
    predicted_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_asset_id', 'asset_id'),
        Index('idx_model_name', 'model_name'),
        Index('idx_predicted_at', 'predicted_at'),
    )
    
    def __repr__(self):
        return f"<MLPrediction(asset_id='{self.asset_id}', model='{self.model_name}', prediction='{self.prediction}')>"


class GraphEdge(Base):
    """Asset connections for graph analysis."""
    __tablename__ = 'graph_edges'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    source_asset_id = Column(String(36), ForeignKey('assets.asset_id', ondelete='CASCADE'), nullable=False)
    target_asset_id = Column(String(36), ForeignKey('assets.asset_id', ondelete='CASCADE'), nullable=False)
    edge_type = Column(String(50), nullable=False)
    weight = Column(DECIMAL(3, 2), default=1.00)
    meta_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_source', 'source_asset_id'),
        Index('idx_target', 'target_asset_id'),
        Index('idx_edge_type', 'edge_type'),
    )
    
    def __repr__(self):
        return f"<GraphEdge(source='{self.source_asset_id}', target='{self.target_asset_id}', type='{self.edge_type}')>"


class SystemMetadata(Base):
    """Track ingestion runs and system state."""
    __tablename__ = 'system_metadata'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    key_name = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SystemMetadata(key='{self.key_name}', value='{self.value}')>"
