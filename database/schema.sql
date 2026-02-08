-- Internet Exposure Discovery System - MySQL Database Schema
-- This schema stores all discovered assets, features, and risk assessments

-- Create database
CREATE DATABASE IF NOT EXISTS exposure_discovery
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE exposure_discovery;

-- Assets table: Core entity storing discovered internet-facing assets
CREATE TABLE IF NOT EXISTS assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id VARCHAR(36) UNIQUE NOT NULL,  -- UUID
    ip VARCHAR(45),  -- IPv4 or IPv6
    domain VARCHAR(255),
    port INT,
    service VARCHAR(100),
    banner TEXT,
    asn INT,
    country VARCHAR(3),  -- ISO 3166-1 alpha-3
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    source VARCHAR(50) NOT NULL,  -- shodan, censys, github, etc.
    metadata JSON,  -- Source-specific additional data
    
    INDEX idx_ip (ip),
    INDEX idx_domain (domain),
    INDEX idx_asn (asn),
    INDEX idx_discovered_at (discovered_at),
    INDEX idx_source (source)
) ENGINE=InnoDB;

-- CVE data: Vulnerability information from NVD
CREATE TABLE IF NOT EXISTS cve_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,  -- e.g., CVE-2023-12345
    description TEXT,
    cvss_score DECIMAL(3, 1),
    severity VARCHAR(20),  -- LOW, MEDIUM, HIGH, CRITICAL
    published_date DATE,
    last_modified DATE,
    cpe_matches JSON,  -- Common Platform Enumeration matches
    references JSON,  -- External references
    
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (severity),
    INDEX idx_cvss_score (cvss_score)
) ENGINE=InnoDB;

-- Breach data: Information from HaveIBeenPwned
CREATE TABLE IF NOT EXISTS breach_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    breach_name VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255),
    domain VARCHAR(255),
    breach_date DATE,
    added_date DATE,
    modified_date DATE,
    pwn_count BIGINT,  -- Number of accounts affected
    description TEXT,
    data_classes JSON,  -- Types of data compromised
    is_verified BOOLEAN,
    is_sensitive BOOLEAN,
    
    INDEX idx_domain (domain),
    INDEX idx_breach_date (breach_date)
) ENGINE=InnoDB;

-- GitHub exposure data: Potential credential/secret leaks
CREATE TABLE IF NOT EXISTS github_exposures (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    repo_full_name VARCHAR(255),
    commit_sha VARCHAR(40),
    file_path VARCHAR(500),
    exposure_type VARCHAR(50),  -- api_key, password, token, etc.
    confidence DECIMAL(3, 2),  -- 0.00 to 1.00
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSON,
    
    INDEX idx_repo (repo_full_name),
    INDEX idx_exposure_type (exposure_type),
    INDEX idx_discovered_at (discovered_at)
) ENGINE=InnoDB;

-- Features table: Engineered features for ML models
CREATE TABLE IF NOT EXISTS asset_features (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id VARCHAR(36) NOT NULL,
    feature_vector JSON NOT NULL,  -- Serialized feature vector
    numeric_features JSON,
    categorical_features JSON,
    text_embedding BLOB,  -- Binary embedding data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_asset_id (asset_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- Risk assessments: Final risk scores and explanations
CREATE TABLE IF NOT EXISTS risk_assessments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id VARCHAR(36) NOT NULL,
    risk_score DECIMAL(5, 2) NOT NULL,  -- 0.00 to 100.00
    risk_level VARCHAR(20) NOT NULL,  -- Low, High, Critical
    confidence DECIMAL(3, 2),  -- 0.00 to 1.00
    
    -- Component scores
    severity_score DECIMAL(3, 2),
    breach_score DECIMAL(3, 2),
    graph_score DECIMAL(3, 2),
    anomaly_score DECIMAL(3, 2),
    cve_score DECIMAL(3, 2),
    
    -- Explanations
    explanation JSON,
    evidence JSON,
    
    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_asset_id (asset_id),
    INDEX idx_risk_level (risk_level),
    INDEX idx_risk_score (risk_score),
    INDEX idx_assessed_at (assessed_at)
) ENGINE=InnoDB;

-- ML model predictions: Store individual model outputs
CREATE TABLE IF NOT EXISTS ml_predictions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id VARCHAR(36) NOT NULL,
    model_name VARCHAR(100) NOT NULL,  -- logistic_regression, random_forest, etc.
    model_version VARCHAR(20),
    prediction VARCHAR(50),  -- Low, Medium, High for supervised
    confidence DECIMAL(3, 2),
    prediction_data JSON,  -- Additional model-specific data
    predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_asset_id (asset_id),
    INDEX idx_model_name (model_name),
    INDEX idx_predicted_at (predicted_at)
) ENGINE=InnoDB;

-- Graph relationships: Asset connections for graph analysis
CREATE TABLE IF NOT EXISTS graph_edges (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    source_asset_id VARCHAR(36) NOT NULL,
    target_asset_id VARCHAR(36) NOT NULL,
    edge_type VARCHAR(50) NOT NULL,  -- SHARED_ASN, SHARED_CERT, etc.
    weight DECIMAL(3, 2) DEFAULT 1.00,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (source_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (target_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_source (source_asset_id),
    INDEX idx_target (target_asset_id),
    INDEX idx_edge_type (edge_type),
    UNIQUE KEY unique_edge (source_asset_id, target_asset_id, edge_type)
) ENGINE=InnoDB;

-- System metadata: Track ingestion runs and system state
CREATE TABLE IF NOT EXISTS system_metadata (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Insert initial system metadata
INSERT INTO system_metadata (key_name, value) VALUES
    ('schema_version', '1.0'),
    ('last_shodan_sync', NULL),
    ('last_censys_sync', NULL),
    ('last_github_sync', NULL),
    ('last_hibp_sync', NULL),
    ('last_nvd_sync', NULL)
ON DUPLICATE KEY UPDATE key_name=key_name;
