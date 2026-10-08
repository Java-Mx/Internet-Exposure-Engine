"""
Asset Registry
==============
Persistent store for all discovered and annotated assets.
Backed by the existing SQLite database in records/data/ierss.db.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .asset_model import Asset, AssetCriticality, ComplianceScope
from .criticality_scorer import CriticalityScorer
from .org_mapper import OrgMapper
from .compliance_tagger import ComplianceTagger

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent.parent / "records" / "data" / "ierss.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL UNIQUE,
    asset_type      TEXT NOT NULL DEFAULT 'subdomain',
    source          TEXT,
    organisation    TEXT,
    business_unit   TEXT,
    owner_team      TEXT,
    owner_contact   TEXT,
    criticality     TEXT NOT NULL DEFAULT 'UNKNOWN',
    is_customer_facing  INTEGER NOT NULL DEFAULT 0,
    is_internet_exposed INTEGER NOT NULL DEFAULT 1,
    is_revenue_generating INTEGER NOT NULL DEFAULT 0,
    serves_pii      INTEGER NOT NULL DEFAULT 0,
    compliance_scopes TEXT NOT NULL DEFAULT '[]',
    last_risk_score REAL,
    last_risk_level TEXT,
    last_scanned    TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""


class AssetRegistry:
    """
    Persistent, queryable store for all EIRPP-discovered assets.

    Wraps the existing IERSS SQLite DB and adds an 'assets' table.

    Usage:
        registry = AssetRegistry()
        registry.upsert(asset)
        assets = registry.get_by_criticality(AssetCriticality.CRITICAL)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        self._criticality_scorer = CriticalityScorer()
        self._org_mapper = OrgMapper()
        self._compliance_tagger = ComplianceTagger()
        self._ensure_table()

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def upsert(self, asset: Asset) -> Asset:
        """
        Insert or update an asset. If hostname already exists, merges context
        without overwriting manually set fields.
        """
        # Auto-enrich if criticality unknown
        if asset.criticality == AssetCriticality.UNKNOWN:
            self._criticality_scorer.score_asset(asset)
        self._org_mapper.map_asset(asset)
        self._compliance_tagger.tag_asset(asset)

        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO assets (
                        hostname, asset_type, source, organisation, business_unit,
                        owner_team, owner_contact, criticality, is_customer_facing,
                        is_internet_exposed, is_revenue_generating, serves_pii,
                        compliance_scopes, last_risk_score, last_risk_level,
                        last_scanned, notes, tags, created_at, updated_at
                    ) VALUES (
                        :hostname, :asset_type, :source, :organisation, :business_unit,
                        :owner_team, :owner_contact, :criticality, :is_customer_facing,
                        :is_internet_exposed, :is_revenue_generating, :serves_pii,
                        :compliance_scopes, :last_risk_score, :last_risk_level,
                        :last_scanned, :notes, :tags, :created_at, :updated_at
                    )
                    ON CONFLICT(hostname) DO UPDATE SET
                        asset_type         = excluded.asset_type,
                        source             = COALESCE(source, excluded.source),
                        organisation       = COALESCE(organisation, excluded.organisation),
                        business_unit      = COALESCE(business_unit, excluded.business_unit),
                        owner_team         = COALESCE(owner_team, excluded.owner_team),
                        owner_contact      = COALESCE(owner_contact, excluded.owner_contact),
                        criticality        = CASE WHEN criticality = 'UNKNOWN'
                                                  THEN excluded.criticality
                                                  ELSE criticality END,
                        is_customer_facing  = excluded.is_customer_facing,
                        compliance_scopes  = excluded.compliance_scopes,
                        last_risk_score    = COALESCE(excluded.last_risk_score, last_risk_score),
                        last_risk_level    = COALESCE(excluded.last_risk_level, last_risk_level),
                        last_scanned       = COALESCE(excluded.last_scanned, last_scanned),
                        notes              = COALESCE(excluded.notes, notes),
                        tags               = excluded.tags,
                        updated_at         = excluded.updated_at
                """, {
                    **asset.to_dict(),
                    "compliance_scopes": json.dumps([s.value for s in asset.compliance_scopes]),
                    "tags": json.dumps(asset.tags),
                    "is_customer_facing": int(asset.is_customer_facing),
                    "is_internet_exposed": int(asset.is_internet_exposed),
                    "is_revenue_generating": int(asset.is_revenue_generating),
                    "serves_pii": int(asset.serves_pii),
                    "created_at": now,
                    "updated_at": now,
                })
        except Exception as e:
            logger.error(f"[AssetRegistry] Failed to upsert {asset.hostname}: {e}")
        return asset

    def get(self, hostname: str) -> Optional[Asset]:
        """Fetch an asset by hostname. Returns None if not found."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM assets WHERE hostname = ?", (hostname.lower(),)
                ).fetchone()
                if row:
                    return self._row_to_asset(dict(row))
        except Exception as e:
            logger.error(f"[AssetRegistry] get error: {e}")
        return None

    def get_by_criticality(self, criticality: AssetCriticality) -> List[Asset]:
        """Return all assets at a given criticality level."""
        return self._query("SELECT * FROM assets WHERE criticality = ?", (criticality.value,))

    def get_by_org(self, organisation: str) -> List[Asset]:
        """Return all assets for an organisation."""
        return self._query(
            "SELECT * FROM assets WHERE organisation = ?", (organisation,)
        )

    def get_unscored(self) -> List[Asset]:
        """Return assets that haven't been run through the risk pipeline yet."""
        return self._query("SELECT * FROM assets WHERE last_risk_score IS NULL")

    def update_risk(
        self, hostname: str, score: float, level: str
    ) -> None:
        """Update risk score for an asset after pipeline run."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as conn:
                conn.execute(
                    """UPDATE assets SET last_risk_score=?, last_risk_level=?,
                       last_scanned=?, updated_at=? WHERE hostname=?""",
                    (score, level, now, now, hostname.lower()),
                )
        except Exception as e:
            logger.error(f"[AssetRegistry] update_risk error: {e}")

    def all_assets(self) -> List[Asset]:
        """Return all registered assets."""
        return self._query("SELECT * FROM assets ORDER BY criticality, hostname")

    def count(self) -> int:
        """Total number of registered assets."""
        try:
            with self._connect() as conn:
                return conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        except Exception:
            return 0

    # ──────────────────────────────────────────────────────────────────────────
    # Private
    # ──────────────────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        from records.db_manager import SQLiteConnectionWithStatus
        conn = None
        try:
            conn = sqlite3.connect(str(self._db_path), factory=SQLiteConnectionWithStatus)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            raise

    def _ensure_table(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute(_CREATE_TABLE)
        except Exception as e:
            logger.error(f"[AssetRegistry] Failed to create assets table: {e}")

    def _query(self, sql: str, params: tuple = ()) -> List[Asset]:
        try:
            with self._connect() as conn:
                rows = conn.execute(sql, params).fetchall()
                return [self._row_to_asset(dict(r)) for r in rows]
        except Exception as e:
            logger.error(f"[AssetRegistry] Query error: {e}")
            return []

    @staticmethod
    def _row_to_asset(row: dict) -> Asset:
        scopes_raw = json.loads(row.get("compliance_scopes") or "[]")
        tags_raw = json.loads(row.get("tags") or "[]")
        scopes = []
        for s in scopes_raw:
            try:
                scopes.append(ComplianceScope(s))
            except ValueError:
                pass
        try:
            criticality = AssetCriticality(row.get("criticality", "UNKNOWN"))
        except ValueError:
            criticality = AssetCriticality.UNKNOWN
        return Asset(
            hostname=row["hostname"],
            asset_type=row.get("asset_type", "subdomain"),
            source=row.get("source", ""),
            organisation=row.get("organisation"),
            business_unit=row.get("business_unit"),
            owner_team=row.get("owner_team"),
            owner_contact=row.get("owner_contact"),
            criticality=criticality,
            is_customer_facing=bool(row.get("is_customer_facing", 0)),
            is_internet_exposed=bool(row.get("is_internet_exposed", 1)),
            is_revenue_generating=bool(row.get("is_revenue_generating", 0)),
            serves_pii=bool(row.get("serves_pii", 0)),
            compliance_scopes=scopes,
            last_risk_score=row.get("last_risk_score"),
            last_risk_level=row.get("last_risk_level"),
            last_scanned=row.get("last_scanned"),
            notes=row.get("notes", ""),
            tags=tags_raw,
        )
