"""
AERIS Database Schema Migration & Seeding Utility
=================================================
Initializes all multi-tenant enterprise database tables and pre-seeds corporate workspaces 
and users across different RBAC tiers.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

# Add root folder to python path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from portal.core.db import db_manager
from portal.core.tenancy import TenantManager, set_tenant_context, clear_tenant_context
from portal.core.auth import IAMEngine

def run_migration():
    print("=" * 60)
    print("  AERIS DATABASE MIGRATION SYSTEM")
    print("=" * 60)
    print(f"Target DB: {db_manager.db_path.absolute()}")
    
    # 1. Initialization executes automatically during class instantiation,
    # but we force reference to ensure constructor runs
    print("-> Checking and executing schema updates...")
    db_manager._init_schemas()
    print("OK: Schemas checked and verified.")

    # 2. Seeding default tenant
    tenant_id = "aeris_cyber"
    tenant_name = "AERIS Cyber Labs"
    print(f"-> Seeding tenant '{tenant_id}'...")
    try:
        TenantManager.create_tenant(
            tenant_id=tenant_id,
            name=tenant_name,
            industry="technology",
            compliance_scope=["SOC 2", "GDPR", "ISO 27001"]
        )
        print(f"OK: Tenant '{tenant_id}' registered successfully.")
    except Exception as e:
        if "UNIQUE constraint" in str(e) or "already exists" in str(e).lower():
            print(f"INFO: Tenant '{tenant_id}' already exists. Skipping.")
        else:
            print(f"ERROR: Failed to seed tenant: {e}")
            return

    # 3. Seeding users under different RBAC roles
    users_to_seed = [
        ("ciso_cindy", "cindy_pass_2026", "CISO"),
        ("lead_lewis", "lewis_pass_2026", "SOC_MANAGER"),
        ("analyst_andy", "andy_pass_2026", "ANALYST"),
        ("auditor_alice", "alice_pass_2026", "AUDITOR")
    ]

    print("-> Seeding user identities...")
    for username, password, role in users_to_seed:
        try:
            IAMEngine.register_user(
                tenant_id=tenant_id,
                username=username,
                password_raw=password,
                role=role
            )
            print(f"OK: Registered user: {username:<15} | Role: {role:<12}")
        except Exception as e:
            if "UNIQUE constraint" in str(e) or "already exists" in str(e).lower():
                print(f"INFO: User '{username:<15}' already exists. Skipping.")
            else:
                print(f"ERROR: Failed to seed user {username}: {e}")

    print("\n" + "=" * 60)
    print("  MIGRATION & PRE-SEEDING COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    run_migration()
