"""
AERIS Role-Based Access Control
================================
Defines the three roles and their permission sets.
Roles: admin > analyst > viewer
"""
from enum import Enum
from typing import Set


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Every permission key must be checked before granting access to a feature
ROLE_PERMISSIONS: dict = {
    Role.ADMIN: {
        "can_run_assessment",
        "can_view_history",
        "can_run_batch",
        "can_view_visualization",
        "can_access_stress_test",
        "can_access_red_team",
        "can_view_debug_output",
        "can_view_raw_json",
        "can_manage_users",
        "can_view_readiness_tracker",
        "can_run_anti_theater_scan",
    },
    Role.ANALYST: {
        "can_run_assessment",
        "can_view_history",
        "can_run_batch",
        "can_view_visualization",
        "can_access_stress_test",
    },
    Role.VIEWER: {
        "can_view_history",
        "can_view_visualization",
    },
}

# Pages visible per role (navigation filter)
ROLE_PAGES: dict = {
    Role.ADMIN: [
        "Security Assessment",
        "Intelligence Visualization Workspace",
        "Upgraded Platform",
        "Batch Processing",
        "Scan History",
        "Adversarial Stress Test",
        "Red-Team Testing",
        "Admin: Readiness Tracker",
        "Admin: Anti-Theater Scanner",
    ],
    Role.ANALYST: [
        "Security Assessment",
        "Intelligence Visualization Workspace",
        "Upgraded Platform",
        "Batch Processing",
        "Scan History",
        "Adversarial Stress Test",
    ],
    Role.VIEWER: [
        "Scan History",
        "Intelligence Visualization Workspace",
    ],
}


def has_permission(role: Role, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())


def get_allowed_pages(role: Role) -> list:
    """Return the list of pages accessible to this role."""
    return ROLE_PAGES.get(role, [])
