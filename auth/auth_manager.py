"""
AERIS Authentication Manager
==============================
Provides session-based authentication for the Streamlit dashboard.

Design:
- Users stored in auth/user_db.json (gitignored)
- Passwords hashed with SHA-256 + salt (stdlib only, no pip dependencies)
- Three roles: admin, analyst, viewer
- Session persisted in st.session_state
- No cookies, no JWT — Streamlit session only

Default admin: username='admin', password='CHANGE_ME_NOW'
(App will warn loudly if default credentials are still in use)
"""
import os
import json
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

_AUTH_DIR = Path(__file__).parent
_USER_DB_PATH = _AUTH_DIR / 'user_db.json'


def _hash_password(password: str, salt: str) -> str:
    """Hash password with SHA-256 + salt."""
    return hashlib.sha256(f"{salt}{password}{salt}".encode()).hexdigest()


def _generate_salt() -> str:
    return secrets.token_hex(16)


def _load_user_db() -> dict:
    if not _USER_DB_PATH.exists():
        return _create_default_db()
    try:
        with open(_USER_DB_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[Auth] Failed to load user DB: {e}")
        return _create_default_db()


def _save_user_db(db: dict) -> None:
    try:
        with open(_USER_DB_PATH, 'w') as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        logger.error(f"[Auth] Failed to save user DB: {e}")


def _create_default_db() -> dict:
    salt = _generate_salt()
    db = {
        "users": {
            "admin": {
                "password_hash": _hash_password('CHANGE_ME_NOW', salt),
                "salt": salt,
                "role": "admin",
                "display_name": "System Administrator",
                "is_default": True,
            }
        },
        "version": 1
    }
    _save_user_db(db)
    logger.warning("[Auth] Created default user DB. Change default admin password immediately!")
    return db


class AuthManager:
    """Manages authentication state for AERIS Streamlit sessions."""

    def __init__(self):
        self._db = _load_user_db()

    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Verify username + password.
        Returns (success: bool, role: Optional[str])
        """
        user = self._db.get('users', {}).get(username)
        if not user:
            return False, None
        expected = _hash_password(password, user['salt'])
        if expected == user['password_hash']:
            return True, user['role']
        return False, None

    def is_default_credentials_in_use(self) -> bool:
        """Returns True if the default admin password is still 'CHANGE_ME_NOW'."""
        user = self._db.get('users', {}).get('admin', {})
        return user.get('is_default', False)

    def get_user_info(self, username: str) -> dict:
        return self._db.get('users', {}).get(username, {})

    def change_password(self, username: str, new_password: str) -> bool:
        if username not in self._db.get('users', {}):
            return False
        salt = _generate_salt()
        self._db['users'][username]['password_hash'] = _hash_password(new_password, salt)
        self._db['users'][username]['salt'] = salt
        self._db['users'][username]['is_default'] = False
        _save_user_db(self._db)
        return True

    def add_user(self, username: str, password: str, role: str, display_name: str = '') -> bool:
        if username in self._db.get('users', {}):
            return False
        salt = _generate_salt()
        self._db.setdefault('users', {})[username] = {
            "password_hash": _hash_password(password, salt),
            "salt": salt,
            "role": role,
            "display_name": display_name or username,
            "is_default": False,
        }
        _save_user_db(self._db)
        return True


_auth_manager_instance: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    global _auth_manager_instance
    if _auth_manager_instance is None:
        _auth_manager_instance = AuthManager()
    return _auth_manager_instance
