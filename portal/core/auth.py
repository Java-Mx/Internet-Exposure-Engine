"""
AERIS Identity & Access Management (IAM)
=========================================
Implements secure PBKDF2-SHA256 password hashing, enterprise-grade Role-Based Access 
Control (RBAC), and tenant-isolated session JSON Web Tokens (JWT).
"""
from __future__ import annotations

import os
import hmac
import json
import base64
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from .db import db_manager
from .tenancy import set_tenant_context

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("exposure_discovery.portal.auth")

# Secure signing key enforcement - fail-closed
JWT_SECRET = os.getenv("AERIS_SIGNING_KEY")
if not JWT_SECRET:
    raise ValueError(
        "CRITICAL SECURITY CONFIGURATION ERROR: 'AERIS_SIGNING_KEY' environment variable must be set. "
        "Fallback default credentials have been disabled."
    )
JWT_ALGORITHM = "HS256"

# Password Hashing Constants
PBKDF2_ITERATIONS = 100000

class AuthenticationError(Exception):
    """Base exception for access control and identification issues."""
    pass


class AccessDeniedError(Exception):
    """Raised when an authenticated user attempts an operation outside their RBAC permission level."""
    pass


class IAMEngine:
    """
    Cryptographic manager for credentials, RBAC validation, and session issuing.
    """
    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes a password using PBKDF2-SHA256 with a secure random salt."""
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        # Format: iterations$salt_hex$hash_hex
        return f"{PBKDF2_ITERATIONS}${salt.hex()}${pwd_hash.hex()}"

    @staticmethod
    def verify_password(password: str, hashed_str: str) -> bool:
        """Verifies a password against the stored PBKDF2 hash representation."""
        try:
            parts = hashed_str.split("$")
            if len(parts) != 3:
                return False
            iterations = int(parts[0])
            salt = bytes.fromhex(parts[1])
            original_hash = bytes.fromhex(parts[2])

            compare_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, iterations
            )
            return hmac.compare_digest(original_hash, compare_hash)
        except Exception as e:
            logger.error(f"[IAM] Password verification failure: {e}")
            return False

    @staticmethod
    def generate_token(username: str, tenant_id: str, role: str, expires_in_minutes: int = 60) -> str:
        """
        Creates a custom HMAC-SHA256 signed session JWT (Self-contained representation).
        Uses Standard JSON Web Token format: header.payload.signature
        """
        header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
        exp = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
        payload = {
            "sub": username,
            "tenant_id": tenant_id.lower(),
            "role": role,
            "exp": int(exp.timestamp())
        }

        # Encode parts
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{signing_input}.{signature_b64}"

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """
        Verifies token structure, signature validity, and checks expiration.
        Automatically sets active tenant context upon success.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise AuthenticationError("Malformed session token structure.")

            header_b64, payload_b64, signature_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}"

            # Verify signature
            expected_sig = hmac.new(
                JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
            ).digest()
            expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

            if not hmac.compare_digest(expected_sig_b64, signature_b64):
                raise AuthenticationError("Cryptographic signature verification failed.")

            # Padding support for decode
            payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode())

            # Check expiration
            exp = payload.get("exp")
            if not exp or datetime.now(timezone.utc).timestamp() > exp:
                raise AuthenticationError("Session token has expired.")

            # Bind tenant context automatically
            set_tenant_context(payload["tenant_id"])
            return payload

        except Exception as e:
            if not isinstance(e, AuthenticationError):
                logger.error(f"[IAM] Verification error: {e}")
                raise AuthenticationError("Invalid authentication credentials.")
            raise

    @staticmethod
    def register_user(tenant_id: str, username: str, password_raw: str, role: str) -> Dict[str, Any]:
        """Registers a user credentials mapped to a tenant workspace."""
        h = IAMEngine.hash_password(password_raw)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_manager.get_connection() as conn:
                conn.execute("""
                    INSERT INTO users (tenant_id, username, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (tenant_id.lower(), username.lower(), h, role, now))
                conn.commit()
            logger.info(f"[IAM] Registered user {username} with role {role} for Tenant {tenant_id}.")
            return {"username": username, "tenant_id": tenant_id, "role": role}
        except sqlite3.IntegrityError:
            raise AuthenticationError("Username already exists in system database.")
        except Exception as e:
            logger.error(f"[IAM] User registration failed: {e}")
            raise

    @staticmethod
    def authenticate_user(username: str, password_raw: str) -> Dict[str, Any]:
        """Validates credentials and issues a signed session JWT."""
        try:
            with db_manager.get_connection() as conn:
                row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
                if not row:
                    raise AuthenticationError("Invalid username or password.")
                
                user = dict(row)
                if not IAMEngine.verify_password(password_raw, user["password_hash"]):
                    raise AuthenticationError("Invalid username or password.")
                
                # Issue JWT
                token = IAMEngine.generate_token(user["username"], user["tenant_id"], user["role"])
                return {
                    "username": user["username"],
                    "tenant_id": user["tenant_id"],
                    "role": user["role"],
                    "access_token": token
                }
        except Exception as e:
            if not isinstance(e, AuthenticationError):
                logger.error(f"[IAM] Auth flow crash: {e}")
                raise AuthenticationError("System credential validation error.")
            raise

    @staticmethod
    def require_role(user_payload: Dict[str, Any], allowed_roles: List[str]) -> None:
        """Enforces RBAC matrix. Raises AccessDeniedError if check fails."""
        role = user_payload.get("role")
        if role not in allowed_roles:
            raise AccessDeniedError(
                f"Unauthorized. Role '{role}' does not have permissions for this action. Allowed: {allowed_roles}"
            )
