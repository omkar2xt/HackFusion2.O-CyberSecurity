"""
SignalSafe Campus - Supabase JWT Token Validator
Validates JWT tokens according to Supabase security requirements:
- Validates signature (JWKS / secret)
- Validates issuer, audience ('authenticated'), and expiration
- Derives user identity and role from trusted server-side sources
- NEVER trusts client-supplied metadata or headers for privileged roles
"""

import time
import logging
from typing import Optional, Dict, Any
from uuid import UUID
import jwt
from jwt import PyJWKClient, PyJWTError
from pydantic import BaseModel

from backend.app.core.config import settings
from backend.app.core.errors import UnauthorizedException
from backend.app.schemas.common import UserRole

logger = logging.getLogger("signalsafe.auth")


class AuthenticatedUser(BaseModel):
    """Authoritative server-side representation of an authenticated user."""
    id: UUID
    email: Optional[str] = None
    role: UserRole = UserRole.STUDENT
    campus_id: Optional[UUID] = None
    auth_source: str = "supabase_jwt"


# Server-side profile cache/store for role resolution
# In production, this queries the protected public.profiles table using the backend service role.
_SERVER_SIDE_USER_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_server_side_user(
    user_id: str,
    role: UserRole = UserRole.STUDENT,
    campus_id: Optional[str] = None,
    email: Optional[str] = None,
) -> None:
    """Helper used by server startup / tests to seed trusted server-side role profiles."""
    _SERVER_SIDE_USER_REGISTRY[str(user_id)] = {
        "role": role,
        "campus_id": UUID(campus_id) if campus_id else None,
        "email": email,
    }


def clear_server_side_user_registry() -> None:
    _SERVER_SIDE_USER_REGISTRY.clear()


class SupabaseTokenValidator:
    """
    Validates Supabase access tokens.
    Supports asymmetric RS256/ES256 via JWKS and symmetric HS256 via SUPABASE_JWT_SECRET.
    Enforces signature, expiration, audience, and issuer validation.
    """

    def __init__(self):
        self._jwks_client: Optional[PyJWKClient] = None

    def _get_jwks_client(self) -> PyJWKClient:
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(
                uri=settings.SUPABASE_JWKS_URL,
                cache_keys=True,
                max_cached_keys=16,
            )
        return self._jwks_client

    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """
        Thoroughly validates signature, issuer, audience, and expiration.
        Raises UnauthorizedException on any verification failure.
        """
        if not token or not isinstance(token, str):
            raise UnauthorizedException("Missing or invalid token format.")

        try:
            # 1. Inspect unverified header for algorithm and key ID
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg")
            if not alg:
                raise UnauthorizedException("Invalid token header: missing alg.")

            # 2. Retrieve signing key based on algorithm
            signing_key: Any = None
            if alg in ["RS256", "ES256"]:
                try:
                    jwks_client = self._get_jwks_client()
                    signing_key = jwks_client.get_signing_key_from_jwt(token).key
                except Exception as jwks_err:
                    logger.error("Failed to retrieve public key from JWKS: %s", jwks_err)
                    # Never fall back to symmetric HMAC secret for asymmetric tokens
                    raise UnauthorizedException("Unable to verify token signature: public key unavailable.")
            elif alg == "HS256":
                if not settings.SUPABASE_JWT_SECRET:
                    raise UnauthorizedException("Server configuration error: JWT secret not set.")
                signing_key = settings.SUPABASE_JWT_SECRET
            else:
                raise UnauthorizedException(f"Unsupported signing algorithm: {alg}")

            # 3. Decode and verify signature, issuer, audience, and expiration
            payload = jwt.decode(
                token,
                key=signing_key,
                algorithms=[alg],
                audience=settings.SUPABASE_JWT_AUDIENCE,
                issuer=settings.SUPABASE_JWT_ISSUER,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "require": ["exp", "sub", "iss", "aud"],
                },
            )

            # Ensure subject is present and valid UUID
            sub = payload.get("sub")
            if not sub:
                raise UnauthorizedException("Token payload missing 'sub' identifier.")

            return payload

        except UnauthorizedException:
            raise
        except jwt.ExpiredSignatureError:
            raise UnauthorizedException("Token has expired.")
        except jwt.InvalidIssuerError:
            raise UnauthorizedException("Invalid token issuer.")
        except jwt.InvalidAudienceError:
            raise UnauthorizedException("Invalid token audience.")
        except jwt.InvalidSignatureError:
            raise UnauthorizedException("Invalid token signature.")
        except PyJWTError as err:
            logger.warning("JWT verification error: %s", err)
            raise UnauthorizedException(f"Token verification failed: {str(err)}")
        except Exception as err:
            logger.error("Unexpected token validation exception: %s", err)
            raise UnauthorizedException("Invalid or malformed authentication token.")

    def derive_user(self, payload: Dict[str, Any]) -> AuthenticatedUser:
        """
        Derives user identity and role from trusted server-side sources.
        CRITICAL SECURITY REQUIREMENT:
        - NEVER trust client-supplied signup metadata (raw_user_meta_data / user_metadata)
          for role or campus_id.
        - Default to STUDENT.
        - Check server-side profile store for privileged roles (CAMPUS_ADMIN, PLATFORM_ADMIN).
        """
        sub = payload["sub"]
        try:
            user_uuid = UUID(sub)
        except (ValueError, TypeError):
            raise UnauthorizedException("Invalid user identifier in token payload.")

        email = payload.get("email")

        # Check trusted server-side profile registry first
        server_record = _SERVER_SIDE_USER_REGISTRY.get(str(user_uuid))
        if server_record:
            return AuthenticatedUser(
                id=user_uuid,
                email=server_record.get("email") or email,
                role=server_record.get("role", UserRole.STUDENT),
                campus_id=server_record.get("campus_id"),
                auth_source="supabase_jwt",
            )

        # Check server-assigned app_metadata (only writable by Supabase service_role, not user)
        app_metadata = payload.get("app_metadata", {})
        trusted_role_str = app_metadata.get("role")
        trusted_campus_str = app_metadata.get("campus_id")

        derived_role = UserRole.STUDENT
        if trusted_role_str in [r.value for r in UserRole]:
            derived_role = UserRole(trusted_role_str)

        campus_uuid: Optional[UUID] = None
        if trusted_campus_str:
            try:
                campus_uuid = UUID(trusted_campus_str)
            except (ValueError, TypeError):
                campus_uuid = None

        # Return authenticated user safely defaulted to STUDENT
        return AuthenticatedUser(
            id=user_uuid,
            email=email,
            role=derived_role,
            campus_id=campus_uuid,
            auth_source="supabase_jwt",
        )


token_validator = SupabaseTokenValidator()
