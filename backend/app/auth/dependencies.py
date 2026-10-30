"""
SignalSafe Campus - Authentication & Authorization Dependencies
"""

from typing import Optional, List
from fastapi import Header, Depends
from backend.app.core.errors import UnauthorizedException, ForbiddenException
from backend.app.schemas.common import UserRole
from backend.app.auth.token_validator import (
    AuthenticatedUser,
    token_validator,
)


def extract_bearer_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Extracts raw JWT bearer token from the Authorization header."""
    if not authorization:
        return None
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedException("Invalid Authorization header format. Expected 'Bearer <token>'.")
    return parts[1]


async def get_optional_current_user(
    token: Optional[str] = Depends(extract_bearer_token),
) -> Optional[AuthenticatedUser]:
    """
    Dependency for endpoints supporting optional authentication (e.g. scans).
    If a token is provided, it MUST be valid; invalid tokens are rejected with 401.
    If no token is provided, returns None (public/anonymous).
    """
    if not token:
        return None
    payload = token_validator.decode_and_verify(token)
    return token_validator.derive_user(payload)


async def get_current_user(
    token: Optional[str] = Depends(extract_bearer_token),
) -> AuthenticatedUser:
    """
    Dependency for protected endpoints requiring authenticated identity (e.g. incidents).
    Rejects anonymous calls with 401 Unauthorized.
    """
    if not token:
        raise UnauthorizedException("Authentication required. Please provide a valid Bearer token.")
    payload = token_validator.decode_and_verify(token)
    return token_validator.derive_user(payload)


def require_role(allowed_roles: List[UserRole]):
    """Factory dependency that restricts access to users with specific roles."""

    async def role_checker(
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if current_user.role not in allowed_roles:
            raise ForbiddenException(
                f"Action forbidden for role '{current_user.role.value}'. Allowed roles: {[r.value for r in allowed_roles]}."
            )
        return current_user

    return role_checker


# Convenient pre-configured dependency for campus admin endpoints
require_campus_admin = require_role([UserRole.CAMPUS_ADMIN, UserRole.PLATFORM_ADMIN])
