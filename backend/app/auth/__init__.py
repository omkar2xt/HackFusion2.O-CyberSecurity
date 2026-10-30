"""
SignalSafe Campus - Auth Module
"""

from backend.app.auth.token_validator import (
    AuthenticatedUser,
    SupabaseTokenValidator,
    token_validator,
    register_server_side_user,
    clear_server_side_user_registry,
)
from backend.app.auth.dependencies import (
    extract_bearer_token,
    get_optional_current_user,
    get_current_user,
    require_role,
    require_campus_admin,
)

__all__ = [
    "AuthenticatedUser",
    "SupabaseTokenValidator",
    "token_validator",
    "register_server_side_user",
    "clear_server_side_user_registry",
    "extract_bearer_token",
    "get_optional_current_user",
    "get_current_user",
    "require_role",
    "require_campus_admin",
]
