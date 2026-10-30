"""
SignalSafe Campus - Authentication & Token Verification Tests
Thoroughly tests JWT validation, signature, issuer, audience, expiration, and role derivation.
"""

import uuid
import pytest
from backend.app.core.errors import UnauthorizedException
from backend.app.auth.token_validator import token_validator, register_server_side_user
from backend.app.schemas.common import UserRole
from backend.tests.conftest import create_test_jwt, TEST_SECRET


def test_valid_token_decode_and_derive():
    """Test standard valid Supabase token verification and user derivation."""
    user_id = str(uuid.uuid4())
    token = create_test_jwt(user_id=user_id, email="alice@campus.edu")

    payload = token_validator.decode_and_verify(token)
    assert payload["sub"] == user_id
    assert payload["email"] == "alice@campus.edu"

    user = token_validator.derive_user(payload)
    assert str(user.id) == user_id
    assert user.role == UserRole.STUDENT  # Defaults to STUDENT


def test_expired_token_rejected():
    """Test that expired tokens are rejected."""
    user_id = str(uuid.uuid4())
    token = create_test_jwt(user_id=user_id, exp_offset_seconds=-3600)  # Expired 1 hour ago

    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(token)
    assert "expired" in str(exc_info.value.message).lower()


def test_invalid_issuer_rejected():
    """Test that tokens with untrusted issuer are rejected."""
    user_id = str(uuid.uuid4())
    token = create_test_jwt(user_id=user_id, issuer="https://evil-attacker.com/auth/v1")

    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(token)
    assert "issuer" in str(exc_info.value.message).lower()


def test_invalid_audience_rejected():
    """Test that tokens with invalid audience are rejected."""
    user_id = str(uuid.uuid4())
    token = create_test_jwt(user_id=user_id, audience="wrong_aud")

    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(token)
    assert "audience" in str(exc_info.value.message).lower()


def test_tampered_signature_rejected():
    """Test that tokens signed with the wrong key are rejected."""
    user_id = str(uuid.uuid4())
    token = create_test_jwt(
        user_id=user_id,
        secret="wrong-secret-key-32-chars-long-minimum-length!",
    )

    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(token)
    assert "signature" in str(exc_info.value.message).lower() or "failed" in str(exc_info.value.message).lower()


def test_role_escalation_via_user_metadata_prevented():
    """
    CRITICAL SECURITY TEST:
    Client-supplied signup metadata ('user_metadata') attempting to assign CAMPUS_ADMIN
    must be strictly IGNORED. The user must default to STUDENT.
    """
    user_id = str(uuid.uuid4())
    token = create_test_jwt(
        user_id=user_id,
        email="attacker@campus.edu",
        extra_user_metadata={"role": "CAMPUS_ADMIN", "campus_id": str(uuid.uuid4())},
    )

    payload = token_validator.decode_and_verify(token)
    user = token_validator.derive_user(payload)

    # Must remain STUDENT regardless of what user_metadata says!
    assert user.role == UserRole.STUDENT


def test_trusted_server_side_role_resolution():
    """Test that server-side profile store properly resolves privileged roles."""
    user_id = str(uuid.uuid4())
    campus_id = str(uuid.uuid4())
    register_server_side_user(
        user_id=user_id,
        role=UserRole.CAMPUS_ADMIN,
        campus_id=campus_id,
        email="admin@campus.edu",
    )

    token = create_test_jwt(user_id=user_id, email="admin@campus.edu")
    payload = token_validator.decode_and_verify(token)
    user = token_validator.derive_user(payload)

    assert user.role == UserRole.CAMPUS_ADMIN
    assert str(user.campus_id) == campus_id
